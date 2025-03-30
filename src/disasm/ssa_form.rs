use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
};

use super::{
    control_flow_graph::{Block, BlockId, Condition, ControlFlowGraph, FunctionCall, NextKind},
    data_flow_analysis::{Definition, GraphDataFlow},
    low_ir::{Arg, ArgBase, GenericInstruction, HasDebugMarker, OpArg},
    program_analysis::ProgramAnalysis,
};

use itertools::Itertools;
#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
pub struct SSAArg {
    pub block_id: BlockId,
    pub arg: Arg,
    pub version: usize,
    pub deref_version: usize,
}

impl SSAArg {
    pub fn new(block_id: BlockId, arg: Arg, version: usize, deref_version: usize) -> Self {
        SSAArg {
            block_id,
            arg,
            version,
            deref_version,
        }
    }

    fn from_op_arg(block_id: BlockId, op_arg: OpArg) -> Self {
        SSAArg {
            block_id,
            arg: op_arg.kind,
            version: 0,
            deref_version: 0,
        }
    }
}

impl ArgBase for SSAArg {
    fn value(&self) -> Option<i128> {
        self.arg.value()
    }

    fn relative_mem(&self) -> Option<i128> {
        self.arg.relative_mem()
    }

    fn as_arg(&self) -> &Arg {
        &self.arg
    }
}

impl Display for SSAArg {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.arg {
            Arg::Value(x) => write!(f, "{}", x), // No version for immediate values
            Arg::Deref(addr) => write!(f, "[[{}]_{}]", addr, self.deref_version),
            _ => write!(f, "{}_{}", self.arg, self.version),
        }
    }
}

pub struct SSAGraph {
    pub cfg: ControlFlowGraph<SSAArg>,
    pub debug_markers: HashMap<SSAArg, char>,
}
// output = phi(inputs)
struct PhiNode {
    output: SSAArg,
    inputs: Vec<SSAArg>,
}

pub fn convert_to_ssa<
    ArgType: ArgBase + std::fmt::Debug + std::hash::Hash + Eq + Copy + From<OpArg> + HasDebugMarker,
>(
    program_analysis: &ProgramAnalysis,
    control_flow: &ControlFlowGraph<ArgType>,
    data_flow: &GraphDataFlow<ArgType>,
) -> SSAGraph {
    let converter = SSAConverter::new(program_analysis, control_flow, data_flow);
    converter.convert()
}

struct SSAConverter<'a, ArgType: ArgBase> {
    control_flow: &'a ControlFlowGraph<ArgType>,
    program_analysis: &'a ProgramAnalysis,
    data_flow: &'a GraphDataFlow<ArgType>,
    // Highest version number created for each variable. Used to allocate new versions.
    current_version: HashMap<Arg, usize>,
    // Latest version of each variable in each block, used for passing into subsequent blocks and
    // phi functions
    var_versions: HashMap<BlockId, HashMap<Arg, SSAArg>>,
    // For each SSA variable, the unique location that it is assigned.
    var_locations: HashMap<SSAArg, usize>,
    // for each block, map Arg to index of phi function in block.ops
    phi_nodes: HashMap<BlockId, HashMap<Arg, PhiNode>>,
    visited: HashSet<BlockId>,
    debug_markers: HashMap<SSAArg, char>,
    out: ControlFlowGraph<SSAArg>,
}

impl<'a, ArgType> SSAConverter<'a, ArgType>
where
    ArgType: ArgBase + Eq + std::hash::Hash + Copy + From<OpArg> + std::fmt::Debug + HasDebugMarker,
{
    pub fn new(
        program_analysis: &'a ProgramAnalysis,
        control_flow: &'a ControlFlowGraph<ArgType>,
        flow: &'a GraphDataFlow<ArgType>,
    ) -> Self {
        let mut res = SSAConverter {
            program_analysis,
            control_flow,
            data_flow: flow,
            current_version: HashMap::new(),
            var_versions: HashMap::new(),
            var_locations: HashMap::new(),
            phi_nodes: HashMap::new(),
            visited: HashSet::new(),
            debug_markers: HashMap::new(),
            out: ControlFlowGraph {
                start: control_flow.start,
                stack_size: control_flow.stack_size,
                blocks: HashMap::new(),
            },
        };
        for block in control_flow.blocks.values() {
            res.out.blocks.insert(
                block.id(),
                Block {
                    ops: Vec::new(),
                    span: block.span,
                    next: NextKind::Unknown,
                    predecessors: Vec::new(),
                },
            );
        }
        res
    }

    pub fn convert(mut self) -> SSAGraph {
        /*
        let start_addr = self.control_flow.start.addr();
        let mut hm = HashMap::new();
        for r in 0..(self.control_flow.stack_size) {
            let arg = OpArg {
                kind: Arg::RelativeMem(-(r as i128)),
                span: Span::new(start_addr, start_addr + 2),
                debug_marker: None,
            }
            .into();
            hm.insert(
                arg,
                SSAArg {
                    arg,
                    version: 0,
                    deref_version: 0,
                    debug_marker: None,
                },
            );
        }
        self.var_versions.insert(self.control_flow.start, hm);
        */
        for block in self.control_flow.blocks.keys() {
            self.insert_phi_functions(*block);
        }
        self.process_block(self.control_flow.start);
        self.prune_phi_functions();
        self.renumber_all_vars();
        self.populate_phi_functions();
        self.transform_next_fields();
        SSAGraph {
            cfg: self.out,
            debug_markers: self.debug_markers,
        }
    }

    fn prune_phi_functions(&mut self) {
        loop {
            let mut changed = false;
            let mut replacements = HashMap::new();
            let mut to_remove = HashSet::new();
            for (&block_id, phis) in &self.phi_nodes {
                for phi in phis.values() {
                    if let Ok(input) = phi.inputs.iter().unique().exactly_one() {
                        replacements.insert(phi.output, (block_id, *input));
                        changed = true;
                    }
                    if phi.inputs.is_empty() {
                        to_remove.insert((block_id, phi.output));
                        changed = true;
                    }
                }
            }
            let mut final_replacements = HashMap::new();
            for (&source, (block_id, mut target)) in &replacements {
                while let Some((_, replacement)) = replacements.get(&target) {
                    target = *replacement
                }
                if to_remove.contains(&(*block_id, target)) {
                    to_remove.insert((*block_id, source));
                } else {
                    final_replacements.insert(source, (block_id, target));
                }
            }

            for (block_id, arg) in &to_remove {
                self.phi_nodes.get_mut(block_id).unwrap().remove(&arg.arg);
                self.var_versions
                    .get_mut(block_id)
                    .unwrap()
                    .remove(&arg.arg);
            }
            for (source, (block_id, _)) in &final_replacements {
                self.phi_nodes
                    .get_mut(block_id)
                    .unwrap()
                    .remove(&source.arg);
                self.var_locations.remove(source);
                for phis in self.phi_nodes.values_mut() {
                    for phi in phis.values_mut() {
                        while let Some(index) = phi.inputs.iter().position(|i| i == source) {
                            phi.inputs[index] = final_replacements.get(source).unwrap().1;
                        }
                    }
                }
            }
            for block in self.out.blocks.values_mut() {
                for (_, op) in block.ops.iter_mut() {
                    *op = op.map(|a| final_replacements.get(a).map(|t| t.1).unwrap_or(*a));
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn populate_phi_functions(&mut self) {
        for (block_id, phis) in &self.phi_nodes {
            let block = self.out.blocks.get_mut(block_id).unwrap();
            block
                .ops
                .splice(
                    0..0,
                    phis.iter()
                        .sorted_by_key(|(_, phi)| phi.output.arg)
                        .map(|(_, phi)| {
                            (
                                block.span.start,
                                GenericInstruction::Phi(phi.output, phi.inputs.clone()),
                            )
                        }),
                )
                .collect_vec();
        }
    }

    fn create_new_version_for_arg(
        &mut self,
        arg: Arg,
        block_id: BlockId,
        offset: usize,
        debug_marker: Option<char>,
    ) -> SSAArg {
        println!(
            "Creating new version for arg: {:?} offset: {} debug_marker: {:?}",
            arg, offset, debug_marker
        );
        if let Arg::Deref(_) = arg {
            return self.current_version_of_arg_in_block(arg, block_id, None);
        }
        let new_version = *self.current_version.entry(arg).or_default() + 1;
        self.current_version.insert(arg, new_version);
        let new_arg = SSAArg {
            block_id,
            arg,
            version: new_version,
            deref_version: 0,
        };
        self.var_versions
            .entry(block_id)
            .or_default()
            .insert(arg, new_arg);
        self.var_locations.insert(new_arg, offset);
        if let Some(marker) = debug_marker {
            self.debug_markers.insert(new_arg, marker);
        }
        new_arg
    }

    fn current_version_of_arg_in_block(
        &mut self,
        arg: Arg,
        function_block_id: BlockId,
        debug_marker: Option<char>,
    ) -> SSAArg {
        if let Arg::Deref(addr) = arg.as_arg() {
            return SSAArg {
                block_id: function_block_id,
                arg: *arg.as_arg(),
                version: 0,
                deref_version: self
                    .current_version_of_arg_in_block(
                        Arg::Mem(*addr as i128),
                        function_block_id,
                        None,
                    )
                    .version,
            };
        }

        let res = *self
            .var_versions
            .get(&function_block_id)
            .and_then(|hs| hs.get(arg.as_arg()))
            .unwrap_or(&SSAArg {
                block_id: function_block_id,
                arg: *arg.as_arg(),
                version: 0,
                deref_version: 0,
            });
        if let Some(debug_marker) = debug_marker {
            self.debug_markers.insert(res, debug_marker);
        }
        res
    }

    fn block_needs_phi_function(&self, block_id: BlockId, arg: &ArgType) -> bool {
        if matches!(arg.as_arg(), Arg::Deref(_)) {
            return false;
        }
        let control_def = &self.control_flow.blocks[&block_id];
        let predecessor_count = control_def.predecessors.len();

        if predecessor_count <= 1 {
            return false;
        }

        let mut has_empty = false;
        let mut def_set: HashSet<Definition<ArgType>> = HashSet::new();
        for pred in &control_def.predecessors {
            let arg_defs = self.data_flow.block_defs[&pred.block_id()]
                .defs_out
                .iter()
                .filter(|d| d.arg.as_arg() == arg.as_arg());

            def_set.extend(arg_defs.clone());
            let count = arg_defs.count();
            if count == 0 {
                has_empty = true;
            }
        }

        def_set.len() > 1 || (!def_set.is_empty() && has_empty)
    }

    fn transform_next_to_ssa(&mut self, next_kind: &NextKind<ArgType>) -> NextKind<SSAArg> {
        let to_ssa = |s: &mut Self, arg: &ArgType| {
            s.current_version_of_arg_in_block(
                *arg.as_arg(),
                self.control_flow.start,
                arg.debug_marker(),
            )
        };

        match next_kind {
            NextKind::Goto(arg) => NextKind::Goto(to_ssa(self, arg)),
            NextKind::FunctionCall(FunctionCall {
                calling_block,
                function_addr,
                return_block,
                ..
            }) => {
                let args = if let Some(value) = function_addr.value() {
                    let funcinfo =
                        &self.program_analysis.function_infos[&((value as usize).into())];
                    Some(
                        funcinfo
                            .args
                            .iter()
                            .map(|arg| {
                                self.current_version_of_arg_in_block(
                                    *arg,
                                    self.control_flow.start,
                                    None,
                                )
                            })
                            .collect(),
                    )
                } else {
                    None
                };
                NextKind::FunctionCall(FunctionCall {
                    calling_block: *calling_block,
                    function_addr: to_ssa(self, function_addr),
                    return_block: *return_block,
                    arguments: args,
                    return_types: None,
                })
            }
            NextKind::Condition(Condition {
                from_block,
                jump_block,
                follows_block,
                arg,
                matches,
            }) => NextKind::Condition(Condition {
                from_block: *from_block,
                jump_block: *jump_block,
                follows_block: *follows_block,
                arg: to_ssa(self, arg),
                matches: *matches,
            }),
            NextKind::Halt => NextKind::Halt,
            NextKind::Unknown => NextKind::Unknown,
            NextKind::Return => NextKind::Return,
            NextKind::Follows(block_id) => NextKind::Follows(*block_id),
        }
    }

    fn insert_phi_functions(&mut self, block_id: BlockId) {
        let control_def = &self.control_flow.blocks[&block_id];
        if control_def.predecessors.len() <= 1 {
            return;
        }
        let data_def = &self.data_flow.block_defs[&block_id];
        for arg in &data_def
            .defs_in
            .iter()
            .map(|d| d.arg)
            .unique()
            .sorted_by_key(|arg| *arg.as_arg())
            .collect_vec()
        {
            assert!(!arg.is_value(), "Immediate values should not be in use set");
            if self.block_needs_phi_function(block_id, arg) {
                let output = self.create_new_version_for_arg(
                    *arg.as_arg(),
                    self.control_flow.start,
                    control_def.span.start,
                    None,
                );
                self.phi_nodes.entry(block_id).or_default().insert(
                    *arg.as_arg(),
                    PhiNode {
                        output,
                        inputs: Vec::new(),
                    },
                );
            }
        }
    }

    fn insert_ops_with_renames(&mut self, block_id: BlockId) {
        for (addr, op) in self.control_flow.blocks[&block_id].ops.iter() {
            let new_op = op.map_rw(
                self,
                &mut |s: &mut Self, read_arg: &ArgType| {
                    s.current_version_of_arg_in_block(
                        *read_arg.as_arg(),
                        block_id,
                        read_arg.debug_marker(),
                    )
                },
                &mut |s: &mut Self, write_arg: &ArgType| {
                    s.create_new_version_for_arg(
                        *write_arg.as_arg(),
                        self.control_flow.start,
                        *addr,
                        write_arg.debug_marker(),
                    )
                },
            );
            let block = self.out.blocks.get_mut(&block_id).unwrap();
            block.ops.push((*addr, new_op));
        }
    }

    fn process_block(&mut self, block_id: BlockId) {
        self.visited.insert(block_id);
        self.insert_ops_with_renames(block_id);
        let cdef = &self.control_flow.blocks[&block_id];
        for next in cdef.next_blocks() {
            let next_visited = self.visited.contains(&next);
            let mut new_vars = HashMap::new();
            if let Some(block_vars) = self.var_versions.get(&block_id) {
                for (var, versioned) in block_vars {
                    let has_phi = if let Some(ref mut block_phis) = self.phi_nodes.get_mut(&next) {
                        if block_phis.contains_key(var) {
                            block_phis.get_mut(var).unwrap().inputs.push(*versioned);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !has_phi && !next_visited {
                        new_vars.insert(*var, *versioned);
                    }
                }
            }
            if !next_visited {
                self.var_versions.entry(next).or_default().extend(new_vars);
                self.process_block(next);
            }
        }
    }

    fn renumber_all_vars(&mut self) {
        let mut rename_list = HashMap::new();
        for (_, vars) in self
            .var_locations
            .iter()
            .sorted_by_key(|(&a, &v)| (a.arg, v))
            .chunk_by(|(a, _)| a.arg)
            .into_iter()
        {
            for (i, (ssa, _)) in vars.enumerate() {
                let mut new_ssa = *ssa;
                new_ssa.version = i;
                rename_list.insert(ssa, new_ssa);
            }
        }

        // All Derefs have version zero and a deref_version which refers to the pointer version.
        let rename_var = |a: &SSAArg| {
            let mut r = rename_list.get(&a).copied().unwrap_or(*a);
            if let SSAArg {
                arg: Arg::Deref(addr),
                deref_version,
                ..
            } = r
            {
                r.deref_version = rename_list
                    .get(&SSAArg {
                        block_id: a.block_id,
                        arg: Arg::Mem(addr as i128),
                        version: deref_version,
                        deref_version: 0,
                    })
                    .unwrap()
                    .version;
            }
            r
        };

        for (_, block) in self.out.blocks.iter_mut() {
            for (_, op) in block.ops.iter_mut() {
                *op = op.map(rename_var);
            }
        }
        for node in self.phi_nodes.values_mut() {
            for (_, phi) in node.iter_mut() {
                phi.output = rename_list.get(&phi.output).copied().unwrap_or(phi.output);
                phi.inputs = phi.inputs.iter().map(rename_var).collect();
            }
        }
        for hm in self.var_versions.values_mut() {
            for arg in hm.values_mut() {
                *arg = rename_var(arg);
            }
        }
    }

    fn transform_next_fields(&mut self) {
        for (id, block) in &self.control_flow.blocks {
            self.out.blocks.get_mut(id).unwrap().next = self.transform_next_to_ssa(&block.next);
        }
    }
}
