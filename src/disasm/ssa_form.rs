use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
};

use super::{
    control_flow_graph::{
        Block, BlockId, Condition, ControlFlowGraph, FunctionCall, FunctionId, NextKind,
    },
    data_flow_analysis::{Definition, GraphDataFlow},
    low_ir::{Arg, ArgBase, GenericInstruction, HasDebugMarker, OpArg},
    program_analysis::ProgramAnalysis,
};

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub enum SSAArgKind {
    Value(i128),
    RelativeMem(i128),
    Mem(i128),
    Deref { addr: usize, deref_version: usize },
}

impl SSAArgKind {
    fn from_arg(arg: Arg) -> Self {
        match arg {
            Arg::Value(x) => SSAArgKind::Value(x),
            Arg::RelativeMem(x) => SSAArgKind::RelativeMem(x),
            Arg::Mem(x) => SSAArgKind::Mem(x),
            Arg::Deref(addr) => SSAArgKind::Deref {
                addr,
                deref_version: 0,
            },
        }
    }
}

use itertools::Itertools;

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
pub struct SSAArg {
    pub scope: FunctionId,
    pub arg: SSAArgKind,
    pub version: usize,
}

impl SSAArg {
    pub fn new(scope: FunctionId, arg: SSAArgKind, version: usize) -> Self {
        SSAArg {
            scope,
            arg,
            version,
        }
    }
}

impl ArgBase for SSAArg {
    fn value(&self) -> Option<i128> {
        match self.arg {
            SSAArgKind::Value(x) => Some(x),
            _ => None,
        }
    }

    fn relative_mem(&self) -> Option<i128> {
        match self.arg {
            SSAArgKind::RelativeMem(x) => Some(x),
            _ => None,
        }
    }

    fn as_arg(&self) -> Arg {
        match self.arg {
            SSAArgKind::Value(x) => Arg::Value(x),
            SSAArgKind::RelativeMem(x) => Arg::RelativeMem(x),
            SSAArgKind::Deref { addr, .. } => Arg::Deref(addr),
            SSAArgKind::Mem(addr) => Arg::Mem(addr),
        }
    }
}

impl Display for SSAArg {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.arg {
            SSAArgKind::Value(x) => write!(f, "{}", x), // No version for immediate values
            SSAArgKind::Deref {
                addr,
                deref_version,
            } => write!(f, "[[{}]_{}]", addr, deref_version),
            _ => write!(f, "{}_{}", self.as_arg(), self.version),
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
        self.var_versions
            .insert(self.control_flow.start.as_block_id(), HashMap::new());
        self.process_block(self.control_flow.start.as_block_id());
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
                self.phi_nodes
                    .get_mut(block_id)
                    .unwrap()
                    .remove(&arg.as_arg());
                self.var_versions
                    .get_mut(block_id)
                    .unwrap()
                    .remove(&arg.as_arg());
            }
            for (source, (block_id, _)) in &final_replacements {
                self.phi_nodes
                    .get_mut(block_id)
                    .unwrap()
                    .remove(&source.as_arg());
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
        block: BlockId,
        offset: usize,
        debug_marker: Option<char>,
    ) -> SSAArg {
        let new_arg = if let Arg::Deref(addr) = arg {
            let mem_arg = Arg::Mem(addr as i128);
            let deref_version = self
                .create_new_version_for_arg(mem_arg, block, offset, None)
                .version;
            SSAArg::new(
                self.control_flow.start,
                SSAArgKind::Deref {
                    addr,
                    deref_version,
                },
                0,
            )
        } else {
            let new_version = *self.current_version.entry(arg).or_default() + 1;
            self.current_version.insert(arg, new_version);
            let new_arg = SSAArg::new(
                self.control_flow.start,
                SSAArgKind::from_arg(arg),
                new_version,
            );
            self.var_versions
                .entry(block)
                .or_default()
                .insert(arg, new_arg);
            self.var_locations.insert(new_arg, offset);
            new_arg
        };
        if let Some(marker) = debug_marker {
            self.debug_markers.insert(new_arg, marker);
        }
        new_arg
    }

    fn get_or_create_new_version_for_arg(
        &mut self,
        arg: Arg,
        block_id: BlockId,
        offset: usize,
        debug_marker: Option<char>,
    ) -> SSAArg {
        let new_arg = self
            .get_current_version_of_arg_in_block(arg, block_id)
            .unwrap_or_else(|| {
                self.create_new_version_for_arg(arg, block_id, offset, debug_marker)
            });

        if let Some(marker) = debug_marker {
            self.debug_markers.insert(new_arg, marker);
        }
        new_arg
    }

    fn get_current_version_of_arg_in_block(&self, arg: Arg, block_id: BlockId) -> Option<SSAArg> {
        if let Arg::Deref(addr) = arg.as_arg() {
            let deref_version = self
                .get_current_version_of_arg_in_block(Arg::Mem(addr as i128), block_id)?
                .version;
            Some(SSAArg {
                scope: self.control_flow.start,
                arg: SSAArgKind::Deref {
                    addr,
                    deref_version,
                },
                version: 0,
            })
        } else {
            let Some(hs) = self.var_versions.get(&block_id) else {
                panic!("Block not found")
            };
            hs.get(&arg).copied()
        }
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

    fn transform_next_to_ssa(
        &mut self,
        block_id: BlockId,
        next_kind: &NextKind<ArgType>,
    ) -> NextKind<SSAArg> {
        let to_ssa = |s: &mut Self, arg: &ArgType| {
            s.get_or_create_new_version_for_arg(arg.as_arg(), block_id, 0, arg.debug_marker())
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
                                self.get_or_create_new_version_for_arg(*arg, block_id, 0, None)
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
            .sorted_by_key(|arg| arg.as_arg())
            .collect_vec()
        {
            assert!(!arg.is_value(), "Immediate values should not be in use set");
            if self.block_needs_phi_function(block_id, arg) {
                let output =
                    self.create_new_version_for_arg(arg.as_arg(), block_id, block_id.addr(), None);
                self.phi_nodes.entry(block_id).or_default().insert(
                    arg.as_arg(),
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
                    s.get_or_create_new_version_for_arg(
                        read_arg.as_arg(),
                        block_id,
                        *addr,
                        read_arg.debug_marker(),
                    )
                },
                &mut |s: &mut Self, write_arg: &ArgType| {
                    s.create_new_version_for_arg(
                        write_arg.as_arg(),
                        block_id,
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
                arg:
                    SSAArgKind::Deref {
                        addr,
                        ref mut deref_version,
                    },
                ..
            } = r
            {
                let key = SSAArg {
                    scope: a.scope,
                    arg: SSAArgKind::Mem(addr as i128),
                    version: *deref_version,
                };
                *deref_version = rename_list.get(&key).unwrap().version;
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
        self.debug_markers = self
            .debug_markers
            .iter()
            .map(|(k, v)| (rename_var(k), *v))
            .collect();
    }

    fn transform_next_fields(&mut self) {
        for (id, block) in &self.control_flow.blocks {
            self.out.blocks.get_mut(id).unwrap().next =
                self.transform_next_to_ssa(block.id(), &block.next);
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::disasm::parser;

    macro_rules! ssa_main_rel {
        ($offset:expr, $version:expr) => {
            SSAArg::new(0usize.into(), SSAArgKind::RelativeMem($offset), $version)
        };
    }

    macro_rules! ssa_main_mem {
        ($addr:expr, $version:expr) => {
            SSAArg::new(0usize.into(), SSAArgKind::Mem($addr), $version)
        };
    }

    macro_rules! ssa_main_val {
        ($val:expr, $version:expr) => {
            SSAArg::new(0usize.into(), SSAArgKind::Value($val), $version)
        };
    }

    macro_rules! ssa_main_deref {
        ($addr:expr, $deref_version:expr) => {
            SSAArg::new(
                0usize.into(),
                SSAArgKind::Deref {
                    addr: $addr,
                    deref_version: $deref_version,
                },
                0,
            )
        };
    }
    macro_rules! assert_marker_at_func {
        ($self:expr, $marker:expr, $func_id:expr, $expected:expr) => {
            if let Some(graph) = $self.ssa_graphs.get(&$func_id) {
                if let Some((ssa, _)) = graph.debug_markers.iter().find(|&(_, v)| *v == $marker) {
                    assert_eq!(
                        *ssa, $expected,
                        "For marker '{}:\nExpected: {}\nActual: {}",
                        $marker, $expected, ssa
                    );
                } else {
                    panic!("Marker '{}' not found in function {}", $marker, $func_id);
                }
            } else {
                panic!("Marker '{}' found in function {}", $marker, $func_id);
            }
        };
    }

    macro_rules! assert_marker_at_main {
        ($self:expr, $marker:expr, $arg:expr) => {
            assert_marker_at_func!($self, $marker, FunctionId::from(0), $arg)
        };
    }
    use super::*;

    #[test]
    fn test_ssa_arg_creation() {
        let func_id = FunctionId::from(0);
        let ssa_arg = ssa_main_rel!(0, 1);

        assert_eq!(ssa_arg.scope, func_id);
        assert_eq!(ssa_arg.version, 1);
    }

    // #[test]
    // fn test_ssa_arg_from_op_arg() {
    //     let func_id = FunctionId::from(0);
    //     let op_arg = OpArg {
    //         kind: Arg::RelativeMem(1),
    //         span: Span::new(0, 2),
    //         debug_marker: None,
    //     };

    //     let ssa_arg = SSAArg::from_op_arg(func_id, op_arg);

    //     assert_eq!(ssa_arg.scope, func_id);
    //     assert_eq!(ssa_arg.arg, op_arg.kind);
    //     assert_eq!(ssa_arg.version, 0);
    //     assert_eq!(ssa_arg.deref_version, 0);
    // }

    #[test]
    fn test_ssa_arg_display() {
        // Test immediate value
        let imm_arg = ssa_main_val!(42, 0);
        assert_eq!(format!("{}", imm_arg), "42");

        // Test register
        let reg_arg = ssa_main_rel!(2, 3);
        assert_eq!(format!("{}", reg_arg), "[R+2]_3");

        // Test deref
        let deref_arg = ssa_main_deref!(0x100, 2);
        assert_eq!(format!("{}", deref_arg), "[[256]_2]");
    }

    #[test]
    fn test_ssa_arg_display_with_deref() {
        // Test immediate value
        let imm_arg = ssa_main_val!(42, 0);
        assert_eq!(format!("{}", imm_arg), "42");

        // Test register
        let reg_arg = ssa_main_rel!(2, 3);
        assert_eq!(format!("{}", reg_arg), "[R+2]_3");

        // Test deref
        let deref_arg = ssa_main_deref!(0x100, 2);
        assert_eq!(format!("{}", deref_arg), "[[256]_2]");
    }

    struct TestContext {
        ssa_graphs: HashMap<FunctionId, SSAGraph>,
    }

    impl TestContext {
        fn new(code: &str) -> Self {
            let binary = parser::compile(code);
            let program: ProgramAnalysis = ProgramAnalysis::build(&binary);
            let mut ssa_graphs = HashMap::new();
            for (function_id, cflow) in &program.control_flows {
                let ssa = convert_to_ssa(&program, &cflow, &program.data_flows[&function_id]);
                ssa_graphs.insert(*function_id, ssa);
            }
            TestContext { ssa_graphs }
        }

        fn main(&self) -> &SSAGraph {
            let main_func_id = FunctionId::from(0);
            self.ssa_graphs.get(&main_func_id).unwrap()
        }
    }

    #[test]
    fn test_ssa_arg_display_with_deref_and_version() {
        // Test immediate value
        let imm_arg = ssa_main_val!(42, 0);
        assert_eq!(format!("{}", imm_arg), "42");

        // Test register
        let reg_arg = ssa_main_rel!(2, 3);
        assert_eq!(format!("{}", reg_arg), "[R+2]_3");

        // Test deref
        let deref_arg = ssa_main_deref!(0x100, 2);
        assert_eq!(format!("{}", deref_arg), "[[256]_2]");
    }

    #[test]
    fn test_basic_versioning() {
        let ctx = TestContext::new(
            r#"
            R += 5
            'b [R+2] = 'a [R+3] + [R+4]
            'c [R+2] = [R+3] + [R+4]
        "#,
        );
        let main_graph = ctx.main();
        println!("{:?}", main_graph.debug_markers);
        assert_marker_at_main!(ctx, 'a', ssa_main_rel!(3, 0));
        assert_marker_at_main!(ctx, 'b', ssa_main_rel!(2, 0));
        assert_marker_at_main!(ctx, 'c', ssa_main_rel!(2, 1));
    }

    #[test]
    fn test_deref_versioning() {
        let ctx = TestContext::new(
            r#"
            R += 5
            ptr = 500
            'a ptr = ptr + [R+2]
            'b ptr = ptr + [R+3]
            'd [R+1] = 'c *ptr
            "#,
        );
        let main_graph = ctx.main();
        println!("{:?}", main_graph.debug_markers);
        assert_marker_at_main!(ctx, 'a', ssa_main_mem!(15, 1));
        assert_marker_at_main!(ctx, 'b', ssa_main_mem!(15, 2));
        assert_marker_at_main!(ctx, 'c', ssa_main_deref!(15, 2));
        assert_marker_at_main!(ctx, 'd', ssa_main_rel!(1, 0))
    }

    #[test]
    fn test_incr_write_after_read() {
        let ctx = TestContext::new(
            r#"
            R += 5
            output('a [R-1])
            'b [R-1] = 17
            "#,
        );
        let main_graph = ctx.main();
        println!("{:?}", main_graph.debug_markers);
        assert_marker_at_main!(ctx, 'a', ssa_main_rel!(-1, 0));
        assert_marker_at_main!(ctx, 'b', ssa_main_rel!(-1, 1));
    }
}
