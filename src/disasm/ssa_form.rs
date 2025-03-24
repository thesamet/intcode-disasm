use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
};

use super::{
    control_flow_graph::{
        Block, BlockId, Condition, ControlFlowGraph, FunctionCall, NextKind, PredecessorKind,
    },
    data_flow_analysis::{Definition, GraphDataFlow},
    low_ir::{Arg, ArgBase, GenericInstruction, OpArg, Span},
};

use itertools::Itertools;
#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
pub struct SSAArg {
    pub arg: Arg,
    pub version: usize,
}

impl From<OpArg> for SSAArg {
    fn from(arg: OpArg) -> Self {
        SSAArg {
            arg: arg.kind,
            version: 0,
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
}

impl Display for SSAArg {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self.arg {
            Arg::Value(x) => write!(f, "{}", x), // No version for immediate values
            _ => write!(f, "{}_{}", self.arg, self.version),
        }
    }
}

type SSAGraph = ControlFlowGraph<SSAArg>;

// output = phi(inputs)
struct PhiNode {
    output: SSAArg,
    inputs: Vec<SSAArg>,
}

pub struct SSAConverter<'a> {
    control_flow: &'a ControlFlowGraph<Arg>,
    data_flow: &'a GraphDataFlow<Arg>,
    current_version: HashMap<Arg, usize>,
    var_versions: HashMap<BlockId, HashMap<Arg, SSAArg>>,
    // for each block, map Arg to index of phi function in block.ops
    phi_nodes: HashMap<BlockId, HashMap<Arg, PhiNode>>,
    visited: HashSet<BlockId>,
    out: ControlFlowGraph<SSAArg>,
}

impl<'a> SSAConverter<'a> {
    pub fn new(control_flow: &'a ControlFlowGraph<Arg>, flow: &'a GraphDataFlow<Arg>) -> Self {
        let mut res = SSAConverter {
            control_flow,
            data_flow: flow,
            current_version: HashMap::new(),
            var_versions: HashMap::new(),
            phi_nodes: HashMap::new(),
            visited: HashSet::new(),
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
        // First pass
        let mut hm = HashMap::new();
        let start_addr = self.control_flow.start.addr();
        for r in 0..(self.control_flow.stack_size) {
            let arg = OpArg {
                kind: Arg::RelativeMem(-(r as i128)),
                span: Span::new(start_addr, start_addr + 2),
            }
            .into();
            hm.insert(arg, SSAArg { arg, version: 0 });
        }
        self.var_versions.insert(self.control_flow.start, hm);
        for block in self.control_flow.blocks.keys() {
            self.insert_phi_functions(*block);
        }
        self.process_block(self.control_flow.start);
        self.prune_phi_functions();
        self.populate_phi_functions();
        self.out
    }

    fn prune_phi_functions(&mut self) {
        let mut replacements = HashMap::new();
        for (&block_id, phis) in &self.phi_nodes {
            for phi in phis.values() {
                if let Ok(input) = phi.inputs.iter().unique().exactly_one() {
                    replacements.insert(phi.output, (block_id, *input));
                }
            }
        }
        let mut final_replacements = HashMap::new();
        for (&source, (block_id, mut target)) in &replacements {
            while let Some((_, replacement)) = replacements.get(&target) {
                target = *replacement
            }
            final_replacements.insert(source, (block_id, target));
        }
        println!("Replacement for graph {}", self.control_flow.start);
        for rep in &final_replacements {
            println!("rep: {:?}", rep);
        }
        for (source, (block_id, _)) in &final_replacements {
            self.phi_nodes
                .get_mut(block_id)
                .unwrap()
                .remove(&source.arg);
        }
    }

    fn populate_phi_functions(&mut self) {
        for (block_id, phis) in &self.phi_nodes {
            let block = self.out.blocks.get_mut(block_id).unwrap();
            block
                .ops
                .splice(
                    0..0,
                    phis.iter().map(|(_, phi)| {
                        (
                            block.span.start,
                            GenericInstruction::Phi(phi.output, phi.inputs.clone()),
                        )
                    }),
                )
                .collect_vec();
        }
    }

    fn create_new_version_for_arg(&mut self, arg: Arg, block_id: BlockId) -> SSAArg {
        let new_version = *self.current_version.entry(arg).or_default() + 1;
        self.current_version.insert(arg, new_version);
        let new_arg = SSAArg {
            arg,
            version: new_version,
        };
        self.var_versions
            .entry(block_id)
            .or_default()
            .insert(arg, new_arg);
        new_arg
    }

    fn current_version_of_arg_in_block(&self, arg: Arg, block_id: BlockId) -> SSAArg {
        *self
            .var_versions
            .get(&block_id)
            .and_then(|hs| hs.get(&arg))
            .unwrap_or(&SSAArg { arg, version: 0 })
    }

    fn block_needs_phi_function(&self, block_id: BlockId, arg: &Arg) -> bool {
        let control_def = &self.control_flow.blocks[&block_id];
        let predecessor_count = control_def.predecessors.len();

        if predecessor_count <= 1 {
            return false;
        }

        let mut total_defs = 0;
        let mut has_empty = false;
        for pred in &control_def.predecessors {
            let count = self.data_flow.block_defs[&pred.block_id()]
                .defs_out
                .iter()
                .filter(|d| d.arg == *arg)
                .count();
            if count == 0 {
                has_empty = true;
            }
            total_defs += 1;
        }

        total_defs > 1 || has_empty
    }

    fn transform_next_to_ssa(
        &self,
        block_id: BlockId,
        next_kind: NextKind<Arg>,
    ) -> NextKind<SSAArg> {
        let to_ssa = |&arg| self.current_version_of_arg_in_block(arg, block_id);
        match next_kind {
            NextKind::Goto(arg) => NextKind::Goto(to_ssa(&arg)),
            NextKind::FunctionCall(FunctionCall {
                calling_block,
                function_addr,
                return_block,
            }) => NextKind::FunctionCall(FunctionCall {
                calling_block,
                function_addr: to_ssa(&function_addr),
                return_block,
            }),
            NextKind::Condition(Condition {
                from_block,
                jump_block,
                follows_block,
                arg,
                matches,
            }) => NextKind::Condition(Condition {
                from_block,
                jump_block,
                follows_block,
                arg: to_ssa(&arg),
                matches,
            }),
            NextKind::Halt => NextKind::Halt,
            NextKind::Unknown => NextKind::Unknown,
            NextKind::Return => NextKind::Return,
            NextKind::Follows(block_id) => NextKind::Follows(block_id),
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
            .sorted()
            .collect_vec()
        {
            assert!(!arg.is_value(), "Immediate values should not be in use set");
            if self.block_needs_phi_function(block_id, arg) {
                let output = self.create_new_version_for_arg(*arg, block_id);
                self.phi_nodes.entry(block_id).or_default().insert(
                    *arg,
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
                &mut |s: &mut SSAConverter<'a>, read_arg: &Arg| {
                    s.current_version_of_arg_in_block(*read_arg, block_id)
                },
                // not writing directly to var_versions here since calls to the read_map closure
                // should see the previous version of the variable
                &mut |s: &mut SSAConverter<'a>, write_arg: &Arg| {
                    s.create_new_version_for_arg(*write_arg, block_id)
                },
            );
            let block = self.out.blocks.get_mut(&block_id).unwrap();
            block.ops.push((*addr, new_op));
        }
    }

    fn process_block(&mut self, block_id: BlockId) {
        self.visited.insert(block_id);
        println!("Processing block {}", block_id);
        println!("var_versions: {:?}", self.var_versions[&block_id]);
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
        self.out.blocks.get_mut(&block_id).unwrap().next =
            self.transform_next_to_ssa(block_id, cdef.next);
    }

    /*

                    out.graph.blocks[&block_id].ops.push(GenericInstruction::Phi(
                        SSAArg {
                            arg: *arg,
                            version: 0,
                        }, // Placeholder
                        Vec::new(), // Will be populated during renaming
                    ));
                    graph.blocks[&block_id].ops.push(GenericInstruction::Phi(
                        SSAArg {
                            arg: *arg,
                            version: 0,
                        }, // Placeholder
                        Vec::new(), // Will be populated during renaming
                    ));

                }
    */
}

/*
fn place_phi_functions(&mut self) {
    // For each block
    for (block_id, block_def) in &self.flow.block_defs {
        // For variables that are used in this block before being defined
        for arg in &block_def.use_set {
            assert!(!arg.is_value(), "Immediate values should not be in use set");

            // Count distinct definitions reaching this block
            let incoming_defs: HashSet<_> = block_def
                .defs_in
                .iter()
                .filter(|def| def.arg == *arg)
                .map(|def| def.block) // Group by source block
                .collect();

            // If multiple definitions reach this point, insert a phi function
            if incoming_defs.len() > 1 {
                self.phi_nodes.entry(*block_id).or_default().insert(
                    *arg,
                    GenericInstruction::Phi(
                        SSAArg {
                            arg: *arg,
                            version: 0,
                        }, // Placeholder
                        Vec::new(), // Will be populated during renaming
                    ),
                );
            }
        }
    }
}

fn rename_variables(&mut self) {
    // Start with entry block and visit all blocks in a DFS fashion
    let mut visited = HashSet::new();
    self.rename_block(self.graph.start, &mut visited);
}

fn rename_block(&mut self, block_id: BlockId, visited: &mut HashSet<BlockId>) {
    if !visited.insert(block_id) {
        return; // Already processed
    }

    // Process phi nodes first (if any)
    if let Some(phi_map) = self.phi_nodes.get_mut(&block_id) {
        for (arg, phi) in phi_map {
            // Assign new version to phi result
            let new_version = *self.current_version.entry(*arg).or_insert(0) + 1;
            self.current_version.insert(*arg, new_version);

            let GenericInstruction::Phi(dest, _) = phi else {
                panic!("Non-phi instruction in phi_map");
            };
            *dest = SSAArg {
                arg: *arg,
                version: new_version,
            };
            self.var_versions.insert((block_id, *arg), *dest);
        }
    }

    // Process regular instructions
    let block = &self.graph.blocks[&block_id];
    for (_, instr) in &block.ops {
        // Rename used variables
        for read_arg in instr.reads() {
            if read_arg.is_value() {
                continue;
            }
            // Use the current version
            let version = *self.current_version.entry(*read_arg).or_insert(0);
            self.var_versions.insert(
                (block_id, *read_arg),
                SSAArg {
                    arg: *read_arg,
                    version,
                },
            );
        }

        // Generate new version for defined variables
        if let Some(write_arg) = instr.writes() {
            if write_arg.is_value() {
                continue;
            }
            let new_version = *self.current_version.entry(*write_arg).or_insert(0) + 1;
            self.current_version.insert(*write_arg, new_version);
            self.var_versions.insert(
                (block_id, *write_arg),
                SSAArg {
                    arg: *write_arg,
                    version: new_version,
                },
            );
        }
    }

    // Process successors and update phi arguments
    for succ_addr in block.next_blocks().iter().rev() {
        if let Some(phi_map) = self.phi_nodes.get_mut(&succ_addr) {
            for (arg, phi) in phi_map {
                if let Some(version) = self.var_versions.get(&(block_id, arg.arg)) {
                    if let GenericInstruction::Phi(_, args) = phi {
                        args.push(*version);
                    }
                }
            }
        }

        // Recursively rename successors
        self.rename_block(*succ_addr, visited);
    }
}

fn build_ssa_graph(&self) -> SSAGraph {
    let mut new_blocks = HashMap::new();

    for (&block_id, block) in &self.graph.blocks {
        let to_ssa = |arg: &Arg| {
            if arg.is_value() {
                SSAArg {
                    arg: *arg,
                    version: 0,
                }
            } else if let Some(version) = self.var_versions.get(&(block_id, *arg)) {
                *version
            } else {
                unreachable!()
            }
        };
        let mut new_ops = Vec::new();

        // Add phi functions at the beginning
        if let Some(phi_map) = self.phi_nodes.get(&block_id) {
            for phi in phi_map.values() {
                new_ops.push((block_id.addr(), phi.clone()));
            }
        }

        // Add normal instructions with renamed variables
        for &(op_addr, ref op) in &block.ops {
            let new_op = op.map(to_ssa);
            new_ops.push((op_addr, new_op));
        }

        let next = match block.next {
            NextKind::Goto(arg) => NextKind::Goto(to_ssa(&arg)),
            NextKind::FunctionCall(FunctionCall {
                calling_block,
                function_addr,
                return_block,
            }) => NextKind::FunctionCall(FunctionCall {
                calling_block,
                function_addr: to_ssa(&function_addr),
                return_block,
            }),
            NextKind::Condition(Condition {
                from_block,
                jump_block,
                follows_block,
                arg,
                matches,
            }) => NextKind::Condition(Condition {
                from_block,
                jump_block,
                follows_block,
                arg: to_ssa(&arg),
                matches,
            }),
            NextKind::Halt => NextKind::Halt,
            NextKind::Unknown => NextKind::Unknown,
            NextKind::Return => NextKind::Return,
            NextKind::Follows(block_id) => NextKind::Follows(block_id),
        };

        let new_block = Block {
            ops: new_ops,
            span: block.span,
            next,
            predecessors: vec![],
        };
        new_blocks.insert(block_id, new_block);
    }

    // Return the new graph
    Graph {
        start: self.graph.start,
        stack_size: self.graph.stack_size,
        blocks: new_blocks,
    }
}
*/
