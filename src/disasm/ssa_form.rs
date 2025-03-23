use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
};

use super::{
    control_flow_graph::{Block, BlockId, ControlFlowGraph, NextKind},
    data_flow_analysis::{Definition, GraphDataFlow},
    low_ir::{Arg, ArgBase, GenericInstruction, OpArg},
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

pub struct SSAConverter<'a> {
    control_flow: &'a ControlFlowGraph<Arg>,
    data_flow: &'a GraphDataFlow<Arg>,
    current_version: HashMap<Arg, usize>,
    var_versions: HashMap<(BlockId, Arg), SSAArg>, // Maps (block, var) to SSA version
    // for each block, map Arg to index of phi function in block.ops
    phi_nodes: HashMap<(BlockId, Arg), usize>,
    out: ControlFlowGraph<SSAArg>,
}

impl<'a> SSAConverter<'a> {
    pub fn new(control_flow: &'a ControlFlowGraph<Arg>, flow: &'a GraphDataFlow<Arg>) -> Self {
        SSAConverter {
            control_flow,
            data_flow: flow,
            current_version: HashMap::new(),
            var_versions: HashMap::new(),
            phi_nodes: HashMap::new(),
            out: ControlFlowGraph {
                start: control_flow.start,
                stack_size: control_flow.stack_size,
                blocks: HashMap::new(),
            },
        }
    }

    pub fn convert(mut self) -> SSAGraph {
        // First pass
        for &block_id in self.control_flow.blocks.keys().sorted() {
            self.insert_phi_functions(block_id);
            self.insert_ops_with_renamed_writes(block_id);
        }
        // Second pass
        for &block_id in self.control_flow.blocks.keys().sorted() {
            self.rename_reads(block_id);
        }
        self.out
    }

    fn create_new_version_for_arg(&mut self, arg: Arg, block_id: BlockId) -> SSAArg {
        let new_version = *self.current_version.entry(arg).or_default() + 1;
        self.current_version.insert(arg, new_version);
        self.var_versions.insert(
            (block_id, arg),
            SSAArg {
                arg,
                version: new_version,
            },
        );
        SSAArg {
            arg,
            version: new_version,
        }
    }

    fn current_version_of_arg_in_block(&self, arg: Arg, block_id: BlockId) -> SSAArg {
        *self
            .var_versions
            .get(&(block_id, arg))
            .unwrap_or(&SSAArg { arg, version: 0 })
    }

    fn block_needs_phi_function(&self, block_id: BlockId, arg: &Arg) -> bool {
        let mut defs: HashSet<Definition<Arg>> = HashSet::new();
        let mut has_unknown = false;

        for pred in &self.control_flow.blocks[&block_id].predecessors {
            let pred_def = &self.data_flow.block_defs[&pred.block_id()];
            let incoming = pred_def.defs_out.iter().filter(|def| def.arg == *arg);
            if incoming.clone().count() == 0 {
                has_unknown = true;
                continue;
            }
            defs.extend(incoming);
        }
        defs.len() > 1 || (defs.len() == 1 && has_unknown)
    }

    /*
    fn transform_next_to_ssa(next_kind: NextKind<Arg>) -> NextKind<SSAArg> {
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
    */

    fn insert_phi_functions(&mut self, block_id: BlockId) {
        let block_def = &self.data_flow.block_defs[&block_id];
        let mut new_ops = vec![];

        for arg in &block_def.use_set {
            assert!(!arg.is_value(), "Immediate values should not be in use set");
            if self.block_needs_phi_function(block_id, arg) {
                let new_arg = self.create_new_version_for_arg(*arg, block_id);
                new_ops.push((
                    block_id.addr(),
                    GenericInstruction::Phi(
                        new_arg,
                        Vec::new(), // Will be populated in the next pass.
                    ),
                ));
                self.phi_nodes.insert((block_id, *arg), new_ops.len() - 1);
            }
        }

        self.out.blocks.insert(
            block_id,
            Block {
                ops: new_ops,
                span: self.control_flow.blocks[&block_id].span,
                next: NextKind::Unknown, // will be overwritten later
                predecessors: vec![],
            },
        );
    }

    fn insert_ops_with_renamed_writes(&mut self, block_id: BlockId) {
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

    fn rename_reads(&mut self, block_id: BlockId) {
        /*
                let block = self.out.blocks.get_mut(&block_id).unwrap();
                for op in block.ops.iter_mut() {
                    let new_op = op.1.map_rw(
                        &mut |read_arg: &SSAArg| {
                            if read_arg.arg.is_value() || read_arg.version != 0 {
                                *read_arg
                            } else {
                                self.control_flow[block_id].predecessors.iter().map(|pred| {
                                    pred.block_id
                                }
                            }
                        },
                        &mut |write_arg: &SSAArg| *write_arg,
                    );
                    *op = (op.0, new_op);
                }
        */
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
