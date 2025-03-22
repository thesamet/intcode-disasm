use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display, Formatter},
};

use super::{
    control_flow_graph::{Block, BlockId, Graph},
    data_flow_analysis::GraphDataFlow,
    low_ir::{Arg, ArgBase, GenericInstruction, OpArg},
};

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

type SSAInstruction = GenericInstruction<SSAArg>;

type SSAGraph = Graph<SSAArg>;

type SSADataFlow = GraphDataFlow<SSAArg>;

pub struct SSAConverter<'a> {
    graph: &'a SSAGraph,
    flow: &'a SSADataFlow,
    current_version: HashMap<Arg, usize>,
    var_versions: HashMap<(BlockId, Arg), SSAArg>, // Maps (block, var) to SSA version
    phi_nodes: HashMap<BlockId, HashMap<SSAArg, SSAInstruction>>,
}

impl<'a> SSAConverter<'a> {
    pub fn new(graph: &'a SSAGraph, flow: &'a SSADataFlow) -> Self {
        SSAConverter {
            graph,
            flow,
            current_version: HashMap::new(),
            var_versions: HashMap::new(),
            phi_nodes: HashMap::new(),
        }
    }

    pub fn convert(&mut self) -> SSAGraph {
        // 1. Identify where phi functions are needed using data flow analysis
        self.place_phi_functions();

        // 2. Rename variables through the CFG
        self.rename_variables();

        // 3. Build the SSA graph with renamed variables and phi functions
        self.build_ssa_graph()
    }

    fn place_phi_functions(&mut self) {
        // For each block
        for (block_addr, block_def) in &self.flow.block_defs {
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
                    self.phi_nodes.entry(*block_addr).or_default().insert(
                        *arg,
                        GenericInstruction::Phi(
                            SSAArg {
                                arg: arg.arg,
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
                let new_version = *self.current_version.entry(arg.arg).or_insert(0) + 1;
                self.current_version.insert(arg.arg, new_version);

                let GenericInstruction::Phi(dest, _) = phi else {
                    panic!("Non-phi instruction in phi_map");
                };
                *dest = SSAArg {
                    arg: arg.arg,
                    version: new_version,
                };
                self.var_versions.insert((block_id, arg.arg), *dest);
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
                let version = *self.current_version.entry(read_arg.arg).or_insert(0);
                self.var_versions.insert(
                    (block_id, read_arg.arg),
                    SSAArg {
                        arg: read_arg.arg,
                        version,
                    },
                );
            }

            // Generate new version for defined variables
            if let Some(write_arg) = instr.writes() {
                if write_arg.is_value() {
                    continue;
                }
                let new_version = *self.current_version.entry(write_arg.arg).or_insert(0) + 1;
                self.current_version.insert(write_arg.arg, new_version);
                self.var_versions.insert(
                    (block_id, write_arg.arg),
                    SSAArg {
                        arg: write_arg.arg,
                        version: new_version,
                    },
                );
            }
        }

        // Process successors and update phi arguments
        for succ_addr in block.next_blocks() {
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
            self.rename_block(succ_addr, visited);
        }
    }

    fn build_ssa_graph(&self) -> SSAGraph {
        let mut new_blocks = HashMap::new();

        for (&block_id, block) in &self.graph.blocks {
            let mut new_ops = Vec::new();

            // Add phi functions at the beginning
            if let Some(phi_map) = self.phi_nodes.get(&block_id) {
                for phi in phi_map.values() {
                    new_ops.push((block_id.addr(), phi.clone()));
                }
            }

            // Add normal instructions with renamed variables
            for &(op_addr, ref op) in &block.ops {
                let new_op = op.map(|arg| {
                    if arg.is_value() {
                        SSAArg {
                            arg: arg.arg,
                            version: 0,
                        }
                    } else if let Some(version) = self.var_versions.get(&(block_id, arg.arg)) {
                        *version
                    } else {
                        unreachable!()
                    }
                });
                new_ops.push((op_addr, new_op));
            }

            // Create the new block with renamed instructions
            // ...update next and predecessor info accordingly...
            /*
                        let new_block = Block {
                            ops: new_ops,
                            span: block.span.clone(),
                            next: block.next.clone(),
                            predecessors: block.predecessors.clone(),
                        };
            */
        }

        // Return the new graph
        Graph {
            start: self.graph.start,
            stack_size: self.graph.stack_size,
            blocks: new_blocks,
        }
    }
    // Build a new graph with SSA-form instructions
    // ...implementation details...
}
