use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use super::{
    control_flow_graph::{Block, BlockId, Graph},
    low_ir::Arg,
};

use itertools::Itertools;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Definition {
    pub instruction_addr: usize,
    pub arg: Arg,
    pub block: BlockId,
}

impl Display for Definition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}", self.arg, self.block)
    }
}

#[derive(Debug)]
pub struct BlockDef {
    // Definitions available to the block from previous blocks.
    pub defs_in: HashSet<Definition>,

    // Definitions provided to following blocks.
    pub defs_out: HashSet<Definition>,

    // Defintions that are expected to be live when coming in (will be used in the block, or in a
    // successor block).
    pub live_in: HashSet<Arg>,

    // Contains values that will be used in any successor blocks.
    pub live_out: HashSet<Arg>,

    // Args defined in this block
    pub gen_set: HashMap<Arg, Definition>,

    // Args used in this block before being possibly defined in the block.
    pub use_set: HashSet<Arg>,
}

impl BlockDef {
    fn new() -> BlockDef {
        BlockDef {
            defs_in: HashSet::new(),
            defs_out: HashSet::new(),
            live_in: HashSet::new(),
            live_out: HashSet::new(),
            gen_set: HashMap::new(),
            use_set: HashSet::new(),
        }
    }
}

#[derive(Debug)]
pub struct GraphDataFlow {
    pub block_defs: HashMap<BlockId, BlockDef>,
}

fn get_definitions(block: &Block) -> HashMap<Arg, Definition> {
    let mut hm = HashMap::new();
    for (addr, inst) in &block.ops {
        if let Some(arg) = inst.writes() {
            // gives last from each block
            hm.insert(
                *arg,
                Definition {
                    arg: *arg,
                    instruction_addr: *addr,
                    block: block.id(),
                },
            );
        }
    }
    hm
}

fn get_read_before_write(block: &Block) -> HashSet<Arg> {
    let mut use_set = HashSet::new();
    let mut defines = HashSet::new();
    for (_, inst) in &block.ops {
        for r in inst.reads() {
            if !defines.contains(r) {
                use_set.insert(*r);
            }
        }
        if let Some(r) = inst.writes() {
            defines.insert(*r);
        }
    }
    use_set
}

impl GraphDataFlow {
    /** Get the set of definitions that potentially reach the given block */

    fn forward_analysis(flow: &mut GraphDataFlow, graph: &Graph) {
        loop {
            let mut changed = false;
            for (addr, block) in &graph.blocks {
                let mut in_set = HashSet::new();
                for pred in &block.predecessors {
                    in_set.extend(flow.block_defs[&pred.addr()].defs_out.clone());
                }
                let block_def = flow.block_defs.get_mut(addr).unwrap();
                if in_set != block_def.defs_in {
                    changed = true;
                    block_def.defs_in = in_set;
                }
                let mut out_set = block_def.defs_in.clone();
                out_set.retain(|def| !block_def.gen_set.contains_key(&def.arg));
                out_set.extend(block_def.gen_set.values());
                if out_set != block_def.defs_out {
                    changed = true;
                    block_def.defs_out = out_set;
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn live_variable_analysis(flow: &mut GraphDataFlow, graph: &Graph) {
        loop {
            let mut changed = false;
            for (addr, block) in &graph.blocks {
                let mut live_out_set = HashSet::new();
                for succ in &block.next_blocks() {
                    live_out_set.extend(flow.block_defs[succ].live_in.clone());
                }
                let block_def = flow.block_defs.get_mut(addr).unwrap();
                if live_out_set != block_def.live_out {
                    changed = true;
                    block_def.live_out = live_out_set;
                }
                let mut live_in_set = block_def.use_set.clone();
                live_in_set.extend(
                    block_def
                        .live_out
                        .iter()
                        .filter(|arg| !block_def.gen_set.contains_key(arg))
                        .cloned(),
                );
                if live_in_set != block_def.live_in {
                    changed = true;
                    block_def.live_in = live_in_set;
                }
            }
            if !changed {
                break;
            }
        }
    }

    pub fn build_for(graph: &Graph) -> GraphDataFlow {
        let mut flow = GraphDataFlow {
            block_defs: HashMap::new(),
        };
        for (addr, block) in &graph.blocks {
            let mut block_def = BlockDef::new();
            block_def.gen_set = get_definitions(block);
            block_def.use_set = get_read_before_write(block);
            flow.block_defs.insert(*addr, block_def);
        }
        Self::forward_analysis(&mut flow, graph);
        Self::live_variable_analysis(&mut flow, graph);
        flow
    }
}
