use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use super::{
    control_flow_graph::{Block, BlockId, ControlFlowGraph},
    low_ir::{Arg, ArgBase, GenericInstruction, OpArg, Span},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Definition<ArgType> {
    pub instruction_addr: usize,
    pub arg: ArgType,
    pub block: BlockId,
}

impl<ArgType> Display for Definition<ArgType>
where
    ArgType: Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at {}", self.arg, self.block)
    }
}

#[derive(Debug)]
pub struct BlockDef<ArgType> {
    // Definitions available to the block from previous blocks.
    pub defs_in: HashSet<Definition<ArgType>>,

    // Definitions provided to following blocks.
    pub defs_out: HashSet<Definition<ArgType>>,

    // Defintions that are expected to be live when coming in (will be used in the block, or in a
    // successor block).
    pub live_in: HashSet<ArgType>,

    // Contains values that will be used in any successor blocks.
    pub live_out: HashSet<ArgType>,

    // ArgTypes defined in this block
    pub gen_set: HashMap<ArgType, Definition<ArgType>>,

    // ArgTypes used in this block before being possibly defined in the block.
    pub use_set: HashSet<ArgType>,
}

impl<ArgType> BlockDef<ArgType> {
    fn new() -> Self {
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
pub struct GraphDataFlow<ArgType> {
    pub block_defs: HashMap<BlockId, BlockDef<ArgType>>,
}

struct CreateStack {
    stack_size: usize,
    instruction_addr: usize,
}

fn get_definitions<ArgType>(
    block: &Block<ArgType>,
    create_stack: Option<CreateStack>,
) -> HashMap<ArgType, Definition<ArgType>>
where
    ArgType: ArgBase + Eq + std::hash::Hash + Clone + Copy + From<OpArg> + std::fmt::Debug,
{
    let mut hm = HashMap::new();
    if let Some(CreateStack {
        stack_size,
        instruction_addr,
    }) = create_stack
    {
        for r in 0..stack_size {
            let arg = OpArg {
                kind: Arg::RelativeMem(-(r as i128)),
                span: Span::new(instruction_addr, instruction_addr + 2),
            }
            .into();
            hm.insert(
                arg,
                Definition {
                    arg,
                    instruction_addr,
                    block: block.id(),
                },
            );
        }
    }
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

fn get_read_before_write<ArgType>(block: &Block<ArgType>) -> HashSet<ArgType>
where
    ArgType: ArgBase + Eq + std::hash::Hash + Clone + Copy + std::fmt::Debug,
{
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

impl<ArgType> GraphDataFlow<ArgType>
where
    ArgType: ArgBase + Copy + Clone + Eq + std::hash::Hash + From<OpArg> + std::fmt::Debug,
{
    /** Get the set of definitions that potentially reach the given block */

    fn forward_analysis(
        data_flow: &mut GraphDataFlow<ArgType>,
        control_flow: &ControlFlowGraph<ArgType>,
    ) {
        loop {
            let mut changed = false;
            for (addr, block) in &control_flow.blocks {
                let mut in_set = HashSet::new();
                for pred in &block.predecessors {
                    in_set.extend(data_flow.block_defs[&pred.block_id()].defs_out.clone());
                }
                let block_def = data_flow.block_defs.get_mut(addr).unwrap();
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

    fn live_variable_analysis(
        data_flow: &mut GraphDataFlow<ArgType>,
        control_flow: &ControlFlowGraph<ArgType>,
    ) {
        loop {
            let mut changed = false;
            for (addr, block) in &control_flow.blocks {
                let mut live_out_set = HashSet::new();
                for succ in &block.next_blocks() {
                    live_out_set.extend(data_flow.block_defs[succ].live_in.clone());
                }
                let block_def = data_flow.block_defs.get_mut(addr).unwrap();
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

    pub fn build_for(control_flow: &ControlFlowGraph<ArgType>) -> GraphDataFlow<ArgType> {
        let mut flow = GraphDataFlow {
            block_defs: HashMap::new(),
        };
        for (addr, block) in &control_flow.blocks {
            let mut block_def = BlockDef::new();
            let create_stack = if block.id() == control_flow.start && block.span.start != 0 {
                Some(CreateStack {
                    stack_size: control_flow.stack_size,
                    instruction_addr: block.span.start,
                })
            } else {
                None
            };
            block_def.gen_set = get_definitions(block, create_stack);
            block_def.use_set = get_read_before_write(block);
            flow.block_defs.insert(*addr, block_def);
        }
        Self::forward_analysis(&mut flow, control_flow);
        Self::live_variable_analysis(&mut flow, control_flow);
        flow
    }
}
