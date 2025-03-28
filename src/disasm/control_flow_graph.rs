use std::{
    collections::{HashMap, HashSet},
    fmt::{Debug, Display},
};

use itertools::Itertools;

use crate::disasm::low_ir::Span;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlockId(usize);

impl BlockId {
    pub fn addr(&self) -> usize {
        self.0
    }
}

impl From<usize> for BlockId {
    fn from(id: usize) -> Self {
        BlockId(id)
    }
}

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
use super::{
    low_ir::{Arg, ArgBase, GenericInstruction, Input, OpArg, ParseError},
    mid_ir::ArgType,
    program_analysis::ProgramAnalysis,
    type_inference::TypeInference,
};

#[derive(Debug, Copy, Clone)]
pub struct FunctionCall<ArgType> {
    pub calling_block: BlockId,
    pub function_addr: ArgType,
    pub return_block: BlockId,
}

#[derive(Debug, Copy, Clone)]
pub struct Condition<ArgType> {
    pub from_block: BlockId,
    pub jump_block: BlockId,
    pub follows_block: BlockId,
    pub arg: ArgType,
    pub matches: bool,
}

#[derive(Debug, Copy, Clone)]
pub enum NextKind<ArgType> {
    Follows(BlockId), // block always immediately follows
    Goto(ArgType),    // unconditional jump
    FunctionCall(FunctionCall<ArgType>),
    Condition(Condition<ArgType>),
    Halt,
    Unknown,
    Return,
}

#[derive(Debug, Copy, Clone)]
pub enum PredecessorKind<ArgType> {
    FollowsFrom(BlockId), // block immediately before
    GotoFrom(BlockId),    // block the goto came from
    FunctionCallReturns(FunctionCall<ArgType>),
    ConditionalFollow(Condition<ArgType>),
    ConditionalJump(Condition<ArgType>),
}

impl<ArgType: ArgBase> PredecessorKind<ArgType> {
    pub fn block_id(&self) -> BlockId {
        match self {
            PredecessorKind::FollowsFrom(block_id) => *block_id,
            PredecessorKind::GotoFrom(block_id) => *block_id,
            PredecessorKind::FunctionCallReturns(FunctionCall { calling_block, .. }) => {
                *calling_block
            }
            PredecessorKind::ConditionalFollow(Condition { from_block, .. }) => *from_block,
            PredecessorKind::ConditionalJump(Condition { from_block, .. }) => *from_block,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Block<ArgType> {
    pub predecessors: Vec<PredecessorKind<ArgType>>,
    pub ops: Vec<(usize, GenericInstruction<ArgType>)>,
    pub next: NextKind<ArgType>,
    pub span: Span, // includes the possible branching at the end.
}

impl<ArgType> Block<ArgType> {
    pub fn id(&self) -> BlockId {
        BlockId(self.span.start)
    }
}

impl<ArgType: ArgBase + From<OpArg> + Copy + Debug> Block<ArgType> {
    fn parse_function_call<'a>(
        input: Input<'a>,
        block: &mut Block<ArgType>,
    ) -> Result<Input<'a>, ParseError> {
        let assign_offset = input.offset;
        let (input, assign_op) = GenericInstruction::<ArgType>::parse(input)?;
        let return_addr = match assign_op {
            GenericInstruction::Assign(_, arg) if arg.is_value() => arg.value().unwrap(),
            _ => return Err(ParseError::InvalidOpcode),
        };
        let return_addr = return_addr as usize;

        let goto_offset = input.offset;
        let (input, goto_op) = GenericInstruction::parse(input)?;
        let GenericInstruction::Goto(goto_arg) = goto_op else {
            return Err(ParseError::InvalidOpcode);
        };
        if return_addr != input.offset {
            return Err(ParseError::InvalidOpcode);
        }
        block.next = NextKind::FunctionCall(FunctionCall {
            calling_block: BlockId(0),
            function_addr: goto_arg,
            return_block: BlockId(return_addr),
        });
        block.ops.push((assign_offset, assign_op));
        block.ops.push((goto_offset, goto_op));
        Ok(input)
    }

    fn parse_return<'a>(
        input: Input<'a>,
        block: &mut Block<ArgType>,
    ) -> Result<Input<'a>, ParseError> {
        let adjust_offset = input.offset;
        let (input, adjust_op) = GenericInstruction::<ArgType>::parse(input)?;
        let GenericInstruction::AdjustRelativeBase(arg) = &adjust_op else {
            return Err(ParseError::NoMatch);
        };
        if arg.value().is_none_or(|r| r >= 0) {
            return Err(ParseError::NoMatch);
        }
        let goto_offset = input.offset;
        let (input, goto_op) = GenericInstruction::<ArgType>::parse(input)?;
        let GenericInstruction::Goto(goto_arg) = &goto_op else {
            return Err(ParseError::NoMatch);
        };
        if goto_arg.relative_mem() != Some(0) {
            return Err(ParseError::NoMatch);
        }
        block.next = NextKind::Return;
        block.ops.push((adjust_offset, adjust_op));
        block.ops.push((goto_offset, goto_op));
        Ok(input)
    }

    // continues as long as it returns Ok(true), Ok(false) is successful completion.
    fn parse_single<'a>(
        input: Input<'a>,
        block: &mut Block<ArgType>,
    ) -> Result<(Input<'a>, bool), ParseError> {
        if let Ok(input) =
            Self::parse_function_call(input, block).or_else(|_| Self::parse_return(input, block))
        {
            return Ok((input, false));
        }
        let offset = input.offset;
        let (input, op) = GenericInstruction::parse(input)?;
        block.ops.push((offset, op.clone()));

        match &op {
            GenericInstruction::Goto(op_arg) => {
                block.next = NextKind::Goto(*op_arg);
                Ok((input, false))
            }
            GenericInstruction::JumpIf(arg, matches, jump_arg) if jump_arg.is_value() => {
                let jump_block = BlockId(jump_arg.value().unwrap() as usize);
                block.next = NextKind::Condition(Condition {
                    from_block: BlockId(0), // filled in another pass since the block we are currently on may split.
                    jump_block,
                    follows_block: BlockId(input.offset),
                    arg: *arg,
                    matches: *matches,
                });
                Ok((input, false))
            }
            GenericInstruction::Halt => {
                let input = Self::parse_halt_exit(block, input).unwrap_or(input);
                block.next = NextKind::Halt; // needs to be here since parse_halt_exit may set to
                                             // return kind.
                Ok((input, false))
            }
            GenericInstruction::Data(_) => unreachable!(),
            _ => Ok((input, true)),
        }
    }

    fn parse_halt_exit<'a>(
        block: &mut Block<ArgType>,
        input: Input<'a>,
    ) -> Result<Input<'a>, ParseError> {
        let halt_offset = input.offset - 1;
        let (input, op) = GenericInstruction::<ArgType>::parse(input)?;
        let goto_offset = match op {
            GenericInstruction::Goto(arg) if arg.is_value() => arg.value().unwrap() as usize,
            _ => return Err(ParseError::NoMatch),
        };
        if goto_offset != halt_offset {
            return Err(ParseError::NoMatch);
        }
        block.ops.push((halt_offset, op));
        let input = Self::parse_return(input, block).unwrap_or(input);
        Ok(input)
    }

    fn parse(input: Input, jump_targets: &HashSet<usize>) -> Result<Block<ArgType>, ParseError> {
        let mut block = Block {
            predecessors: vec![],
            ops: vec![],
            next: NextKind::Unknown,
            span: Span::new(input.offset, input.offset),
        };
        let mut input = input;
        let mut cont = true;
        while cont {
            let (next_input, next_cont) = Self::parse_single(input, &mut block)?;
            input = next_input;
            cont = next_cont;
            if cont && jump_targets.contains(&next_input.offset) {
                block.next = NextKind::Follows(BlockId(next_input.offset));
                break;
            }
        }
        block.span.end = input.offset;
        Ok(block)
    }

    fn next_unconditional(&self) -> Option<BlockId> {
        match &self.next {
            NextKind::Follows(block_id) => Some(*block_id),
            NextKind::Goto(arg) if arg.is_value() => Some(BlockId(arg.value().unwrap() as usize)),
            _ => None,
        }
    }

    pub fn function_call_address(&self) -> Option<usize> {
        match &self.next {
            NextKind::FunctionCall(
                FunctionCall {
                    function_addr: arg, ..
                },
                ..,
            ) if arg.is_value() => Some(arg.value().unwrap() as usize),
            _ => None,
        }
    }

    pub fn next_blocks(&self) -> Vec<BlockId> {
        match &self.next {
            NextKind::Follows(addr) => vec![*addr],
            NextKind::Goto(arg) if arg.is_value() => vec![BlockId(arg.value().unwrap() as usize)],
            NextKind::FunctionCall(FunctionCall { return_block, .. }) => vec![*return_block],
            NextKind::Halt => vec![],
            NextKind::Unknown => vec![],
            NextKind::Return => vec![],
            NextKind::Condition(Condition {
                jump_block,
                follows_block,
                ..
            }) => vec![*jump_block, *follows_block],
            _ => {
                unreachable!("next_blocks: {:?}", self.next);
            }
        }
    }
}

impl<ArgType> Display for Block<ArgType>
where
    ArgType: ArgBase + Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Block {}: ", self.span)?;
        for (addr, op) in &self.ops {
            writeln!(f, "{:8}  {}", addr, op)?;
        }
        write!(f, "Next block: ")?;
        match &self.next {
            NextKind::Follows(addr) => writeln!(f, "follows {}", addr)?,
            NextKind::Goto(arg) => writeln!(f, "goto {}", arg)?,
            NextKind::FunctionCall(FunctionCall {
                function_addr,
                return_block,
                ..
            }) => writeln!(f, "function call {} return {}", function_addr, return_block)?,
            NextKind::Condition(Condition {
                jump_block,
                follows_block,
                arg,
                matches,
                ..
            }) => writeln!(
                f,
                "if {} is {} goto {} else {}",
                arg, matches, jump_block, follows_block
            )?,
            NextKind::Halt => writeln!(f, "halt")?,
            NextKind::Unknown => writeln!(f, "unknown")?,
            NextKind::Return => writeln!(f, "return")?,
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ControlFlowGraph<ArgType: ArgBase> {
    pub start: BlockId,
    pub stack_size: usize,
    pub blocks: HashMap<BlockId, Block<ArgType>>,
}

impl<ArgType: ArgBase> ControlFlowGraph<ArgType>
where
    ArgType: ArgBase + From<OpArg> + Copy + Clone + Debug,
{
    fn split_blocks(blocks: &mut HashMap<BlockId, Block<ArgType>>, jump_targets: &HashSet<usize>) {
        let mut blocks_to_split = vec![];
        for (addr, block) in blocks.iter() {
            for jump_target in jump_targets.iter().sorted().rev() {
                if *jump_target != block.span.start && block.span.contains_address(*jump_target) {
                    blocks_to_split.push((*addr, *jump_target));
                    println!("Splitting block at {} to {}", addr, jump_target);
                }
            }
        }

        for (addr, jump_target) in blocks_to_split {
            let block = blocks.get_mut(&addr).unwrap();
            let index = block
                .ops
                .iter()
                .position(|(addr, _)| *addr == jump_target)
                .unwrap();
            let new_ops = block.ops.split_off(index);

            let new_block = Block {
                ops: new_ops,
                next: block.next,
                span: block.span.with_start(jump_target),
                predecessors: vec![],
            };
            block.next = NextKind::Follows(BlockId(jump_target));
            block.span.end = jump_target;
            blocks.insert(BlockId(jump_target), new_block);
        }
    }

    fn parse_stack_size(input: Input) -> Result<usize, ParseError> {
        let (_, adjust_res) = GenericInstruction::parse(input)?;
        match adjust_res {
            GenericInstruction::AdjustRelativeBase(Arg::Value(r)) if r > 0 => {
                if input.offset == 0 {
                    Ok(0)
                } else {
                    Ok(r as usize)
                }
            }
            _ => Err(ParseError::NoMatch),
        }
    }

    pub fn build_from(prog: &[i128], start: usize) -> Result<Self, ParseError> {
        let mut blocks = HashMap::new();
        let mut seen = HashSet::new();
        let mut stack = Vec::new();
        let mut jump_targets = HashSet::new();
        stack.push(start);
        let stack_size = Self::parse_stack_size(make_input(prog, start))?;
        while let Some(offset) = stack.pop() {
            if seen.contains(&offset) {
                continue;
            }
            seen.insert(offset);
            let input = make_input(prog, offset);
            let block = Block::parse(input, &jump_targets)?;
            stack.extend(block.next_blocks().iter().map(|b| b.addr()));
            jump_targets.extend(block.next_blocks().iter().map(|b| b.addr()));
            blocks.insert(BlockId(offset), block);
        }
        Self::split_blocks(&mut blocks, &jump_targets);
        for (addr, block) in &mut blocks {
            if let NextKind::FunctionCall(fc) = &mut block.next {
                fc.calling_block = *addr;
            }
        }
        for (x, y) in blocks.iter().sorted_by_key(|x| x.0).tuple_windows() {
            assert!(x.1.span.end <= y.1.span.start);
        }
        Self::update_predecessor(&mut blocks);
        Ok(ControlFlowGraph {
            start: BlockId(start),
            stack_size,
            blocks,
        })
    }

    pub fn scan(prog: &[i128]) -> Vec<ControlFlowGraph<ArgType>> {
        let mut graphs = vec![];
        let mut data = vec![];
        for start in 0..prog.len() {
            if graphs.iter().any(|g: &ControlFlowGraph<ArgType>| {
                g.blocks
                    .iter()
                    .any(|(_, block)| block.span.contains_address(start))
            }) {
                continue;
            }
            let Ok((_, GenericInstruction::AdjustRelativeBase(Arg::Value(r)))) =
                GenericInstruction::parse(make_input(prog, start))
            else {
                data.push(start);
                continue;
            };
            if r < 0 {
                data.push(start);
                continue;
            }

            if let Ok(res) = Self::build_from(prog, start) {
                println!("Added graph starting at {}", start);
                graphs.push(res);
            } else {
                data.push(start);
            }
        }
        let data_segments = data
            .iter()
            .map(|o| Span::new(*o, *o + 1))
            .coalesce(|x, y| {
                if x.end == y.start {
                    Ok(Span::new(x.start, y.end))
                } else {
                    Err((x, y))
                }
            })
            .collect_vec();
        println!("Data segments: {:?}", data_segments);
        graphs
    }

    fn update_predecessor(blocks: &mut HashMap<BlockId, Block<ArgType>>) {
        let mut hm = HashMap::new();
        let mut add_pred = |dst, v| {
            hm.entry(dst).or_insert_with(Vec::new).push(v);
        };
        for (&src, block) in blocks.iter_mut() {
            match block.next {
                NextKind::Follows(p) => add_pred(p, PredecessorKind::FollowsFrom(src)),
                NextKind::Goto(arg) if arg.is_value() => add_pred(
                    BlockId(arg.value().unwrap() as usize),
                    PredecessorKind::GotoFrom(src),
                ),
                NextKind::Goto(_) => unreachable!(),
                NextKind::FunctionCall(ref mut function_call) => {
                    function_call.calling_block = src;
                    add_pred(
                        function_call.return_block,
                        PredecessorKind::FunctionCallReturns(*function_call),
                    );
                }
                NextKind::Condition(ref mut condition) => {
                    condition.from_block = src;
                    add_pred(
                        condition.jump_block,
                        PredecessorKind::ConditionalJump(*condition),
                    );
                    add_pred(
                        condition.follows_block,
                        PredecessorKind::ConditionalFollow(*condition),
                    )
                }
                _ => {}
            }
        }
        for (src, pred) in hm {
            let block = blocks.get_mut(&src).unwrap();
            block.predecessors = pred;
        }
    }
}

fn make_input(prog: &[i128], offset: usize) -> Input<'_> {
    let input = Input::new(offset, &prog[offset..]);
    input
}

impl<ArgType> Display for ControlFlowGraph<ArgType>
where
    ArgType: ArgBase + Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (addr, block) in self.blocks.iter().sorted_by_key(|x| x.0) {
            writeln!(f, "addr {}, {}", addr, block)?;
        }
        Ok(())
    }
}

pub fn drive(prog: &[i128]) {
    let p = ProgramAnalysis::build(prog);
    let mut ti = TypeInference::new();
    ti.generate_constaints_for_program(&p);
    let subst = ti.unify().unwrap();
    p.list_program_with_types(&mut ti, &subst)

    /*
    for f in p.control_flows.keys().sorted() {
        if let Some(fc) = p.function_infos.get(f) {
            println!(
                "Function at {}: args={:?}, returns={:?}",
                fc.start_block, fc.args, fc.return_vars
            );
        } else {
            // println!("Missing function info for {}", f);
        }
    }
    */
}
