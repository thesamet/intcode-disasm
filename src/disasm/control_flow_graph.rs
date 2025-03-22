use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use itertools::Itertools;

use crate::disasm::{data_flow_analysis, low_ir::Span};

use super::low_ir::{Arg, ArgInstruction, Input, ParseError};

#[derive(Debug, Copy, Clone)]
pub struct FunctionCall {
    pub calling_block: usize,
    pub function_addr: Arg,
    pub return_block: usize,
}

#[derive(Debug, Copy, Clone)]
pub struct Condition {
    pub from_block: usize,
    pub jump_block: usize,
    pub follows_block: usize,
    pub arg: Arg,
    pub matches: bool,
}

#[derive(Debug, Copy, Clone)]
pub enum NextKind {
    Follows(usize), // block always immediately follows
    Goto(Arg),      // unconditional jump
    FunctionCall(FunctionCall),
    Condition(Condition),
    Halt,
    Unknown,
    Return,
}

#[derive(Debug, Copy, Clone)]
pub enum PredecessorKind {
    FollowsFrom(usize), // block immediately before
    GotoFrom(usize),    // block the goto came from
    FunctionCallReturns(FunctionCall),
    ConditionalFollow(Condition),
    ConditionalJump(Condition),
}

impl PredecessorKind {
    pub fn addr(&self) -> usize {
        match self {
            PredecessorKind::FollowsFrom(addr) => *addr,
            PredecessorKind::GotoFrom(addr) => *addr,
            PredecessorKind::FunctionCallReturns(FunctionCall { calling_block, .. }) => {
                *calling_block
            }
            PredecessorKind::ConditionalFollow(Condition { from_block, .. }) => *from_block,
            PredecessorKind::ConditionalJump(Condition { from_block, .. }) => *from_block,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub predecessors: Vec<PredecessorKind>,
    pub ops: Vec<(usize, ArgInstruction)>,
    pub next: NextKind,
    pub span: Span, // includes the possible branching at the end.
}

impl Block {
    fn parse_function_call<'a>(
        input: Input<'a>,
        block: &mut Block,
    ) -> Result<Input<'a>, ParseError> {
        let assign_offset = input.offset;
        let (input, assign_op) = ArgInstruction::parse(input)?;
        let ArgInstruction::Assign(_, Arg::Value(return_addr)) = assign_op else {
            return Err(ParseError::InvalidOpcode);
        };
        let return_addr = return_addr as usize;

        let goto_offset = input.offset;
        let (input, goto_op) = ArgInstruction::parse(input)?;
        let ArgInstruction::Goto(goto_arg) = goto_op else {
            return Err(ParseError::InvalidOpcode);
        };
        if return_addr != input.offset {
            return Err(ParseError::InvalidOpcode);
        }
        block.next = NextKind::FunctionCall(FunctionCall {
            calling_block: 0,
            function_addr: goto_arg,
            return_block: return_addr,
        });
        block.ops.push((assign_offset, assign_op));
        block.ops.push((goto_offset, goto_op));
        Ok(input)
    }

    fn parse_return<'a>(input: Input<'a>, block: &mut Block) -> Result<Input<'a>, ParseError> {
        let adjust_offset = input.offset;
        let (input, adjust_op) = ArgInstruction::parse(input)?;
        let ArgInstruction::AdjustRelativeBase(Arg::Value(r)) = adjust_op else {
            return Err(ParseError::NoMatch);
        };
        if r >= 0 {
            return Err(ParseError::NoMatch);
        }
        let goto_offset = input.offset;
        let (input, goto_op) = ArgInstruction::parse(input)?;
        if let ArgInstruction::Goto(Arg::RelativeMem(0)) = goto_op {
            block.next = NextKind::Return;
        } else {
            return Err(ParseError::NoMatch);
        }
        block.ops.push((adjust_offset, adjust_op));
        block.ops.push((goto_offset, goto_op));
        Ok(input)
    }

    // continues as long as it returns Ok(true), Ok(false) is successful completion.
    fn parse_single<'a>(
        input: Input<'a>,
        block: &mut Block,
    ) -> Result<(Input<'a>, bool), ParseError> {
        if let Ok(input) =
            Self::parse_function_call(input, block).or_else(|_| Self::parse_return(input, block))
        {
            return Ok((input, false));
        }
        let offset = input.offset;
        let (input, op) = ArgInstruction::parse(input)?;
        block.ops.push((offset, op.clone()));

        match op {
            ArgInstruction::Goto(op_arg) => {
                block.next = NextKind::Goto(op_arg);
                Ok((input, false))
            }
            ArgInstruction::JumpIf(arg, matches, Arg::Value(addr)) => {
                block.next = NextKind::Condition(Condition {
                    from_block: block.span.start,
                    jump_block: addr as usize,
                    follows_block: input.offset,
                    arg,
                    matches,
                });
                Ok((input, false))
            }
            ArgInstruction::Halt => {
                let input = Self::parse_halt_exit(block, input).unwrap_or(input);
                block.next = NextKind::Halt; // needs to be here since parse_halt_exit may set to
                                             // return kind.
                Ok((input, false))
            }
            ArgInstruction::Data(_) => unreachable!(),
            _ => Ok((input, true)),
        }
    }

    fn parse_halt_exit<'a>(block: &mut Block, input: Input<'a>) -> Result<Input<'a>, ParseError> {
        let halt_offset = input.offset - 1;
        let (input, op) = ArgInstruction::parse(input)?;
        let ArgInstruction::Goto(Arg::Value(goto_offset)) = op else {
            return Err(ParseError::NoMatch);
        };
        if goto_offset as usize != halt_offset {
            return Err(ParseError::NoMatch);
        }
        block.ops.push((halt_offset, op));
        let input = Self::parse_return(input, block).unwrap_or(input);
        Ok(input)
    }

    fn parse(input: Input, jump_targets: &HashSet<usize>) -> Result<Block, ParseError> {
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
                block.next = NextKind::Follows(next_input.offset);
                break;
            }
        }
        block.span.end = input.offset;
        Ok(block)
    }

    fn next_unconditional(&self) -> Option<usize> {
        match self.next {
            NextKind::Follows(addr) => Some(addr),
            NextKind::Goto(Arg::Value(addr)) => Some(addr as usize),
            _ => None,
        }
    }

    pub fn function_call_address(&self) -> Option<usize> {
        match self.next {
            NextKind::FunctionCall(
                FunctionCall {
                    function_addr: Arg::Value(addr),
                    ..
                },
                ..,
            ) => Some(addr as usize),
            _ => None,
        }
    }

    fn function_return_addr(&self) -> Option<usize> {
        match self.next {
            NextKind::FunctionCall(FunctionCall { return_block, .. }) => Some(return_block),
            _ => None,
        }
    }

    pub fn next_addresses(&self) -> Vec<usize> {
        match self.next {
            NextKind::Follows(addr) => vec![addr],
            NextKind::Goto(Arg::Value(addr)) => vec![addr as usize],
            NextKind::FunctionCall(FunctionCall { return_block, .. }) => vec![return_block],
            NextKind::Halt => vec![],
            NextKind::Unknown => vec![],
            NextKind::Return => vec![],
            NextKind::Condition(Condition {
                jump_block,
                follows_block,
                ..
            }) => vec![jump_block, follows_block],
            _ => unreachable!(),
        }
    }
}

impl Display for Block {
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
pub struct Graph {
    pub start: usize,
    pub stack_size: usize,
    pub blocks: HashMap<usize, Block>,
}

impl Graph {
    fn split_blocks(blocks: &mut HashMap<usize, Block>, jump_targets: &HashSet<usize>) {
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
            block.next = NextKind::Follows(jump_target);
            block.span.end = jump_target;
            blocks.insert(jump_target, new_block);
        }
    }

    fn parse_stack_size(input: Input) -> Result<usize, ParseError> {
        let (_, adjust_res) = ArgInstruction::parse(input)?;
        match adjust_res {
            ArgInstruction::AdjustRelativeBase(Arg::Value(r)) if r > 0 => {
                if input.offset == 0 {
                    Ok(0)
                } else {
                    Ok(r as usize)
                }
            }
            _ => Err(ParseError::NoMatch),
        }
    }

    pub fn build_from(prog: &[i128], start: usize) -> Result<Graph, ParseError> {
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
            stack.extend(block.next_addresses());
            jump_targets.extend(block.next_addresses());
            blocks.insert(offset, block);
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
        Ok(Graph {
            start,
            stack_size,
            blocks,
        })
    }

    fn scan(prog: &[i128]) -> Vec<Graph> {
        let mut graphs = vec![];
        let mut data = vec![];
        for start in 0..prog.len() {
            if graphs.iter().any(|g: &Graph| {
                g.blocks
                    .iter()
                    .any(|(_, block)| block.span.contains_address(start))
            }) {
                continue;
            }
            let Ok((_, ArgInstruction::AdjustRelativeBase(Arg::Value(r)))) =
                ArgInstruction::parse(make_input(prog, start))
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

    fn update_predecessor(blocks: &mut HashMap<usize, Block>) {
        let mut hm = HashMap::new();
        let mut add_pred = |dst, v| {
            hm.entry(dst).or_insert_with(Vec::new).push(v);
        };
        for (&src, block) in blocks.iter() {
            match block.next {
                NextKind::Follows(p) => add_pred(p, PredecessorKind::FollowsFrom(src)),
                NextKind::Goto(Arg::Value(p)) => {
                    add_pred(p as usize, PredecessorKind::GotoFrom(src))
                }
                NextKind::Goto(_) => unreachable!(),
                NextKind::FunctionCall(function_call) => add_pred(
                    function_call.return_block,
                    PredecessorKind::FunctionCallReturns(function_call),
                ),
                NextKind::Condition(condition) => {
                    add_pred(
                        condition.jump_block,
                        PredecessorKind::ConditionalJump(condition),
                    );
                    add_pred(
                        condition.follows_block,
                        PredecessorKind::ConditionalFollow(condition),
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

impl Display for Graph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (addr, block) in self.blocks.iter().sorted_by_key(|x| x.0) {
            writeln!(f, "addr {}, {}", addr, block)?;
        }
        Ok(())
    }
}

pub fn drive(prog: &[i128]) {
    let graphs = Graph::scan(prog);
    for graph in graphs {
        println!("----------");
        println!("Graph at {}", graph.start);
        let flow = data_flow_analysis::GraphDataFlow::build_for(&graph);
        for (_, block) in graph.blocks.iter().sorted_by_key(|x| x.0) {
            print!("{}", block);
            let bd = flow.block_defs.get(&block.span.start).unwrap();
            println!(
                " In={}\nOut={}\n LiveIn={}\nLiveOut={}",
                bd.defs_in.iter().map(|x| x.to_string()).join(", "),
                bd.defs_out.iter().map(|x| x.to_string()).join(", "),
                bd.live_in.iter().map(|x| x.to_string()).join(", "),
                bd.live_out.iter().map(|x| x.to_string()).join(", "),
            );
            println!();
        }
    }
}
