use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
};

use itertools::Itertools;

use crate::disasm::low_ir::Span;

use super::low_ir::{Arg, Input, Instruction, Op, OpArg, ParseError};

#[derive(Debug, Copy, Clone)]
enum NextKind {
    Follows(usize), // block immediately follows
    Goto(OpArg),    // unconditional jump
    FunctionCall { addr: Arg, return_addr: usize },
    Halt,
    Unknown,
    Return,
}

#[derive(Debug, Clone)]
struct Condition {
    arg: OpArg,    // value to be tested
    matches: bool, // is it truthy or falsy
    addr: usize,   // then jump to this addr
}

#[derive(Debug, Clone)]
struct Node {
    block: Vec<(usize, Instruction)>,
    next: NextKind,
    condition: Option<Condition>,
    span: Span, // includes the possible branching at the end.
}

impl Node {
    fn parse_function_call<'a>(input: Input<'a>, node: &mut Node) -> Result<Input<'a>, ParseError> {
        let assign_offset = input.offset;
        let (input, assign_op) = Instruction::parse(input)?;
        let Instruction::Assign(
            _,
            OpArg {
                kind: Arg::Value(return_addr),
                ..
            },
        ) = assign_op.kind
        else {
            return Err(ParseError::InvalidOpcode);
        };
        let return_addr = return_addr as usize;

        let goto_offset = input.offset;
        let (input, goto_op) = Instruction::parse(input)?;
        let Instruction::Goto(OpArg { kind: goto_arg, .. }) = goto_op.kind else {
            return Err(ParseError::InvalidOpcode);
        };
        if return_addr != input.offset {
            return Err(ParseError::InvalidOpcode);
        }
        node.next = NextKind::FunctionCall {
            addr: goto_arg,
            return_addr,
        };
        node.block.push((assign_offset, assign_op.kind));
        node.block.push((goto_offset, goto_op.kind));
        node.condition = None;
        Ok(input)
    }

    fn parse_return<'a>(input: Input<'a>, node: &mut Node) -> Result<Input<'a>, ParseError> {
        let adjust_offset = input.offset;
        let (input, adjust_op) = Instruction::parse(input)?;
        let Instruction::AdjustRelativeBase(OpArg {
            kind: Arg::Value(r),
            ..
        }) = adjust_op.kind
        else {
            return Err(ParseError::NoMatch);
        };
        if r >= 0 {
            return Err(ParseError::NoMatch);
        }
        let goto_offset = input.offset;
        let (input, goto_op) = Instruction::parse(input)?;
        if let Instruction::Goto(OpArg {
            kind: Arg::RelativeMem(0),
            ..
        }) = goto_op.kind
        {
            node.next = NextKind::Return;
            node.condition = None;
        } else {
            return Err(ParseError::NoMatch);
        }
        node.block.push((adjust_offset, adjust_op.kind));
        node.block.push((goto_offset, goto_op.kind));
        Ok(input)
    }

    // continues as long as it returns Ok(true), Ok(false) is successful completion.
    fn parse_single<'a>(
        input: Input<'a>,
        node: &mut Node,
    ) -> Result<(Input<'a>, bool), ParseError> {
        if let Ok(input) =
            Self::parse_function_call(input, node).or_else(|_| Self::parse_return(input, node))
        {
            return Ok((input, false));
        }
        let offset = input.offset;
        let (input, op) = Instruction::parse(input)?;
        node.block.push((offset, op.kind.clone()));

        match op.kind {
            Instruction::Goto(op_arg) => {
                node.next = NextKind::Goto(op_arg);
                Ok((input, false))
            }
            Instruction::JumpIf(
                arg,
                matches,
                OpArg {
                    kind: Arg::Value(addr),
                    ..
                },
            ) => {
                node.next = NextKind::Follows(input.offset);
                node.condition = Some(Condition {
                    arg,
                    matches,
                    addr: addr as usize,
                });
                Ok((input, false))
            }
            Instruction::Halt => {
                let input = Self::parse_halt_exit(node, input).unwrap_or(input);
                node.next = NextKind::Halt; // needs to be here since parse_halt_exit may set to
                                            // return kind.
                Ok((input, false))
            }
            Instruction::Data(_) => unreachable!(),
            _ => Ok((input, true)),
        }
    }

    fn parse_halt_exit<'a>(node: &mut Node, input: Input<'a>) -> Result<Input<'a>, ParseError> {
        let halt_offset = input.offset - 1;
        let (input, op) = Instruction::parse(input)?;
        let Instruction::Goto(OpArg {
            kind: Arg::Value(goto_offset),
            ..
        }) = op.kind
        else {
            return Err(ParseError::NoMatch);
        };
        if goto_offset as usize != halt_offset {
            return Err(ParseError::NoMatch);
        }
        node.block.push((halt_offset, op.kind));
        let input = Self::parse_return(input, node).unwrap_or(input);
        Ok(input)
    }

    fn parse(input: Input, jump_targets: &HashSet<usize>) -> Result<Node, ParseError> {
        let mut node = Node {
            block: vec![],
            next: NextKind::Unknown,
            condition: None,
            span: Span::new(input.offset, input.offset),
        };
        let mut input = input;
        let mut cont = true;
        while cont {
            let (next_input, next_cont) = Self::parse_single(input, &mut node)?;
            input = next_input;
            cont = next_cont;
            if cont && jump_targets.contains(&next_input.offset) {
                node.next = NextKind::Follows(next_input.offset);
                break;
            }
        }
        node.span.end = input.offset;
        Ok(node)
    }

    fn next_addr(&self) -> Option<usize> {
        match self.next {
            NextKind::Follows(addr) => Some(addr),
            NextKind::Goto(OpArg {
                kind: Arg::Value(addr),
                ..
            }) => Some(addr as usize),
            _ => None,
        }
    }

    fn function_call_address(&self) -> Option<usize> {
        match self.next {
            NextKind::FunctionCall {
                addr: Arg::Value(addr),
                ..
            } => Some(addr as usize),
            _ => None,
        }
    }

    fn function_return_addr(&self) -> Option<usize> {
        match self.next {
            NextKind::FunctionCall { return_addr, .. } => Some(return_addr),
            _ => None,
        }
    }

    fn cond_addr(&self) -> Option<usize> {
        match self.condition {
            Some(Condition { addr, .. }) => Some(addr),
            _ => None,
        }
    }
}

impl Display for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Block {}: ", self.span)?;
        for (addr, op) in &self.block {
            writeln!(f, "{:8}  {}", addr, op)?;
        }
        write!(f, "Next block: ")?;
        match &self.next {
            NextKind::Follows(addr) => writeln!(f, "follows {}", addr)?,
            NextKind::Goto(arg) => writeln!(f, "goto {}", arg.kind)?,
            NextKind::FunctionCall { addr, return_addr } => {
                writeln!(f, "function call {} return {}", addr, return_addr)?
            }
            NextKind::Halt => writeln!(f, "halt")?,
            NextKind::Unknown => writeln!(f, "unknown")?,
            NextKind::Return => writeln!(f, "return")?,
        }
        if let Some(cond) = &self.condition {
            writeln!(
                f,
                "Condition: if {} is {} goto {}",
                cond.arg.kind, cond.matches, cond.addr
            )?;
        }
        Ok(())
    }
}

struct Graph {
    start: usize,
    stack_size: usize,
    nodes: HashMap<usize, Node>,
}

impl Graph {
    fn split_nodes(nodes: &mut HashMap<usize, Node>, jump_targets: &HashSet<usize>) {
        let mut nodes_to_split = vec![];
        for (addr, node) in nodes.iter() {
            for jump_target in jump_targets.iter().sorted().rev() {
                if *jump_target != node.span.start && node.span.contains_address(*jump_target) {
                    nodes_to_split.push((*addr, *jump_target));
                }
            }
        }

        for (addr, jump_target) in nodes_to_split {
            let node = nodes.get_mut(&addr).unwrap();
            let index = node
                .block
                .iter()
                .position(|(addr, _)| *addr == jump_target)
                .unwrap();
            let block = node.block.split_off(index);

            let new_node = Node {
                block,
                next: node.next,
                condition: node.condition.take(),
                span: node.span.with_start(jump_target),
            };
            node.next = NextKind::Follows(jump_target);
            node.span.end = jump_target;
            nodes.insert(jump_target, new_node);
        }
    }

    fn parse_stack_size(input: Input) -> Result<usize, ParseError> {
        let (_, adjust_res) = Instruction::parse(input)?;
        match adjust_res.kind {
            Instruction::AdjustRelativeBase(OpArg {
                kind: Arg::Value(r),
                ..
            }) if r > 0 => {
                if adjust_res.span.start == 0 {
                    Ok(0)
                } else {
                    Ok(r as usize)
                }
            }
            _ => Err(ParseError::NoMatch),
        }
    }

    pub fn build_from(prog: &[i128], start: usize) -> Result<Graph, ParseError> {
        let mut nodes = HashMap::new();
        let mut seen = HashSet::new();
        let mut stack = Vec::new();
        let mut jump_targets = HashSet::new();
        let mut inbounds: HashMap<usize, Vec<usize>> = HashMap::new();
        stack.push(start);
        let stack_size = Self::parse_stack_size(make_input(prog, start))?;
        while let Some(offset) = stack.pop() {
            if seen.contains(&offset) {
                continue;
            }
            seen.insert(offset);
            let input = make_input(prog, offset);
            let node = Node::parse(input, &jump_targets)?;
            if let Some(cond_addr) = node.cond_addr() {
                stack.push(cond_addr);
                jump_targets.insert(cond_addr);
                inbounds.entry(cond_addr).or_default().push(offset);
            }
            if let Some(return_addr) = node.function_return_addr() {
                stack.push(return_addr);
            }
            if let Some(next) = node.next_addr() {
                stack.push(next);

                jump_targets.insert(next);
            }
            nodes.insert(offset, node);
        }
        Self::split_nodes(&mut nodes, &jump_targets);
        for (x, y) in nodes.iter().sorted_by_key(|x| x.0).tuple_windows() {
            assert!(x.1.span.end <= y.1.span.start);
        }
        Ok(Graph {
            start,
            stack_size,
            nodes,
        })
    }

    fn scan(prog: &[i128]) {
        let mut graphs = vec![];
        let mut data = vec![];
        for start in 0..prog.len() {
            if graphs.iter().any(|g: &Graph| {
                g.nodes
                    .iter()
                    .any(|(addr, node)| node.span.contains_address(start))
            }) {
                continue;
            }
            let Ok((
                _,
                Op {
                    kind:
                        Instruction::AdjustRelativeBase(OpArg {
                            kind: Arg::Value(r),
                            ..
                        }),
                    ..
                },
            )) = Instruction::parse(make_input(prog, start))
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
    }
}

fn make_input(prog: &[i128], offset: usize) -> Input<'_> {
    let input = Input::new(offset, &prog[offset..]);
    input
}

impl Display for Graph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (addr, node) in self.nodes.iter().sorted_by_key(|x| x.0) {
            writeln!(f, "addr {}, {}", addr, node)?;
        }
        Ok(())
    }
}

pub fn drive(prog: &[i128]) {
    Graph::scan(prog);
}
