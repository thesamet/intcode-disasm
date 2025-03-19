use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display, Formatter};

use crate::disasm::low_ir::*;
use crate::line;
use itertools::Itertools;
use log::trace;
use pathfinding::prelude::dfs;

use super::code_printer::{CodePrinter, CodeWriter};
use super::mid_flow::{self, FlowGraph, LoopId};
use super::mid_flow::{FlowHigh, FlowNode};
use super::mid_transform::{
    find_dynamic_function_calls, find_static_function_calls, rename_vars_on_stack,
};

#[derive(Debug, Clone)]
pub enum ArgType {
    Value,
    FunctionPointer { args: Vec<ArgType> },
}

#[derive(Debug, Clone)]
pub struct Argument {
    pub name: String,
    pub typ: ArgType,
}

#[derive(Debug, Clone)]
pub struct FunctionRange {
    pub start: usize,
    pub end: usize,
    pub stack_size: usize,
    pub args: Vec<Argument>,
    pub static_calls: Vec<usize>,
    pub return_point: Option<usize>,
    pub block: MidIR,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Expr {
    Input(),
    Var(String), // To be deleted
    InArg(usize),
    OutArg(usize),
    MemRef(Box<Expr>),
    Literal(i128),
    Add(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    NotEqual(Box<Expr>, Box<Expr>),
    Equal(Box<Expr>, Box<Expr>),
    LessThan(Box<Expr>, Box<Expr>),
    GreaterOrEqual(Box<Expr>, Box<Expr>),
    Negate(Box<Expr>),
    If(Box<Expr>, Box<Expr>, Box<Expr>),
    FunctionCall(Box<Expr>, Vec<Expr>),
    Ignore,
}

impl Expr {
    pub fn negate(&self) -> Expr {
        match self {
            Expr::NotEqual(a, b) => Expr::Equal(Box::new(*a.clone()), Box::new(*b.clone())),
            Expr::Equal(a, b) => Expr::NotEqual(Box::new(*a.clone()), Box::new(*b.clone())),
            Expr::LessThan(a, b) => {
                Expr::GreaterOrEqual(Box::new(*a.clone()), Box::new(*b.clone()))
            }
            Expr::GreaterOrEqual(a, b) => {
                Expr::LessThan(Box::new(*a.clone()), Box::new(*b.clone()))
            }
            Expr::Negate(e) => *e.clone(),
            _ => Expr::Negate(Box::new(self.clone())),
        }
    }

    pub fn literal(&self) -> Option<i128> {
        match self {
            Expr::Literal(x) => Some(*x),
            _ => None,
        }
    }

    pub fn in_arg(&self) -> Option<usize> {
        match self {
            Expr::InArg(x) => Some(*x),
            _ => None,
        }
    }
}

impl Display for Expr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Expr::Input() => write!(f, "input()"),
            Expr::Var(x) => write!(f, "{}", x),
            Expr::Literal(x) => write!(f, "{}", x),
            Expr::Add(a, b) => write!(f, "({} + {})", a, b),
            Expr::Mul(a, b) => write!(f, "({} * {})", a, b),
            Expr::InArg(x) => write!(f, "i{}", x),
            Expr::OutArg(x) => write!(f, "o{}", x),
            Expr::MemRef(x) => write!(f, "*({})", x),
            Expr::NotEqual(a, b) => write!(f, "{} != {}", a, b),
            Expr::Equal(a, b) => write!(f, "{} == {}", a, b),
            Expr::LessThan(a, b) => write!(f, "{} < {}", a, b),
            Expr::GreaterOrEqual(a, b) => write!(f, "{} >= {}", a, b),
            Expr::Negate(e) => write!(f, "!{}", e),
            Expr::FunctionCall(addr, args) => match addr.as_ref() {
                Expr::Literal(addr) => write!(f, "f{}({})", addr, args.iter().join(", ")),
                e => write!(f, "{}({})", e, args.iter().join(", ")),
            },
            Expr::Ignore => write!(f, "_"),
            Expr::If(cond, then, els) => {
                write!(f, "if ({}) {{ {} }} else {{ {} }}", cond, then, els)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum MidIR {
    Block(Vec<MidIR>),
    Assign(Expr, Expr),
    If(Expr, Box<MidIR>, Option<Box<MidIR>>),
    While(LoopId, Option<Box<MidIR>>, Expr, Box<MidIR>),
    DoWhile(LoopId, Box<MidIR>, Expr),
    Loop(LoopId, Box<MidIR>),
    Output(Expr),
    Break(LoopId),
    Continue(LoopId),
    Unknown(usize, Instruction),
    Return(),
}

impl MidIR {
    fn print<F>(&self, f: &mut F)
    where
        F: CodeWriter,
    {
        match self {
            MidIR::Assign(a, b) => {
                if matches!(a, Expr::Ignore) {
                    line!(f, "{};", b);
                } else {
                    line!(f, "{} = {};", a, b);
                }
            }
            MidIR::If(cond, then, els) => {
                line!(f, "if ({}) {{", cond);
                then.print(&mut f.indented());
                if els.is_none() {
                    line!(f, "}}");
                } else {
                    line!(f, "}} else {{");
                    if let Some(i) = els {
                        i.print(&mut f.indented());
                    }
                    line!(f, "}}");
                }
            }
            MidIR::Output(x) => {
                line!(f, "output({});", x);
            }
            MidIR::Unknown(offset, i) => {
                line!(f, "// {}: {}", offset, i);
            }
            MidIR::Return() => {
                line!(f, "return");
            }
            MidIR::Block(code) => {
                for i in code {
                    i.print(f);
                }
            }
            MidIR::Loop(id, body) => {
                line!(f, "'{}: while (true) {{", id.0);
                body.print(&mut f.indented());
                line!(f, "}}  // '{}", id.0);
            }
            MidIR::While(id, header, cond, body) => {
                {
                    let mut sl = f.single_line_mode();
                    line!(sl, "'{}: while (", id.0);
                    if let Some(header) = header {
                        header.print(&mut sl)
                    }
                    line!(sl, "{}) {{", cond);
                }
                body.print(&mut f.indented());
                line!(f, "}}  // '{}", id.0);
            }
            MidIR::DoWhile(id, body, cond) => {
                line!(f, "'{}: do {{", id.0);
                body.print(&mut f.indented());
                line!(f, "}} while ({})", cond);
            }
            MidIR::Break(id) => {
                line!(f, "break '{};", id.0);
            }
            MidIR::Continue(id) => {
                line!(f, "continue '{};", id.0);
            }
        }
    }
}

pub struct Program {
    pub inst: Vec<i128>,
    pub functions: HashMap<usize, FunctionRange>,
}

impl Program {}

fn discover_function_pointers(functions: &[FunctionRange]) -> Vec<(usize, usize)> {
    let mut new_funcs = vec![];
    let mut arg_count = HashMap::new();
    for f in functions {
        // func f calls functions dynamically using. The first usize
        // represents the 1-based arg_index of f.
        let dynamic_calls = find_dynamic_function_calls(&f.block);
        if dynamic_calls.is_empty() {
            continue;
        }
        for g in functions {
            for (fc, f_args) in find_static_function_calls(&g.block) {
                if fc != f.start {
                    continue;
                }
                for (arg_index, dyn_args) in &dynamic_calls {
                    let Some(arg_index) = arg_index.in_arg() else {
                        continue;
                    };

                    // g calls f(*f_args) which calls f_args[arg_index-1](dyn_args) function dynamically.
                    if arg_index > f_args.len() {
                        println!(
                            "Problem with function {} called from f{} args={:?} [arg={}]",
                            fc, g.start, f_args, arg_index
                        );
                    } else {
                        let Expr::Literal(addr) = f_args[arg_index - 1] else {
                            panic!("Expected literal argument");
                        };
                        if let Some(existing_arg_count) = arg_count.get(&addr) {
                            assert_eq!(
                                *existing_arg_count,
                                dyn_args.len(),
                                "Mismatch in argument count for function at {}",
                                addr
                            );
                        } else {
                            trace!("Dyn function at {} has {} arguments", addr, dyn_args.len());
                            arg_count.insert(addr, dyn_args.len());
                        }
                        new_funcs.push((addr as usize, dyn_args.len()));
                    }
                }
            }
        }
    }
    new_funcs.iter().unique().copied().collect_vec()
}

fn discover_functions(prog: &[i128]) -> Program {
    let mut program = Program {
        functions: HashMap::new(),
        inst: prog.to_vec(),
    };
    let mut outer_stack = vec![0];
    let mut seen: HashSet<usize> = HashSet::new();
    let mut arg_counts = HashMap::new();

    while let Some(init) = outer_stack.pop() {
        dfs(
            init,
            |offset| {
                trace!("Discovering function at {}", offset);
                let input = Input::new(*offset, &program.inst[*offset..]);
                let fr = parse_function(input).unwrap();
                program.functions.insert(fr.start, fr.clone());
                let function_calls = find_static_function_calls(&fr.block);
                for (addr, args) in &function_calls {
                    if let Some(arg_count) = arg_counts.get(addr) {
                        assert!(
                            *arg_count == args.len(),
                            "Mismatch in argument count for function at {}",
                            addr
                        );
                    } else {
                        arg_counts.insert(*addr, args.len());
                    }
                }
                let fcs = function_calls
                    .iter()
                    .map(|fc| fc.0)
                    .filter(|c| !seen.contains(c))
                    .unique()
                    .collect_vec();
                seen.extend(&fcs);
                fcs
            },
            |_| false,
        );
        for (func_pointer, arg_count) in
            discover_function_pointers(&program.functions.values().cloned().collect_vec())
        {
            if seen.contains(&func_pointer) {
                continue;
            }
            if let Some(existing) = arg_counts.get(&func_pointer) {
                assert!(
                    arg_count == *existing,
                    "Mismatch in argument count for function at {}",
                    func_pointer
                );
            } else {
                arg_counts.insert(func_pointer, arg_count);
            }
            seen.insert(func_pointer);
            println!("Discovered function at {}", func_pointer);
            outer_stack.push(func_pointer);
        }
        println!("----")
    }
    for (addr, arg_count) in arg_counts {
        program.functions.get_mut(&addr).unwrap().args = (1..=arg_count)
            .map(|i| Argument {
                name: format!("i{}", i),
                typ: ArgType::Value,
            })
            .collect();
        println!("Function at {} has {} arguments", addr, arg_count);
    }
    for fr in program.functions.values_mut() {
        rename_vars_on_stack(fr);
    }

    program
}

pub fn to_mid_ir(prog: &[i128]) {
    // program.functions.push(f);
    let program = discover_functions(prog);

    let mut printer = CodePrinter::new();
    for (_, f) in program.functions.iter().sorted_by_key(|f| f.1.start) {
        line!(
            &mut printer,
            "fn f{}({}) {{",
            f.start,
            f.args.iter().map(|x| &x.name).join(", ")
        );
        let mut indent = printer.indented();
        f.block.print(&mut indent);
        line!(&mut printer, "}}");
        line!(&mut printer, "");
    }
    println!("{}", printer.result());
}

fn parse_return(input: Input) -> Result<(Input, MidIR), ParseError> {
    let (input, adjust) = Instruction::parse(input)?;
    match adjust.kind {
        Instruction::AdjustRelativeBase(OpArg {
            kind: Arg::Value(r),
            ..
        }) if r < 0 => {
            let (input, goto) = Instruction::parse(input)?;
            match goto.kind {
                Instruction::Goto(OpArg {
                    kind: Arg::RelativeMem(0),
                    ..
                }) => Ok((input, MidIR::Return())),
                _ => Err(ParseError::NoMatch),
            }
        }
        _ => Err(ParseError::NoMatch),
    }
}

#[derive(Debug, Clone)]
struct FlowAnalysis {
    span: Span,
    halts: Vec<usize>,
    graph: FlowGraph,
}

struct NonBranchingTracker {
    current: Option<Vec<(usize, usize, MidIR)>>,
    non_branching: Vec<Vec<(usize, usize, MidIR)>>,
    jumps: HashSet<usize>,
}

impl NonBranchingTracker {
    fn new() -> Self {
        Self {
            current: None,
            non_branching: vec![],
            jumps: HashSet::new(),
        }
    }

    fn track(&mut self, start: usize, end: usize, op: MidIR) {
        if self.jumps.contains(&start) {
            self.end();
        }

        if self.current.is_none() {
            self.current = Some(vec![]);
        };
        if let Some(current) = self.current.as_mut() {
            assert!(current
                .iter()
                .last()
                .map(|x| x.1)
                .is_none_or(|e| e == start));
            current.push((start, end, op));
        }
    }

    fn end(&mut self) {
        if let Some(current) = self.current.take() {
            if !current.is_empty() {
                self.non_branching.push(current);
            }
        }
    }

    fn break_at(&mut self, addr: usize) {
        self.end();
        let mut res = vec![];
        for block in self.non_branching.iter_mut() {
            if let Some(end_pos) = block.iter().position(|(s, _, _)| *s == addr) {
                let next = block.split_off(end_pos);
                if !block.is_empty() {
                    res.push(block.clone());
                }
                if !next.is_empty() {
                    res.push(next);
                }
            } else {
                res.push(block.clone());
            }
        }
        self.non_branching = res;
        self.jumps.insert(addr);
    }
}

struct FunctionParser {
    stack_size: usize,
}

impl FunctionParser {
    fn parse_simple_ternary_assign_tmp<'a>(
        &self,
        input: Input<'a>,
    ) -> Result<(Input<'a>, MidIR), ParseError> {
        let (
            input,
            Op {
                kind:
                    Instruction::JumpIf(
                        value,
                        equal_to,
                        OpArg {
                            kind: Arg::Value(addr1),
                            ..
                        },
                    ),
                ..
            },
        ) = Instruction::parse(input)?
        else {
            return Err(ParseError::NoMatch);
        }; // if jump
        let mut condition = self.from_arg(&value);
        if equal_to {
            condition = condition.negate();
        }
        let (input, op) = Instruction::parse(input)?;
        let Some(MidIR::Assign(Expr::OutArg(v1), val1)) = self.instruction_to_midir(op.kind) else {
            return Err(ParseError::NoMatch);
        };

        let (
            input,
            Op {
                kind:
                    Instruction::Goto(OpArg {
                        kind: Arg::Value(addr2),
                        ..
                    }),
                ..
            },
        ) = Instruction::parse(input)?
        else {
            return Err(ParseError::NoMatch);
        };

        if input.offset != addr1 as usize {
            return Err(ParseError::NoMatch);
        }

        let (input, op) = Instruction::parse(input)?;
        let Some(MidIR::Assign(Expr::OutArg(v2), val2)) = self.instruction_to_midir(op.kind) else {
            return Err(ParseError::NoMatch);
        };
        if input.offset != addr2 as usize {
            return Err(ParseError::NoMatch);
        }
        if v1 != v2 {
            return Err(ParseError::NoMatch);
        }
        Ok((
            input,
            MidIR::Assign(
                Expr::OutArg(v1),
                Expr::If(Box::new(condition), Box::new(val1), Box::new(val2)),
            ),
        ))
    }

    fn parse_simple_assign<'a>(&self, input: Input<'a>) -> Result<(Input<'a>, MidIR), ParseError> {
        let (input, op) = Instruction::parse(input)?;
        let Some(midir) = self.instruction_to_midir(op.kind) else {
            return Err(ParseError::NoMatch);
        };
        Ok((input, midir))
    }

    fn parse_function_call<'a>(&self, input: Input<'a>) -> Result<(Input<'a>, MidIR), ParseError> {
        let mut input = input;
        let mut args = vec![];
        let mut last_arg_offset = 0;
        let return_addr = loop {
            let (next_input, midir) = self
                .parse_simple_assign(input)
                .or_else(|_| self.parse_simple_ternary_assign_tmp(input))?;
            input = next_input;
            let MidIR::Assign(Expr::OutArg(v), val) = midir else {
                return Err(ParseError::NoMatch);
            };
            if v == 0 {
                let Expr::Literal(addr) = val else {
                    return Err(ParseError::NoMatch);
                };
                break addr as usize;
            }
            if v != last_arg_offset + 1 {
                return Err(ParseError::NoMatch);
            }
            args.push(val);
            last_arg_offset = v;
        };

        let (input, goto) = Instruction::parse(input)?;
        if return_addr != input.offset {
            return Err(ParseError::NoMatch);
        }
        trace!("{:?}", goto.kind);
        match goto.kind {
            Instruction::Goto(o) => Ok((
                input,
                MidIR::Assign(
                    Expr::Ignore,
                    Expr::FunctionCall(Box::new(self.from_arg(&o)), args),
                ),
            )),

            _ => Err(ParseError::NoMatch),
        }
    }

    fn from_arg(&self, arg: &OpArg) -> Expr {
        match &arg.kind {
            Arg::Value(x) => Expr::Literal(*x),
            Arg::RelativeMem(x) if *x >= 0 => Expr::OutArg(*x as usize),
            Arg::RelativeMem(x) if *x < 0 => {
                Expr::InArg(self.stack_size.checked_add_signed(*x as isize).unwrap())
            }
            Arg::Mem(x) => Expr::Var(format!("data[{}]", *x)),
            Arg::Pointer(x) => Expr::Var(x.clone()),
            _ => panic!("Unexpected argument {:?}", arg),
        }
    }

    fn analyze_flow(&self, input: Input) -> FlowAnalysis {
        let mut input = input;
        let start_offset = input.offset;
        let mut max_addr_seen = start_offset;
        let mut halts = Vec::new();
        let mut nodes = vec![];
        let mut non_branching_tracker = NonBranchingTracker::new();
        let mut jumps = vec![];
        loop {
            let offset = input.offset;
            trace!("offset={} max_addr_seen={}", offset, max_addr_seen);
            if let Ok((new_input, fc)) = self.parse_function_call(input) {
                non_branching_tracker.track(input.offset, new_input.offset, fc);
                if new_input.offset >= max_addr_seen {
                    max_addr_seen = new_input.offset;
                }
                input = new_input;
            } else if let Ok((new_input, _)) = parse_return(input) {
                trace!("Return at {}", offset);
                non_branching_tracker.end();
                nodes.push(FlowNode::new_return(Span::new(offset, new_input.offset)));
                input = new_input;
                if new_input.offset >= max_addr_seen {
                    max_addr_seen = input.offset;
                    break;
                }
            } else if let Ok((new_input, op)) = Instruction::parse(input) {
                match op.kind {
                    Instruction::Goto(OpArg {
                        kind: Arg::Value(addr),
                        ..
                    }) => {
                        let addr = addr as usize;
                        jumps.push(addr);
                        non_branching_tracker.end();
                        non_branching_tracker.break_at(addr);
                        nodes.push(FlowNode::goto(op.span, addr));
                        // back jump, code beyond max_addr_seen is not reachable.
                        if max_addr_seen < addr.max(input.offset) {
                            max_addr_seen = addr.max(input.offset);
                        }
                        trace!(
                            "{}: max_addr_seen={} addr={}",
                            input.offset,
                            max_addr_seen,
                            addr
                        );
                        if addr <= input.offset && max_addr_seen == input.offset {
                            trace!("Function end detected at instruction at {}", input.offset);
                            break;
                        }
                    }
                    Instruction::Goto(_) => {
                        panic!("Unexpected goto at {} {}", offset, op.kind);
                    }
                    Instruction::JumpIf(
                        value,
                        equal_to,
                        OpArg {
                            kind: Arg::Value(addr),
                            ..
                        },
                    ) => {
                        let addr = addr as usize;
                        non_branching_tracker.end();
                        non_branching_tracker.break_at(addr);
                        jumps.push(addr);
                        let condition = {
                            let mut t = self.from_arg(&value);
                            if !equal_to {
                                t = t.negate();
                            }
                            t
                        };
                        nodes.push(FlowNode::jump_if(op.span, condition, addr));
                        if max_addr_seen < addr.max(new_input.offset) {
                            max_addr_seen = addr.max(new_input.offset);
                        }
                    }
                    Instruction::JumpIf(_, _, _) => {
                        panic!("Unexpected jumpif at {} {}", offset, op.kind);
                    }
                    Instruction::Halt => {
                        non_branching_tracker.end();
                        halts.push(offset);
                    }
                    _ => {
                        non_branching_tracker.track(
                            input.offset,
                            new_input.offset,
                            self.instruction_to_midir(op.kind).unwrap(),
                        );
                    }
                }
                if max_addr_seen < new_input.offset {
                    max_addr_seen = new_input.offset;
                }
                input = new_input;
            } else {
                panic!("Could not parse instruction at {}", offset);
            }
        }
        non_branching_tracker.end();
        trace!(
            "Non-branching tracker: {:?}",
            non_branching_tracker.non_branching
        );
        for v in non_branching_tracker.non_branching {
            let start = v.first().unwrap().0;
            let end = v.last().unwrap().1;
            let ops = v.into_iter().map(|(_, _, op)| op).collect();
            nodes.push(FlowNode::non_branching(Span::new(start, end), ops));
        }

        let graph = FlowGraph::build_from(&nodes);

        FlowAnalysis {
            span: Span {
                start: start_offset,
                end: max_addr_seen,
            },
            graph,
            halts,
        }
    }

    fn instruction_to_midir(&self, kind: Instruction) -> Option<MidIR> {
        Some(match kind {
            Instruction::Assign(arg1, arg2) => {
                MidIR::Assign(self.from_arg(&arg1), self.from_arg(&arg2))
            }
            Instruction::Add(a, b, c) => MidIR::Assign(
                self.from_arg(&c),
                Expr::Add(Box::new(self.from_arg(&a)), Box::new(self.from_arg(&b))),
            ),
            Instruction::Mul(a, b, c) => MidIR::Assign(
                self.from_arg(&c),
                Expr::Mul(Box::new(self.from_arg(&a)), Box::new(self.from_arg(&b))),
            ),
            Instruction::Output(a) => MidIR::Output(self.from_arg(&a)),
            Instruction::Input(a) => MidIR::Assign(self.from_arg(&a), Expr::Input()),
            Instruction::Equals(a, b, c) => MidIR::Assign(
                self.from_arg(&c),
                Expr::Equal(Box::new(self.from_arg(&a)), Box::new(self.from_arg(&b))),
            ),
            Instruction::LessThan(a, b, c) => MidIR::Assign(
                self.from_arg(&c),
                Expr::LessThan(Box::new(self.from_arg(&a)), Box::new(self.from_arg(&b))),
            ),
            _ => return None,
        })
    }
}

fn parse_function(input: Input) -> Result<FunctionRange, ParseError> {
    let (input, adjust_res) = Instruction::parse(input)?;
    let stack_size = match adjust_res.kind {
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
    }?;
    let parser = FunctionParser { stack_size };
    let flow = parser.analyze_flow(input);
    let flow_high = mid_flow::parse_flow(&flow.graph, flow.span).unwrap();
    let mid_ir = flow_to_mid_ir(&flow_high);

    Ok(FunctionRange {
        start: adjust_res.span.start,
        end: flow.span.end,
        stack_size,
        args: vec![],
        static_calls: vec![],
        return_point: None,
        block: mid_ir,
    })
}

pub fn flow_to_mid_ir(flow: &FlowHigh) -> MidIR {
    match flow {
        FlowHigh::NonBranching { instructions, .. } => {
            assert!(!instructions.is_empty());
            if instructions.len() == 1 {
                instructions[0].clone()
            } else {
                MidIR::Block(instructions.clone())
            }
        }
        FlowHigh::Composite(flows) => {
            let blocks: Vec<MidIR> = flows.iter().map(flow_to_mid_ir).collect();
            MidIR::Block(blocks)
        }
        FlowHigh::While {
            id,
            header,
            expr,
            body,
            ..
        } => {
            // Convert while loops to infinite loops for now
            // In a real implementation, we'd need the condition from jump_if_span
            MidIR::While(
                *id,
                header.as_ref().map(|h| Box::new(flow_to_mid_ir(&h))),
                expr.clone(),
                Box::new(flow_to_mid_ir(body)),
            )
        }
        FlowHigh::DoWhile { id, expr, body } => {
            // Convert while loops to infinite loops for now
            // In a real implementation, we'd need the condition from jump_if_span
            MidIR::DoWhile(*id, Box::new(flow_to_mid_ir(body)), expr.clone())
        }
        FlowHigh::Loop { id, body } => MidIR::Loop(*id, Box::new(flow_to_mid_ir(body))),
        FlowHigh::If { expr, then, .. } => {
            // Use a placeholder condition for now
            MidIR::If(expr.clone(), Box::new(flow_to_mid_ir(then)), None)
        }
        FlowHigh::IfElse {
            expr, then, els, ..
        } => {
            // Use a placeholder condition for now
            MidIR::If(
                expr.clone(),
                Box::new(flow_to_mid_ir(then)),
                Some(Box::new(flow_to_mid_ir(els))),
            )
        }
        FlowHigh::Return => MidIR::Return(),
        FlowHigh::Break(id) => MidIR::Break(*id),
        FlowHigh::Continue(id) => MidIR::Continue(*id),
    }
}
