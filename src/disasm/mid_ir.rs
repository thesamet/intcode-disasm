use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};

use crate::disasm::low_ir::*;
use crate::line;
use itertools::Itertools;
use log::trace;
use pathfinding::prelude::dfs;

use super::code_printer::{CodePrinter, CodeWriter};
use super::mid_flow::{self, FlowGraph, LoopId};
use super::mid_flow::{FlowHigh, FlowNode};

#[derive(Debug, Clone)]
enum ArgType {
    Value,
    FunctionPointer { args: Vec<ArgType> },
}

#[derive(Debug, Clone)]
struct Argument {
    name: String,
    typ: ArgType,
}

#[derive(Debug, Clone)]
struct FunctionRange {
    start: usize,
    end: usize,
    args: Vec<Argument>,
    static_calls: Vec<usize>,
    return_point: Option<usize>,
    block: MidIR,
}

fn parse_function_call(input: Input) -> Result<(Input, MidIR), ParseError> {
    let (input, assign_op) = Instruction::parse(input)?;
    let Instruction::Assign(
        OpArg {
            kind: Arg::RelativeMem(0),
            ..
        },
        OpArg {
            kind: Arg::Value(return_addr),
            ..
        },
    ) = assign_op.kind
    else {
        return Err(ParseError::NoMatch);
    };
    let (input, goto) = Instruction::parse(input)?;
    if return_addr as usize != input.offset {
        return Err(ParseError::NoMatch);
    }
    trace!("{:?}", goto.kind);
    match goto.kind {
        Instruction::Goto(OpArg {
            kind: Arg::Value(addr),
            ..
        }) => Ok((input, MidIR::FunctionCall(addr as usize, vec![]))),
        Instruction::Goto(OpArg {
            kind: Arg::RelativeMem(offset),
            ..
        }) if offset < 0 => Ok((
            input,
            MidIR::DynamicFunctionCall(Expr::InArg((-offset) as usize), vec![]),
        )),
        Instruction::Goto(OpArg {
            kind: Arg::Pointer(p),
            ..
        }) => Ok((input, MidIR::DynamicFunctionCall(Expr::Var(p), vec![]))),

        _ => Err(ParseError::NoMatch),
    }
}

#[derive(Clone, Debug, PartialEq)]
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
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum MidIR {
    Block(Vec<MidIR>),
    Assign(Expr, Expr),
    FunctionCall(usize, Vec<Expr>),
    DynamicFunctionCall(Expr, Vec<Expr>),
    If(Expr, Box<MidIR>, Option<Box<MidIR>>),
    While(LoopId, Option<Box<MidIR>>, Expr, Box<MidIR>),
    DoWhile(LoopId, Box<MidIR>, Expr),
    Loop(LoopId, Box<MidIR>),
    Output(i128),
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
                line!(f, "{} = {};", a, b);
            }
            MidIR::FunctionCall(addr, args) => {
                line!(f, "f{}({});", addr, args.iter().join(", "));
            }
            MidIR::DynamicFunctionCall(fcall, args) => {
                line!(f, "{}({});", fcall, args.iter().join(", "));
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
                line!(f, "return;");
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
                line!(f, "'{}: while (", id.0);
                if let Some(header) = header {
                    header.print(&mut f.indented());
                }
                line!(f.indented(), "{}) {{", cond);
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

struct Program {
    inst: Vec<i128>,
    functions: Vec<FunctionRange>,
}

impl Program {}

fn children_of<'a>(mid_ir: &'a MidIR) -> Box<dyn Iterator<Item = &'a MidIR> + 'a> {
    match mid_ir {
        MidIR::Block(mid_irs) => Box::new(mid_irs.iter().flat_map(|x| children_of(x))),
        MidIR::Loop(_, mid_ir) => children_of(mid_ir),
        MidIR::If(_, t, f) => match f {
            Some(f) => Box::new(children_of(t).chain(children_of(f))),
            _ => Box::new(children_of(t)),
        },
        x => Box::new(std::iter::once(x)),
    }
}

fn scan_ops<'a>(fp: &'a FunctionRange) -> Box<dyn Iterator<Item = &'a MidIR> + 'a> {
    children_of(&fp.block)
}

fn find_function_calls(f: FunctionRange) -> Vec<usize> {
    let mut calls = vec![];
    for i in scan_ops(&f) {
        if let MidIR::FunctionCall(addr, _) = i {
            calls.push(*addr)
        }
    }
    calls.iter().unique().copied().collect()
}

/*
impl<'a> Iterator for FunctionIterator<'a> {
    type Item = &'a MidIR;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(sub) = &mut self.sub {
            if let Some(i) = sub.next() {
                return Some(i);
            } else {
                self.sub = None;
            }
        }
    }
}
*/

pub fn to_mid_ir(prog: &[i128]) {
    let mut program = Program {
        functions: vec![],
        inst: prog.to_vec(),
    };
    dfs(
        0,
        |offset| {
            trace!("Discovering function at {}", offset);
            let input = Input::new(*offset, &program.inst[*offset..]);
            let fr = parse_function(input).unwrap();
            program.functions.push(fr.clone());
            find_function_calls(fr)
        },
        |_| false,
    );
    // program.functions.push(f);

    let mut printer = CodePrinter::new();
    for f in program.functions.iter().sorted_by_key(|f| f.start) {
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

fn from_arg(arg: &OpArg) -> Expr {
    match &arg.kind {
        Arg::Value(x) => Expr::Literal(*x),
        Arg::RelativeMem(x) if *x > 0 => Expr::OutArg(*x as usize),
        Arg::RelativeMem(x) if *x < 0 => Expr::InArg((-*x) as usize),
        Arg::Mem(x) => Expr::Var(format!("data[{}]", *x)),
        Arg::Pointer(x) => Expr::Var(x.clone()),
        _ => panic!("Unexpected argument {:?}", arg),
    }
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

fn analyze_flow(input: Input) -> FlowAnalysis {
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
        if let Ok((new_input, fc)) = parse_function_call(input) {
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
                        let mut t = from_arg(&value);
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
                        instruction_to_midir(op.kind),
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

fn instruction_to_midir(kind: Instruction) -> MidIR {
    match kind {
        Instruction::Assign(arg1, arg2) => MidIR::Assign(from_arg(&arg1), from_arg(&arg2)),
        Instruction::Add(a, b, c) => MidIR::Assign(
            from_arg(&c),
            Expr::Add(Box::new(from_arg(&a)), Box::new(from_arg(&b))),
        ),
        Instruction::Mul(a, b, c) => MidIR::Assign(
            from_arg(&c),
            Expr::Mul(Box::new(from_arg(&a)), Box::new(from_arg(&b))),
        ),
        Instruction::Output(OpArg {
            kind: Arg::Value(x),
            ..
        }) => MidIR::Output(x),
        Instruction::Input(a) => MidIR::Assign(from_arg(&a), Expr::Input()),
        Instruction::Equals(a, b, c) => MidIR::Assign(
            from_arg(&c),
            Expr::Equal(Box::new(from_arg(&a)), Box::new(from_arg(&b))),
        ),
        Instruction::LessThan(a, b, c) => MidIR::Assign(
            from_arg(&c),
            Expr::LessThan(Box::new(from_arg(&a)), Box::new(from_arg(&b))),
        ),
        _ => panic!("Unexpected instruction {:?}", kind),
    }
}

fn parse_function(input: Input) -> Result<FunctionRange, ParseError> {
    let (input, adjust_res) = Instruction::parse(input)?;
    let arg_count = match adjust_res.kind {
        Instruction::AdjustRelativeBase(OpArg {
            kind: Arg::Value(r),
            ..
        }) if r > 0 => {
            if adjust_res.span.start == 0 {
                Ok(0)
            } else {
                Ok(r)
            }
        }
        _ => Err(ParseError::NoMatch),
    }?;
    let flow = analyze_flow(input);
    let flow_high = mid_flow::parse_flow(&flow.graph, flow.span).unwrap();
    let mid_ir = flow_to_mid_ir(&flow_high);

    Ok(FunctionRange {
        start: adjust_res.span.start,
        end: flow.span.end,
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
        FlowHigh::If { then, .. } => {
            // Use a placeholder condition for now
            let condition = Expr::Literal(1);
            MidIR::If(condition, Box::new(flow_to_mid_ir(then)), None)
        }
        FlowHigh::IfElse { then, els, .. } => {
            // Use a placeholder condition for now
            let condition = Expr::Literal(1);
            MidIR::If(
                condition,
                Box::new(flow_to_mid_ir(then)),
                Some(Box::new(flow_to_mid_ir(els))),
            )
        }
        FlowHigh::Return => MidIR::Return(),
        FlowHigh::Break(id) => MidIR::Break(*id),
        FlowHigh::Continue(id) => MidIR::Continue(*id),
    }
}

/*
    /*
    fn process_all_functions(&mut self) {
        let funcs = self.functions.len();
        for f in 0..funcs {
            self.process_function(f);
        }
    }
    */
pub fn to_mid_ir(prog: &[i128]) -> Vec<MidIR> {
    let mut program = Program {
        functions: vec![],
        inst: prog.to_vec(),
    };
    discover_functions(0, &mut program);
    program.process_all_functions();
    loop {
        let new_funcs = program.scan_dynamic_calls();
        for new_func in &new_funcs {
            trace!("Discovering function at {}", new_func);
            discover_functions(*new_func, &mut program);
            program.process_all_functions();
        }
        if new_funcs.is_empty() {
            break;
        }
    }

    let mut printer = CodePrinter::new();
    for f in program.functions.iter().sorted_by_key(|f| f.start) {
        line!(
            &mut printer,
            "fn f{}({}) {{",
            f.start,
            f.args.iter().map(|x| &x.name).join(", ")
        );
        let mut indent = printer.indented();
        for c in &f.code {
            c.print(&mut indent);
        }
        line!(&mut printer, "}}");
        line!(&mut printer, "");
    }
    trace!("{}\n", printer.result());
    vec![]
}
fn discover_functions(start: usize, program: &mut Program) {
    let mut stack = Vec::new();
    // let mut offset_to_name = HashMap::new();
    stack.push(start);
    let mut seen_functions: HashSet<usize> =
        HashSet::from_iter(program.functions.iter().map(|f| f.start));
    while let Some(start_offset) = stack.pop() {
        let mut offset = start_offset;
        let i = Instruction::from_slice(offset, &program.inst[offset..]).unwrap();
        let mut arg_count: usize = 0;
        match i {
            Instruction::AdjustRelativeBase(OpArg {
                kind: Arg::Value(r),
                ..
            }) => {
                assert!(r > 0);
                if offset != 0 {
                    arg_count = r as usize - 1;
                }
            }
            _ => panic!("Expected relative base instruction"),
        }
        offset += i.size();
        let mut prev: Option<Instruction> = None;
        let mut return_point = None;
        let mut min_end_offset = None;
        let mut args = (1..=arg_count)
            .map(|i| Argument {
                name: format!("i{}", i),
                typ: ArgType::Value,
            })
            .collect_vec();
        let mut static_calls = vec![];
        loop {
            if let Some(f) = matches_function_call(&program.inst, offset) {
                if !seen_functions.contains(&f) {
                    stack.push(f);
                    seen_functions.insert(f);
                }
                static_calls.push(f);
                offset += 7; // assign and goto
                continue;
            }
            if let Some(f) = matches_dynamic_call(&program.inst, offset) {
                args[arg_count - f].typ = ArgType::FunctionPointer { args: vec![] };
                args[arg_count - f].name = format!("f{}", 1 + arg_count - f);
                offset += 7; // assign and goto
                continue;
            }
            let i = Instruction::from_slice(offset, &program.inst[offset..]).unwrap();
            let i = i.simplify();
            offset += i.size();
            match i {
                Instruction::Goto(OpArg {
                    kind: Arg::Value(p),
                    ..
                }) => {
                    let p = p as usize;
                    if min_end_offset.is_none() || p > min_end_offset.unwrap() {
                        min_end_offset = Some(p);
                    }
                    if (start_offset..=offset).contains(&p)
                        && offset - i.size() > min_end_offset.unwrap_or(0)
                    {
                        break;
                    }
                }
                Instruction::Goto(OpArg {
                    kind: Arg::RelativeMem(0),
                    ..
                }) => {
                    assert!(matches!(
                        prev.as_ref().unwrap(),
                        &Instruction::AdjustRelativeBase(OpArg {
                            kind: Arg::Value(x),
                            ..
                        }) if x == -(arg_count as i128 + 1)
                    ));
                    return_point = Some(offset - i.size() - prev.unwrap().size());
                    break;
                }
                Instruction::JumpIfFalse(
                    _,
                    OpArg {
                        kind: Arg::Value(addr),
                        ..
                    },
                )
                | Instruction::JumpIfTrue(
                    _,
                    OpArg {
                        kind: Arg::Value(addr),
                        ..
                    },
                ) => {
                    let addr = addr as usize;
                    if min_end_offset.is_none() || addr > min_end_offset.unwrap() {
                        min_end_offset = Some(addr);
                    }
                }
                Instruction::Data(_) => panic!("Unexpected data at {}", offset),
                _ => {}
            }
            prev = Some(i);
        }
        program.functions.push(FunctionRange {
            start: start_offset,
            end: offset,
            args,
            static_calls,
            return_point,
            code: vec![],
        });
    }
}

    fn process_function(&mut self, function_index: usize) {
        let mut f = &self.functions[function_index];
        let mut offset = f.start + 2; // Adjus relative base
        let mut code = vec![];
        let arg_count = f.args.len();
        let from_arg = |arg: &Arg| match arg {
            Arg::Mem(x) => Expr::Var(format!("data[{}]", x)),
            Arg::Value(x) => Expr::Literal(*x),
            Arg::RelativeMem(x) if *x > 0 => Expr::Var(format!("o{}", *x)),
            Arg::RelativeMem(x) if *x < 0 => {
                Expr::Var(f.args[(arg_count as i128 + *x) as usize].name.clone())
            }
            Arg::RelativeMem(x) => Expr::Var("*R".to_string()),
            Arg::Pointer(x) => Expr::Var(x.clone()),
        };
        while offset < f.return_point.unwrap_or(f.end) {
            if let Some(addr) = matches_function_call(&self.inst, offset) {
                let target = self.functions.iter().find(|f| f.start == addr).unwrap();
                let args = (1..=target.args.len())
                    .map(|i| Expr::Var(format!("o{}", i)))
                    .collect_vec();
                code.push(MidIR::FunctionCall(addr, args));
                offset += 7;
                continue;
            }
            if let Some(rev_arg_index) = matches_dynamic_call(&self.inst, offset) {
                /*
                let args = (0..arg_count)
                    .map(|i| Expr::Var(format!("i{}", i + 1)))
                    .collect_vec();
                */
                code.push(MidIR::DynamicFunctionCall(
                    Expr::Var(f.args[arg_count - rev_arg_index].name.clone()),
                    vec![],
                ));
                offset += 7;
                continue;
            }

            let i = Instruction::from_slice(offset, &self.inst[offset..]).unwrap();
            let i = i.simplify();
            let mid = match &i {
                Instruction::Assign(arg1, ref arg2) => {
                    MidIR::Assign(from_arg(&arg1.kind), from_arg(&arg2.kind))
                }
                Instruction::Add(a, b, c) => MidIR::Assign(
                    from_arg(&c.kind),
                    Expr::Add(Box::new(from_arg(&a.kind)), Box::new(from_arg(&b.kind))),
                ),
                Instruction::Mul(a, b, c) => MidIR::Assign(
                    from_arg(&c.kind),
                    Expr::Mul(Box::new(from_arg(&a.kind)), Box::new(from_arg(&b.kind))),
                ),
                _ => MidIR::Unknown(offset, i.clone()),
            };
            code.push(mid);
            offset += i.size();
        }
        self.functions[function_index].code = code;
    }

    fn scan_dynamic_calls(&self) -> HashSet<usize> {
        let mut dynamic_calls = HashSet::new();
        for f in self.functions.iter() {
            for (index, i) in f.code.iter().enumerate() {
                if let MidIR::FunctionCall(fid, args) = i {
                    let func = self
                        .functions
                        .iter()
                        .find(|func| func.start == *fid)
                        .unwrap();
                    for (func_arg_index, arg) in func.args.iter().enumerate() {
                        if let ArgType::FunctionPointer { args } = &arg.typ {
                            let addr = f.code[0..index].iter().rev().find_map(|fun_assign| {
                                if let MidIR::Assign(Expr::Var(y), Expr::Literal(addr)) = fun_assign
                                {
                                    if format!("o{}", func_arg_index + 1) == *y {
                                        return Some(addr);
                                    }
                                }
                                None
                            });
                            if let Some(addr) = addr {
                                dynamic_calls.insert(*addr as usize);
                            }
                        }
                    }
                }
            }
        }
        dynamic_calls.retain(|x| self.functions.iter().all(|f| f.start != *x));
        dynamic_calls
    }
}

*/
