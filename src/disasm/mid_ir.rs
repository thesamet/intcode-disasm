use std::fmt::{self, Display, Formatter};

use crate::disasm::low_ir::*;
use crate::line;
use itertools::Itertools;
use pathfinding::prelude::dfs;

use super::code_printer::{CodePrinter, CodeWriter};

#[derive(Debug)]
enum ArgType {
    Value,
    FunctionPointer { args: Vec<ArgType> },
}

#[derive(Debug)]
struct Argument {
    name: String,
    typ: ArgType,
}

#[derive(Debug)]
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
    if let Instruction::Assign(
        OpArg {
            kind: Arg::RelativeMem(0),
            ..
        },
        OpArg {
            kind: Arg::Value(return_addr),
            ..
        },
    ) = assign_op.kind
    {
        println!("Return addr: {}", return_addr);
        let (input, goto) = Instruction::parse(input)?;
        if return_addr as usize != input.offset {
            return Err(ParseError::NoMatch);
        }
        match goto.kind {
            Instruction::Goto(OpArg {
                kind: Arg::Value(addr),
                ..
            }) => Ok((input, MidIR::FunctionCall(addr as usize, vec![]))),
            Instruction::Goto(OpArg {
                kind: Arg::RelativeMem(offset),
                ..
            }) => {
                if offset < 0 {
                    Ok((
                        input,
                        MidIR::DynamicFunctionCall(Expr::InArg((-offset) as usize), vec![]),
                    ))
                } else {
                    Err(ParseError::NoMatch)
                }
            }

            _ => Err(ParseError::NoMatch),
        }
    } else {
        Err(ParseError::NoMatch)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Var(String), // To be deleted
    InArg(usize),
    OutArg(usize),
    MemRef(Box<Expr>),
    Literal(i128),
    Add(Box<Expr>, Box<Expr>),
    Mul(Box<Expr>, Box<Expr>),
    NotEqual(Box<Expr>, Box<Expr>),
    Equal(Box<Expr>, Box<Expr>),
}

impl Expr {}

impl Display for Expr {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Expr::Var(x) => write!(f, "{}", x),
            Expr::Literal(x) => write!(f, "{}", x),
            Expr::Add(a, b) => write!(f, "({} + {})", a, b),
            Expr::Mul(a, b) => write!(f, "({} * {})", a, b),
            Expr::InArg(x) => write!(f, "i{}", x),
            Expr::OutArg(x) => write!(f, "o{}", x),
            Expr::MemRef(x) => write!(f, "*({})", x),
            Expr::NotEqual(a, b) => write!(f, "{} != {}", a, b),
            Expr::Equal(a, b) => write!(f, "{} == {}", a, b),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum MidIR {
    Block(Vec<MidIR>),
    Loop(Box<MidIR>),
    Assign(Expr, Expr),
    FunctionCall(usize, Vec<Expr>),
    DynamicFunctionCall(Expr, Vec<Expr>),
    If(Expr, Vec<MidIR>, Vec<MidIR>),
    Output(i128),
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
                for i in then {
                    i.print(&mut f.indented());
                }
                if els.is_empty() {
                    line!(f, "}}");
                } else {
                    line!(f, "}} else {{");
                    for i in els {
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
            MidIR::Loop(body) => {
                line!(f, "while (true) {{");
                body.print(&mut f.indented());
                line!(f, "}}");
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
        MidIR::Block(mid_irs) => Box::new(mid_irs.iter()),
        MidIR::Loop(mid_ir) => children_of(mid_ir),
        MidIR::If(expr, t, f) => Box::new(t.iter().chain(f.iter())),
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
    let program = Program {
        functions: vec![],
        inst: prog.to_vec(),
    };
    dfs(
        0,
        |offset| {
            println!("Discovering function at {}", offset);
            let input = Input::new(*offset, &program.inst[*offset..]);
            let (_, fr) = parse_function(input).unwrap();
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

fn parse_assign(input: Input) -> Result<(Input, MidIR), ParseError> {
    let (input, assign_op) = Instruction::parse(input)?;
    if let Instruction::Assign(arg1, arg2) = assign_op.kind {
        println!("Parsing assign");
        Ok((input, MidIR::Assign(from_arg(&arg1), from_arg(&arg2))))
    } else {
        Err(ParseError::NoMatch)
    }
}

fn parse_mul(input: Input) -> Result<(Input, MidIR), ParseError> {
    let (input, mul_op) = Instruction::parse(input)?;
    if let Instruction::Mul(a, b, c) = mul_op.kind {
        Ok((
            input,
            MidIR::Assign(
                from_arg(&c),
                Expr::Mul(Box::new(from_arg(&a)), Box::new(from_arg(&b))),
            ),
        ))
    } else {
        Err(ParseError::NoMatch)
    }
}

fn parse_add(input: Input) -> Result<(Input, MidIR), ParseError> {
    let (input, add_op) = Instruction::parse(input)?;
    if let Instruction::Add(a, b, c) = add_op.kind {
        Ok((
            input,
            MidIR::Assign(
                from_arg(&c),
                Expr::Add(Box::new(from_arg(&a)), Box::new(from_arg(&b))),
            ),
        ))
    } else {
        Err(ParseError::NoMatch)
    }
}

fn parse_eq(input: Input) -> Result<(Input, MidIR), ParseError> {
    let (input, eq_op) = Instruction::parse(input)?;
    if let Instruction::Equals(a, b, c) = eq_op.kind {
        Ok((
            input,
            MidIR::Assign(
                from_arg(&c),
                Expr::Equal(Box::new(from_arg(&a)), Box::new(from_arg(&b))),
            ),
        ))
    } else {
        Err(ParseError::NoMatch)
    }
}

fn parse_if(input: Input) -> Result<(Input, MidIR), ParseError> {
    let offset = input.offset;
    let (input, jump) = Instruction::parse(input)?;
    if let Instruction::JumpIf(
        cond,
        val,
        OpArg {
            kind: Arg::Value(addr),
            ..
        },
    ) = jump.kind
    {
        if addr <= input.offset as i128 {
            return Err(ParseError::NoMatch);
        }
        let (input, then_block) = parse_block(input, Some(addr as usize))?;
        if input.offset == addr as usize {
            Ok((
                input,
                MidIR::If(
                    if val {
                        Expr::NotEqual(Box::new(from_arg(&cond)), Box::new(Expr::Literal(0)))
                    } else {
                        Expr::Equal(Box::new(from_arg(&cond)), Box::new(Expr::Literal(0)))
                    },
                    then_block.into_iter().collect(),
                    vec![],
                ),
            ))
        } else {
            panic!("Expected jump to end of block at {}", addr);
        }
    } else {
        Err(ParseError::NoMatch)
    }
}

fn parse_return(input: Input) -> Result<(Input, MidIR), ParseError> {
    let (input, adjust) = Instruction::parse(input)?;
    if input.offset == 1303 {
        println!("here: {:?}", adjust.kind);
    }
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

fn parse_block(
    input: Input,
    max_known_offset: Option<usize>,
) -> Result<(Input, Vec<MidIR>), ParseError> {
    let mut input = input;
    let mut code = vec![];
    let mut potentially_exit_next = false;
    loop {
        let offset = input.offset;
        if Some(offset) == max_known_offset {
            break;
        }
        if potentially_exit_next {
            if max_known_offset.is_none() {
                break;
            }
            if max_known_offset.unwrap() <= offset {
                break;
            }
            potentially_exit_next = false;
        }
        if let Ok((new_input, mid)) = parse_function_call(input)
            // .or_else(|_| parse_while(input))
            .or_else(|_| parse_if(input))
            .or_else(|_| parse_assign(input))
            .or_else(|_| parse_mul(input))
            .or_else(|_| parse_add(input))
            .or_else(|_| parse_eq(input))
            .or_else(|_| parse_return(input).inspect(|_| potentially_exit_next = true))
        {
            code.push((input.offset, mid));
            input = new_input;
        } else {
            let (input, goto) = Instruction::parse(input)?;
            match goto.kind {
                Instruction::Goto(OpArg {
                    kind: Arg::Value(addr),
                    ..
                }) => {
                    if let Some(loop_start_index) = code.iter().position(|x| x.0 == addr as usize) {
                        let c = code.split_off(loop_start_index);
                        code.push((
                            addr as usize,
                            MidIR::Loop(Box::new(MidIR::Block(
                                c.into_iter().map(|x| x.1).collect(),
                            ))),
                        ));
                        potentially_exit_next = true;
                    } else {
                        panic!("Unexpected goto to {}", addr);
                    }
                }
                _ => panic!("Unexpected instruction at {}: {:?}", offset, goto.kind),
            };
        }
    }
    Ok((input, code.into_iter().map(|x| x.1).collect()))
}

fn parse_while(input: Input) -> Result<(Input, MidIR), ParseError> {
    let (input, assign_cond) = Instruction::parse(input)?;
    let (input, jump_cond) = Instruction::parse(input)?;
    let cond_var = if let Instruction::Assign(
        OpArg {
            kind: a @ Arg::RelativeMem(_),
            ..
        },
        _,
    ) = assign_cond.kind
    {
        a
    } else {
        return Err(ParseError::NoMatch);
    };

    if let Instruction::JumpIf(
        OpArg {
            kind: b @ Arg::RelativeMem(_),
            ..
        },
        val,
        OpArg {
            kind: Arg::Value(end_addr),
            ..
        },
    ) = jump_cond.kind
    {
        if cond_var == b {
            let (input, block) = parse_block(input, Some(end_addr as usize))?;
            /*
            Ok((
                input,
                MidIR::Loop(Box::new(MidIR::If(
                    if val {
                        Expr::NotEqual(Box::new(from_arg(&a)), Box::new(Expr::Literal(0)))
                    } else {
                        Expr::Equal(Box::new(from_arg(&a)), Box::new(Expr::Literal(0)))
                    },
                    block.into_iter().collect(),
                    vec![],
                ))),
            ))
            */
            unreachable!()
        } else {
            Err(ParseError::NoMatch)
        }
    } else {
        Err(ParseError::NoMatch)
    }
}

#[derive(Debug, Clone)]
struct FlowAnalysis {
    span: Span,
    return_statements: Vec<usize>,
    gotos: Vec<(usize, usize)>,
    halts: Vec<usize>,
    ifs: Vec<(usize, usize)>,
}

fn analyze_flow(input: Input) -> FlowAnalysis {
    let mut input = input;
    let start_offset = input.offset;
    let mut return_statements = Vec::new();
    let mut max_addr_seen = start_offset;
    let mut gotos = Vec::new();
    let mut halts = Vec::new();
    let mut ifs = Vec::new();
    loop {
        let offset = input.offset;
        if let Ok((new_input, mid)) = parse_function_call(input) {
            input = new_input;
            continue;
        } else if let Ok((new_input, mid)) = parse_return(input) {
            return_statements.push(offset);
            input = new_input;
            continue;
        } else if let Ok((new_input, op)) = Instruction::parse(input) {
            match op.kind {
                Instruction::Goto(OpArg {
                    kind: Arg::Value(addr),
                    ..
                }) => {
                    let addr = addr as usize;
                    gotos.push((offset, addr));
                    // back jump, code beyond max_addr_seen is not reachable.
                    if offset >= addr && offset >= max_addr_seen {
                        break;
                    }
                    if max_addr_seen <= addr {
                        max_addr_seen = addr;
                    }
                }
                Instruction::Goto(_) => {
                    panic!("Unexpected goto at {} {}", offset, op.kind);
                }
                Instruction::JumpIf(
                    _,
                    _,
                    OpArg {
                        kind: Arg::Value(addr),
                        ..
                    },
                ) => {
                    if addr as usize > max_addr_seen {
                        max_addr_seen = addr as usize;
                    }
                    ifs.push((offset, addr as usize));
                }
                Instruction::JumpIf(_, _, _) => {
                    panic!("Unexpected jumpif at {} {}", offset, op.kind);
                }
                Instruction::Halt => {
                    halts.push(offset);
                    input = new_input;
                    if offset >= max_addr_seen {
                        break;
                    }
                }
                _ => {}
            }
        } else {
            panic!("Could not parse instruction at {}", offset);
        }
    }

    FlowAnalysis {
        span: Span {
            start: start_offset,
            end: max_addr_seen,
        },
        return_statements,
        gotos,
        halts,
        ifs,
    }
}

fn parse_function(input: Input) -> Result<(Input, FunctionRange), ParseError> {
    let flow = analyze_flow(input);
    println!("Flow = {:?}", flow);
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
    let (input, block) = parse_block(input, None)?;
    let end = input.offset;
    Ok((
        input,
        FunctionRange {
            start: adjust_res.span.start,
            end,
            args: vec![],
            static_calls: vec![],
            return_point: None,
            block: MidIR::Block(block),
        },
    ))
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
            println!("Discovering function at {}", new_func);
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
    println!("{}\n", printer.result());
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
