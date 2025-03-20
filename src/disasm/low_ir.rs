use std::fmt::{self, Debug, Display, Formatter};

use itertools::Itertools;

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub enum Arg {
    Mem(i128),
    Value(i128),
    RelativeMem(i128),
    Pointer(usize),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        assert!(start <= end);
        Span { start, end }
    }

    pub fn contains(&self, s: &Span) -> bool {
        self.start <= s.start && s.end <= self.end
    }

    pub fn contains_address(&self, p: usize) -> bool {
        self.start <= p && p < self.end
    }

    pub fn with_start(&self, start: usize) -> Self {
        assert!(start <= self.end);
        Self::new(start, self.end)
    }
}

impl Display for Span {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

impl std::fmt::Debug for Span {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct OpArg {
    pub kind: Arg,
    pub span: Span,
}

impl From<(usize, usize)> for Span {
    fn from(arg: (usize, usize)) -> Span {
        Span {
            start: arg.0,
            end: arg.1,
        }
    }
}

impl Arg {
    fn parse(input: Input, mode: i128) -> Result<(Input, OpArg), ParseError> {
        let offset = input.offset;
        let (new_input, value) = input.read()?;
        let arg = match mode {
            0 => {
                if value == 0 {
                    Arg::Pointer(offset)
                } else {
                    Arg::Mem(value)
                }
            }
            1 => Arg::Value(value),
            2 => Arg::RelativeMem(value),
            _ => return Err(ParseError::InvalidMode),
        };
        Ok((
            new_input,
            OpArg {
                kind: arg,
                span: (offset, offset + 1).into(),
            },
        ))
    }
}

impl Display for Arg {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Arg::Mem(x) => write!(f, "[{}]", x),
            Arg::Value(x) => write!(f, "{}", x),
            Arg::RelativeMem(x) if *x > 0 => write!(f, "[R+{}]", x),
            Arg::RelativeMem(x) if *x < 0 => write!(f, "[R{}]", x),
            Arg::RelativeMem(_) => write!(f, "[R]"),
            Arg::Pointer(x) => write!(f, "[[{}]]", x),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Instruction {
    Add(OpArg, OpArg, OpArg),
    Mul(OpArg, OpArg, OpArg),
    Input(OpArg),
    Output(OpArg),
    JumpIf(OpArg, bool, OpArg),
    LessThan(OpArg, OpArg, OpArg),
    Equals(OpArg, OpArg, OpArg),
    AdjustRelativeBase(OpArg),
    Data(Vec<i128>),
    Halt,
    // synthetic
    Goto(OpArg),
    Assign(OpArg, OpArg),
}

pub struct Op {
    pub span: Span,
    pub kind: Instruction,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    Empty,
    InvalidMode,
    InvalidOpcode,
    NoMatch,
}

#[derive(Debug, Clone, Copy)]
pub struct Input<'a> {
    pub offset: usize,
    pub prog: &'a [i128],
}

impl<'a> Input<'a> {
    pub fn new(offset: usize, prog: &'a [i128]) -> Self {
        Input { offset, prog }
    }

    pub fn read(self) -> Result<(Input<'a>, i128), ParseError> {
        if self.prog.is_empty() {
            Err(ParseError::Empty)
        } else {
            Ok((self.advance(1), self.prog[0]))
        }
    }

    pub fn advance(&self, count: usize) -> Self {
        Input {
            offset: self.offset + count,
            prog: &self.prog[count..],
        }
    }
}

impl Instruction {
    pub fn parse(input: Input) -> Result<(Input, Op), ParseError> {
        let offset = input.offset;
        let (input, op) = input.read()?;
        let opcode = op % 100;
        let mode = |i| (op / 10i128.pow(i as u32 + 2)) % 10;
        let arg_count = match opcode {
            1 => 3,
            2 => 3,
            3 => 1,
            4 => 1,
            5 => 2,
            6 => 2,
            7 => 3,
            8 => 3,
            9 => 1,
            99 => 0,
            _ => return Err(ParseError::InvalidMode),
        };
        let mut args: [Option<OpArg>; 3] = core::array::from_fn(|_| None);
        let mut input = input;
        for (i, mut_arg) in args.iter_mut().take(arg_count).enumerate() {
            let (new_input, arg) = Arg::parse(input, mode(i))?;
            input = new_input;
            *mut_arg = Some(arg);
        }

        let val = match opcode {
            1 => Instruction::Add(
                args[0].clone().unwrap(),
                args[1].clone().unwrap(),
                args[2].clone().unwrap(),
            ),
            2 => Instruction::Mul(
                args[0].clone().unwrap(),
                args[1].clone().unwrap(),
                args[2].clone().unwrap(),
            ),
            3 => Instruction::Input(args[0].clone().unwrap()),
            4 => Instruction::Output(args[0].clone().unwrap()),
            5 => Instruction::JumpIf(args[0].clone().unwrap(), true, args[1].clone().unwrap()),
            6 => Instruction::JumpIf(args[0].clone().unwrap(), false, args[1].clone().unwrap()),
            7 => Instruction::LessThan(
                args[0].clone().unwrap(),
                args[1].clone().unwrap(),
                args[2].clone().unwrap(),
            ),
            8 => Instruction::Equals(
                args[0].clone().unwrap(),
                args[1].clone().unwrap(),
                args[2].clone().unwrap(),
            ),
            9 => Instruction::AdjustRelativeBase(args[0].clone().unwrap()),
            99 => Instruction::Halt,
            _ => return Err(ParseError::InvalidOpcode),
        };
        let end_offset = input.offset;
        Ok((
            input,
            Op {
                span: (offset, end_offset).into(),
                kind: val.simplify(),
            },
        ))
    }

    pub fn from_slice(offset: usize, prog: &[i128]) -> Option<Self> {
        Self::parse(Input::new(offset, prog))
            .ok()
            .map(|(_, op)| op.kind)
    }

    fn simplify(self) -> Self {
        match self {
            Instruction::Add(
                OpArg {
                    kind: Arg::Value(0),
                    ..
                },
                b,
                a,
            )
            | Instruction::Add(
                b,
                OpArg {
                    kind: Arg::Value(0),
                    ..
                },
                a,
            )
            | Instruction::Mul(
                OpArg {
                    kind: Arg::Value(1),
                    ..
                },
                b,
                a,
            ) => Instruction::Assign(a, b),
            Instruction::Mul(
                b,
                OpArg {
                    kind: Arg::Value(1),
                    ..
                },
                a,
            ) => Instruction::Assign(a, b),
            Instruction::JumpIf(
                OpArg {
                    kind: Arg::Value(c),
                    ..
                },
                cond,
                addr,
            ) if (cond && c != 0) || (!cond && c == 0) => Instruction::Goto(addr),
            x => x,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Instruction::Add(_, _, _) => 4,
            Instruction::Mul(_, _, _) => 4,
            Instruction::Input(_) => 2,
            Instruction::Output(_) => 2,
            Instruction::JumpIf(_, _, _) => 3,
            Instruction::LessThan(_, _, _) => 4,
            Instruction::Equals(_, _, _) => 4,
            Instruction::AdjustRelativeBase(_) => 2,
            Instruction::Halt => 1,
            Instruction::Data(i) => i.len(),
            Instruction::Goto(_) => 3,
            Instruction::Assign(_, _) => 4,
        }
    }

    fn coalesce_data(instructions: &[(usize, Self)], prog: &[i128]) -> Vec<(usize, Self)> {
        let mut instructions = instructions.to_vec();
        for i in 0..instructions.len() - 2 {
            let a = instructions[i].clone();
            let c = instructions[i + 2].clone();
            let b = &mut instructions[i + 1];
            match (a.1, &b.1, c.1) {
                (Instruction::Data(_), Instruction::Data(_), Instruction::Data(_)) => {}
                (Instruction::Data(_), _, Instruction::Data(_)) => {
                    *b = (b.0, Instruction::Data(prog[b.0..c.0].to_vec()));
                }
                _ => {}
            }
        }

        instructions
            .into_iter()
            .coalesce(|(prev_addr, prev_inst), (curr_addr, curr_inst)| {
                match (&prev_inst, &curr_inst) {
                    (Instruction::Data(prev_data), Instruction::Data(curr_data)) => Ok((
                        prev_addr,
                        Instruction::Data(prev_data.iter().chain(curr_data).cloned().collect()),
                    )),
                    _ => Err((
                        (prev_addr, prev_inst.clone()),
                        (curr_addr, curr_inst.clone()),
                    )),
                }
            })
            .collect()
    }

    pub fn parse_program(prog: &[i128]) -> Vec<(usize, Self)> {
        let mut instructions = Vec::new();
        let mut i = 0;
        let mut in_data = false;
        while i < prog.len() {
            let instr = match Instruction::from_slice(i, &prog[i..]) {
                Some(
                    i @ Instruction::AdjustRelativeBase(OpArg {
                        kind: Arg::Value(t),
                        ..
                    }),
                ) if t > 0 => {
                    in_data = false;
                    i
                }
                Some(inst) => {
                    if in_data {
                        Instruction::Data(vec![prog[i]])
                    } else {
                        inst
                    }
                }
                None => {
                    in_data = true;
                    Instruction::Data(vec![prog[i]])
                }
            };

            let size = instr.size();
            let instr = instr.simplify();
            instructions.push((i, instr));
            i += size;
        }
        // let mut instructions = Self::find_pointers(&instructions);
        Self::coalesce_data(&instructions, prog)
    }

    pub fn reads(&self) -> Vec<&Arg> {
        let mut v = match self {
            Instruction::Add(a, b, _) => vec![&a.kind, &b.kind],
            Instruction::Mul(a, b, _) => vec![&a.kind, &b.kind],
            Instruction::Input(a) => vec![&a.kind],
            Instruction::Output(a) => vec![&a.kind],
            Instruction::JumpIf(a, _, b) => vec![&a.kind, &b.kind],
            Instruction::LessThan(a, b, _) => vec![&a.kind, &b.kind],
            Instruction::Equals(a, b, _) => vec![&a.kind, &b.kind],
            Instruction::AdjustRelativeBase(a) => vec![&a.kind],
            Instruction::Data(_) => vec![],
            Instruction::Halt => vec![],
            Instruction::Goto(a) => vec![&a.kind],
            Instruction::Assign(_, b) => vec![&b.kind],
        };
        v.retain(|x| !matches!(x, Arg::Value(_)));
        v
    }

    pub fn writes(&self) -> Vec<&Arg> {
        match self {
            Instruction::Add(_, _, c) => vec![&c.kind],
            Instruction::Mul(_, _, c) => vec![&c.kind],
            Instruction::Input(a) => vec![&a.kind],
            Instruction::Output(_) => vec![],
            Instruction::JumpIf(_, _, _) => vec![],
            Instruction::LessThan(_, _, c) => vec![&c.kind],
            Instruction::Equals(_, _, c) => vec![&c.kind],
            Instruction::AdjustRelativeBase(_) => vec![],
            Instruction::Data(_) => vec![],
            Instruction::Halt => vec![],
            Instruction::Goto(_) => vec![],
            Instruction::Assign(a, _) => vec![&a.kind],
        }
    }
}

impl Display for Instruction {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Instruction::Add(a, b, c) => write!(f, "{} = {} + {}", c.kind, a.kind, b.kind),
            Instruction::Mul(a, b, c) => write!(f, "{} = {} * {}", c.kind, a.kind, b.kind),
            Instruction::Input(a) => write!(f, "{} = input()", a.kind),
            Instruction::Output(a) => write!(f, "output({})", a.kind),
            Instruction::JumpIf(a, cond, b) => {
                write!(
                    f,
                    "if {}{} goto {}",
                    if *cond { "" } else { "!" },
                    a.kind,
                    b.kind
                )
            }
            Instruction::LessThan(a, b, c) => write!(f, "{} = {} < {}", c.kind, a.kind, b.kind),
            Instruction::Equals(a, b, c) => write!(f, "{} = {} == {}", c.kind, a.kind, b.kind),
            Instruction::AdjustRelativeBase(a) => write!(f, "R += {}", a.kind),
            Instruction::Halt => write!(f, "halt"),
            Instruction::Data(i) => write!(f, "[DATA: {:?}]", i),
            // Synthetic
            Instruction::Assign(a, b) => write!(f, "{} = {}", a.kind, b.kind),
            Instruction::Goto(a) => write!(f, "goto {}", a.kind),
        }
    }
}
