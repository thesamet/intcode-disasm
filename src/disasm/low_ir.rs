use std::fmt::{self, Debug, Display, Formatter};

use itertools::Itertools;

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
pub enum Arg {
    Mem(i128),
    Value(i128),
    RelativeMem(i128),
    Pointer(usize),
}

impl Arg {
    pub fn value(&self) -> Option<i128> {
        match self {
            Arg::Value(x) => Some(*x),
            _ => None,
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
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

impl Display for OpArg {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.kind)
    }
}

trait ArgBase {
    fn is_value(&self) -> bool;
}

#[derive(Clone, Debug, PartialEq)]
pub enum GenericInstruction<ArgType: ArgBase> {
    Add(ArgType, ArgType, ArgType),
    Mul(ArgType, ArgType, ArgType),
    Input(ArgType),
    Output(ArgType),
    JumpIf(ArgType, bool, ArgType),
    LessThan(ArgType, ArgType, ArgType),
    Equals(ArgType, ArgType, ArgType),
    AdjustRelativeBase(ArgType),
    Data(Vec<i128>),
    Halt,
    // synthetic
    Goto(ArgType),
    Assign(ArgType, ArgType),
}

pub type Instruction = GenericInstruction<OpArg>;

pub type ArgInstruction = GenericInstruction<Arg>;

pub struct GenericOp<T: ArgBase> {
    pub span: Span,
    pub kind: GenericInstruction<T>,
}

pub type Op = GenericOp<OpArg>;

impl Op {
    fn to_arg_instruction(&self) -> ArgInstruction {
        self.kind.map(|x| x.kind)
    }
}

impl ArgBase for Arg {
    fn is_value(&self) -> bool {
        matches!(self, Arg::Value(_))
    }
}

impl ArgBase for OpArg {
    fn is_value(&self) -> bool {
        self.kind.is_value()
    }
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

impl<ArgType: ArgBase> GenericInstruction<ArgType> {
    fn map<F, T: ArgBase>(&self, f: F) -> GenericInstruction<T>
    where
        F: Fn(&ArgType) -> T,
    {
        match self {
            GenericInstruction::Add(a, b, c) => GenericInstruction::Add(f(a), f(b), f(c)),
            GenericInstruction::Mul(a, b, c) => GenericInstruction::Mul(f(a), f(b), f(c)),
            GenericInstruction::Input(a) => GenericInstruction::Input(f(a)),
            GenericInstruction::Output(a) => GenericInstruction::Output(f(a)),
            GenericInstruction::JumpIf(a, b, c) => GenericInstruction::JumpIf(f(a), *b, f(c)),
            GenericInstruction::LessThan(a, b, c) => GenericInstruction::LessThan(f(a), f(b), f(c)),
            GenericInstruction::Equals(a, b, c) => GenericInstruction::Equals(f(a), f(b), f(c)),
            GenericInstruction::AdjustRelativeBase(a) => {
                GenericInstruction::AdjustRelativeBase(f(a))
            }
            GenericInstruction::Data(a) => GenericInstruction::Data(a.clone()),
            GenericInstruction::Halt => GenericInstruction::Halt,
            GenericInstruction::Goto(a) => GenericInstruction::Goto(f(a)),
            GenericInstruction::Assign(a, b) => GenericInstruction::Assign(f(a), f(b)),
        }
    }

    pub fn reads(&self) -> Vec<&ArgType> {
        let mut v = match self {
            Self::Add(a, b, _) => vec![a, b],
            Self::Mul(a, b, _) => vec![a, b],
            Self::Input(a) => vec![a],
            Self::Output(a) => vec![a],
            Self::JumpIf(a, _, b) => vec![a, b],
            Self::LessThan(a, b, _) => vec![a, b],
            Self::Equals(a, b, _) => vec![a, b],
            Self::AdjustRelativeBase(a) => vec![a],
            Self::Data(_) => vec![],
            Self::Halt => vec![],
            Self::Goto(a) => vec![a],
            Self::Assign(_, b) => vec![b],
        };
        v.retain(|x| !x.is_value());
        v
    }

    pub fn writes(&self) -> Option<&ArgType> {
        match self {
            Self::Add(_, _, c) => Some(c),
            Self::Mul(_, _, c) => Some(c),
            Self::Input(a) => Some(a),
            Self::Output(_) => None,
            Self::JumpIf(_, _, _) => None,
            Self::LessThan(_, _, c) => Some(c),
            Self::Equals(_, _, c) => Some(c),
            Self::AdjustRelativeBase(_) => None,
            Self::Data(_) => None,
            Self::Halt => None,
            Self::Goto(_) => None,
            Self::Assign(a, _) => Some(a),
        }
    }
}

impl ArgInstruction {
    pub fn parse(input: Input) -> Result<(Input, ArgInstruction), ParseError> {
        Instruction::parse(input).map(|(input, op)| (input, op.to_arg_instruction()))
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
            1 => Instruction::Add(args[0].unwrap(), args[1].unwrap(), args[2].unwrap()),
            2 => Instruction::Mul(args[0].unwrap(), args[1].unwrap(), args[2].unwrap()),
            3 => Instruction::Input(args[0].unwrap()),
            4 => Instruction::Output(args[0].unwrap()),
            5 => Instruction::JumpIf(args[0].unwrap(), true, args[1].unwrap()),
            6 => Instruction::JumpIf(args[0].unwrap(), false, args[1].unwrap()),
            7 => Instruction::LessThan(args[0].unwrap(), args[1].unwrap(), args[2].unwrap()),
            8 => Instruction::Equals(args[0].unwrap(), args[1].unwrap(), args[2].unwrap()),
            9 => Instruction::AdjustRelativeBase(args[0].unwrap()),
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
}

impl<T: ArgBase + Display> Display for GenericInstruction<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Add(a, b, c) => write!(f, "{} = {} + {}", c, a, b),
            Self::Mul(a, b, c) => write!(f, "{} = {} * {}", c, a, b),
            Self::Input(a) => write!(f, "{} = input()", a),
            Self::Output(a) => write!(f, "output({})", a),
            Self::JumpIf(a, cond, b) => {
                write!(f, "if {}{} goto {}", if *cond { "" } else { "!" }, a, b)
            }
            Self::LessThan(a, b, c) => write!(f, "{} = {} < {}", c, a, b),
            Self::Equals(a, b, c) => write!(f, "{} = {} == {}", c, a, b),
            Self::AdjustRelativeBase(a) => write!(f, "R += {}", a),
            Self::Halt => write!(f, "halt"),
            Self::Data(i) => write!(f, "[DATA: {:?}]", i),
            // Synthetic
            Self::Assign(a, b) => write!(f, "{} = {}", a, b),
            Self::Goto(a) => write!(f, "goto {}", a),
        }
    }
}
