use std::fmt::{self, Debug, Display, Formatter};

use itertools::Itertools;

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub enum Arg {
    Mem(i128),
    Value(i128),
    RelativeMem(i128),
    Deref(usize),
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
                    Arg::Deref(offset)
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
            Arg::Deref(x) => write!(f, "[[{}]]", x),
        }
    }
}

impl Display for OpArg {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.kind)
    }
}

pub trait ArgBase {
    fn value(&self) -> Option<i128>;

    fn is_value(&self) -> bool {
        Self::value(self).is_some()
    }

    fn relative_mem(&self) -> Option<i128>;

    fn is_relative_mem(&self) -> bool {
        Self::relative_mem(self).is_some()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum GenericInstruction<ArgType> {
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
    Phi(ArgType, Vec<ArgType>), // Destination and list of (block, source) pairs
}

pub type FatInstruction = GenericInstruction<OpArg>;

pub type Instruction = GenericInstruction<Arg>;

pub struct GenericOp<T: ArgBase> {
    pub span: Span,
    pub kind: GenericInstruction<T>,
}

pub type Op = GenericOp<OpArg>;

impl From<OpArg> for Arg {
    fn from(arg: OpArg) -> Self {
        arg.kind
    }
}

impl ArgBase for Arg {
    fn value(&self) -> Option<i128> {
        if let Arg::Value(x) = self {
            Some(*x)
        } else {
            None
        }
    }

    fn relative_mem(&self) -> Option<i128> {
        if let Arg::RelativeMem(x) = self {
            Some(*x)
        } else {
            None
        }
    }
}

impl ArgBase for OpArg {
    fn value(&self) -> Option<i128> {
        self.kind.value()
    }

    fn relative_mem(&self) -> Option<i128> {
        self.kind.relative_mem()
    }
}

impl<ArgType> GenericInstruction<ArgType>
where
    ArgType: ArgBase + From<OpArg>,
{
    pub fn parse(input: Input) -> Result<(Input, GenericInstruction<ArgType>), ParseError>
    where
        ArgType: Debug,
    {
        FatInstruction::parse_fat(input).map(|(input, op)| (input, op.kind.map(|f| (*f).into())))
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

impl<ArgType> GenericInstruction<ArgType> {
    /* Maps the arguments of the instruction to a new type using the provided functions.
     * The first function is used to map the read arguments, and the second function is used to map
     * the write arguments. The read function is guaranteed to be called for all read arguments
     * before the write function is called for any write arguments. This is useful for data flow
     * functions.
     */
    pub fn map_rw_result<R, W, O, T, E>(
        &self,
        o: &mut O,
        mut read_map: R,
        mut write_map: W,
    ) -> Result<GenericInstruction<T>, E>
    where
        R: FnMut(&mut O, &ArgType) -> Result<T, E>,
        W: FnMut(&mut O, &ArgType) -> Result<T, E>,
    {
        match self {
            GenericInstruction::Add(a, b, c) => Ok(GenericInstruction::Add(
                read_map(o, a)?,
                read_map(o, b)?,
                write_map(o, c)?,
            )),
            GenericInstruction::Mul(a, b, c) => Ok(GenericInstruction::Mul(
                read_map(o, a)?,
                read_map(o, b)?,
                write_map(o, c)?,
            )),
            GenericInstruction::Input(a) => Ok(GenericInstruction::Input(write_map(o, a)?)),
            GenericInstruction::Output(a) => Ok(GenericInstruction::Output(read_map(o, a)?)),
            GenericInstruction::JumpIf(a, b, c) => Ok(GenericInstruction::JumpIf(
                read_map(o, a)?,
                *b,
                read_map(o, c)?,
            )),
            GenericInstruction::LessThan(a, b, c) => Ok(GenericInstruction::LessThan(
                read_map(o, a)?,
                read_map(o, b)?,
                write_map(o, c)?,
            )),
            GenericInstruction::Equals(a, b, c) => Ok(GenericInstruction::Equals(
                read_map(o, a)?,
                read_map(o, b)?,
                write_map(o, c)?,
            )),
            GenericInstruction::AdjustRelativeBase(a) => {
                Ok(GenericInstruction::AdjustRelativeBase(read_map(o, a)?))
            }
            GenericInstruction::Data(a) => Ok(GenericInstruction::Data(a.clone())),
            GenericInstruction::Halt => Ok(GenericInstruction::Halt),
            GenericInstruction::Goto(a) => Ok(GenericInstruction::Goto(read_map(o, a)?)),
            GenericInstruction::Assign(a, b) => {
                let rb = read_map(o, b)?;
                Ok(GenericInstruction::Assign(write_map(o, a)?, rb))
            }
            GenericInstruction::Phi(a, b) => {
                let mut results = Vec::new();
                for x in b.iter() {
                    results.push(read_map(o, x)?);
                }
                Ok(GenericInstruction::Phi(write_map(o, a)?, results))
            }
        }
    }

    pub fn map_result<O, R, T, E>(&self, o: &mut O, map: R) -> Result<GenericInstruction<T>, E>
    where
        R: FnMut(&mut O, &ArgType) -> Result<T, E> + Clone,
    {
        let map2 = map.clone();
        self.map_rw_result(o, map, map2)
    }

    pub fn map_rw<O, R, W, T>(
        &self,
        o: &mut O,
        mut read_map: R,
        mut write_map: W,
    ) -> GenericInstruction<T>
    where
        R: FnMut(&mut O, &ArgType) -> T,
        W: FnMut(&mut O, &ArgType) -> T,
    {
        self.map_rw_result(
            o,
            |o, arg| Ok::<T, std::convert::Infallible>(read_map(o, arg)),
            |o, arg| Ok::<T, std::convert::Infallible>(write_map(o, arg)),
        )
        .unwrap()
    }

    pub fn map<F, T>(&self, mut f: F) -> GenericInstruction<T>
    where
        F: FnMut(&ArgType) -> T + Clone + Copy,
    {
        let mut g = f.clone();
        self.map_rw(&mut (), |_, a| f(a), |_, b| g(b))
    }

    pub fn reads(&self) -> Vec<&ArgType>
    where
        ArgType: ArgBase,
    {
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
            Self::Phi(_, args) => args.iter().collect(),
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
            Self::Phi(a, _) => Some(a),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            GenericInstruction::Add(..)
            | GenericInstruction::Mul(..)
            | GenericInstruction::LessThan(..)
            | GenericInstruction::Equals(..)
            | GenericInstruction::Assign(..) => 4,

            GenericInstruction::Goto(..) | GenericInstruction::JumpIf(..) => 3,

            GenericInstruction::Input(_)
            | GenericInstruction::Output(_)
            | GenericInstruction::AdjustRelativeBase(_) => 2,

            GenericInstruction::Halt => 1,
            GenericInstruction::Data(v) => v.len(),
            GenericInstruction::Phi(_, _) => panic!("Phi instruction not supported"),
        }
    }
}

impl FatInstruction {
    pub fn parse_fat(input: Input) -> Result<(Input, Op), ParseError> {
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
            1 => FatInstruction::Add(args[0].unwrap(), args[1].unwrap(), args[2].unwrap()),
            2 => FatInstruction::Mul(args[0].unwrap(), args[1].unwrap(), args[2].unwrap()),
            3 => FatInstruction::Input(args[0].unwrap()),
            4 => FatInstruction::Output(args[0].unwrap()),
            5 => FatInstruction::JumpIf(args[0].unwrap(), true, args[1].unwrap()),
            6 => FatInstruction::JumpIf(args[0].unwrap(), false, args[1].unwrap()),
            7 => FatInstruction::LessThan(args[0].unwrap(), args[1].unwrap(), args[2].unwrap()),
            8 => FatInstruction::Equals(args[0].unwrap(), args[1].unwrap(), args[2].unwrap()),
            9 => FatInstruction::AdjustRelativeBase(args[0].unwrap()),
            99 => FatInstruction::Halt,
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
        Self::parse(Input::new(offset, prog)).ok().map(|(_, op)| op)
    }

    fn simplify(self) -> Self {
        match self {
            FatInstruction::Add(
                OpArg {
                    kind: Arg::Value(0),
                    ..
                },
                b,
                a,
            )
            | FatInstruction::Add(
                b,
                OpArg {
                    kind: Arg::Value(0),
                    ..
                },
                a,
            )
            | FatInstruction::Mul(
                OpArg {
                    kind: Arg::Value(1),
                    ..
                },
                b,
                a,
            ) => FatInstruction::Assign(a, b),
            FatInstruction::Mul(
                b,
                OpArg {
                    kind: Arg::Value(1),
                    ..
                },
                a,
            ) => FatInstruction::Assign(a, b),
            FatInstruction::JumpIf(
                OpArg {
                    kind: Arg::Value(c),
                    ..
                },
                cond,
                addr,
            ) if (cond && c != 0) || (!cond && c == 0) => FatInstruction::Goto(addr),
            x => x,
        }
    }

    fn coalesce_data(instructions: &[(usize, Self)], prog: &[i128]) -> Vec<(usize, Self)> {
        let mut instructions = instructions.to_vec();
        for i in 0..instructions.len() - 2 {
            let a = instructions[i].clone();
            let c = instructions[i + 2].clone();
            let b = &mut instructions[i + 1];
            match (a.1, &b.1, c.1) {
                (FatInstruction::Data(_), FatInstruction::Data(_), FatInstruction::Data(_)) => {}
                (FatInstruction::Data(_), _, FatInstruction::Data(_)) => {
                    *b = (b.0, FatInstruction::Data(prog[b.0..c.0].to_vec()));
                }
                _ => {}
            }
        }

        instructions
            .into_iter()
            .coalesce(|(prev_addr, prev_inst), (curr_addr, curr_inst)| {
                match (&prev_inst, &curr_inst) {
                    (FatInstruction::Data(prev_data), FatInstruction::Data(curr_data)) => Ok((
                        prev_addr,
                        FatInstruction::Data(prev_data.iter().chain(curr_data).cloned().collect()),
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
            let instr = match FatInstruction::from_slice(i, &prog[i..]) {
                Some(
                    i @ FatInstruction::AdjustRelativeBase(OpArg {
                        kind: Arg::Value(t),
                        ..
                    }),
                ) if t > 0 => {
                    in_data = false;
                    i
                }
                Some(inst) => {
                    if in_data {
                        FatInstruction::Data(vec![prog[i]])
                    } else {
                        inst
                    }
                }
                None => {
                    in_data = true;
                    FatInstruction::Data(vec![prog[i]])
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
            Self::Phi(a, b) => write!(f, "{} = φ({})", a, b.iter().format(", ")),
        }
    }
}
