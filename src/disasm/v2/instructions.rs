use core::fmt;
use itertools::Itertools;
use thiserror::Error;

use super::{id_types::define_id_type, Span};

// Debug information is now stored in the operands themselves via debug_marker

define_id_type!(InstructionId);

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub enum OperandKind {
    Memory(i128),
    Immediate(i128),
    RelativeMemory(i128),
    Deref(usize),
}

impl OperandKind {
    pub fn memory(value: i128) -> Self {
        OperandKind::Memory(value)
    }

    pub fn immediate(value: i128) -> Self {
        OperandKind::Immediate(value)
    }

    pub fn relative_memory(offset: i128) -> Self {
        OperandKind::RelativeMemory(offset)
    }

    pub fn deref(offset: usize) -> Self {
        OperandKind::Deref(offset)
    }

    pub fn get_memory(&self) -> Option<i128> {
        match self {
            OperandKind::Memory(value) => Some(*value),
            _ => None,
        }
    }

    pub fn get_immediate(&self) -> Option<i128> {
        match self {
            OperandKind::Immediate(value) => Some(*value),
            _ => None,
        }
    }

    pub fn get_relative_memory(&self) -> Option<i128> {
        match self {
            OperandKind::RelativeMemory(value) => Some(*value),
            _ => None,
        }
    }

    pub fn is_positive_relative_memory(&self) -> bool {
        matches!(self, OperandKind::RelativeMemory(n) if *n > 0)
    }

    pub fn is_negative_relative_memory(&self) -> bool {
        matches!(self, OperandKind::RelativeMemory(n) if *n < 0)
    }

    pub fn get_deref(&self) -> Option<usize> {
        match self {
            OperandKind::Deref(offset) => Some(*offset),
            _ => None,
        }
    }

    /// Returns true if this is a variable operand, not an immediate value
    pub fn is_variable(&self) -> bool {
        !matches!(self, OperandKind::Immediate(_))
    }

    /// Returns this operand if it's a variable (not an immediate value)
    /// Used for SSA conversion
    pub fn as_variable(&self) -> Option<Self> {
        if self.is_variable() {
            Some(*self)
        } else {
            None
        }
    }
}

impl fmt::Display for OperandKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperandKind::Memory(addr) => write!(f, "[{}]", addr),
            OperandKind::Immediate(val) => write!(f, "{}", val),
            OperandKind::RelativeMemory(offset) => {
                if *offset == 0 {
                    write!(f, "[R]")
                } else if *offset > 0 {
                    write!(f, "[R+{}]", offset)
                } else {
                    // Handles negative offsets, e.g., [R-50]
                    write!(f, "[R{}]", offset)
                }
            }
            OperandKind::Deref(offset) => write!(f, "[[{}]]", offset),
        }
    }
}

// Operand is a value that is passed as a positional argument to an instruction.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Operand {
    pub kind: OperandKind,
    pub offset: usize,
    pub debug_marker: Option<char>,
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(marker) = self.debug_marker {
            write!(f, "'{}{}", marker, self.kind)
        } else {
            write!(f, "{}", self.kind)
        }
    }
}

/// An enumeration of all instruction types, with their operands
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum InstructionKind<T> {
    Add(T, T, T),
    Mul(T, T, T),
    Input(T),
    Output(T),
    JumpIfTrue(T, T),
    JumpIfFalse(T, T),
    LessThan(T, T, T),
    Equals(T, T, T),
    AdjustRelativeBase(T),
    Data(Vec<i128>),
    Halt,
    // Synthetic instructions
    Goto(T),
    Assign(T, T),
}

/// A generic instruction that can use different operand types
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct GenericInstruction<T> {
    /// The instruction ID
    pub id: InstructionId,
    /// The span of the instruction in the image
    pub span: Span,
    /// The instruction kind with its operands
    pub kind: InstructionKind<T>,
}

pub type Instruction = GenericInstruction<Operand>;

// Legacy enum for backward compatibility, to be phased out
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Opcode {
    Add,
    Mul,
    Input,
    Output,
    JumpIfTrue,
    JumpIfFalse,
    LessThan,
    Equals,
    AdjustRelativeBase,
    Halt,
}

impl Opcode {
    fn from_i128(value: i128) -> Result<Opcode, ParseError> {
        match value {
            1 => Ok(Opcode::Add),
            2 => Ok(Opcode::Mul),
            3 => Ok(Opcode::Input),
            4 => Ok(Opcode::Output),
            5 => Ok(Opcode::JumpIfTrue),
            6 => Ok(Opcode::JumpIfFalse),
            7 => Ok(Opcode::LessThan),
            8 => Ok(Opcode::Equals),
            9 => Ok(Opcode::AdjustRelativeBase),
            99 => Ok(Opcode::Halt),
            _ => Err(ParseError::InvalidOpcode(value)),
        }
    }

    fn as_i128(&self) -> i128 {
        match self {
            Opcode::Add => 1,
            Opcode::Mul => 2,
            Opcode::Input => 3,
            Opcode::Output => 4,
            Opcode::JumpIfTrue => 5,
            Opcode::JumpIfFalse => 6,
            Opcode::LessThan => 7,
            Opcode::Equals => 8,
            Opcode::AdjustRelativeBase => 9,
            Opcode::Halt => 99,
        }
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid opcode: {0}")]
    InvalidOpcode(i128),

    #[error("Unexpected end of file at {0}")]
    EndOfFile(usize),

    #[error("Invalid mode: {0}")]
    InvalidMode(i128),

    #[error("Invalid stack adjustment at offset {0}")]
    InvalidStackAdjustment(usize),

    #[error("Unexpected instruction after R adjustment")]
    UnexpectedOpAfterAdjustment,

    #[error("Instruction does not match the expected pattern")]
    NoMatch,
}

#[derive(Debug, Clone)]
pub struct Assignment<T> {
    pub target: T,
    pub source: T,
}

impl<T: Into<Operand> + Copy + Clone> GenericInstruction<T> {
    pub fn opcode(&self) -> Opcode {
        match &self.kind {
            InstructionKind::Add(_, _, _) => Opcode::Add,
            InstructionKind::Mul(_, _, _) => Opcode::Mul,
            InstructionKind::Input(_) => Opcode::Input,
            InstructionKind::Output(_) => Opcode::Output,
            InstructionKind::JumpIfTrue(_, _) => Opcode::JumpIfTrue,
            InstructionKind::JumpIfFalse(_, _) => Opcode::JumpIfFalse,
            InstructionKind::LessThan(_, _, _) => Opcode::LessThan,
            InstructionKind::Equals(_, _, _) => Opcode::Equals,
            InstructionKind::AdjustRelativeBase(_) => Opcode::AdjustRelativeBase,
            InstructionKind::Halt => Opcode::Halt,
            InstructionKind::Data(_) => Opcode::Add, // Default to Add for backward compatibility
            InstructionKind::Goto(_) => Opcode::JumpIfTrue,
            InstructionKind::Assign(_, _) => Opcode::Add,
        }
    }

    pub fn operands(&self) -> Vec<T> {
        match &self.kind {
            InstructionKind::Add(a, b, c) => vec![*a, *b, *c],
            InstructionKind::Mul(a, b, c) => vec![*a, *b, *c],
            InstructionKind::Input(a) => vec![*a],
            InstructionKind::Output(a) => vec![*a],
            InstructionKind::JumpIfTrue(a, b) => vec![*a, *b],
            InstructionKind::JumpIfFalse(a, b) => vec![*a, *b],
            InstructionKind::LessThan(a, b, c) => vec![*a, *b, *c],
            InstructionKind::Equals(a, b, c) => vec![*a, *b, *c],
            InstructionKind::AdjustRelativeBase(a) => vec![*a],
            InstructionKind::Halt => vec![],
            InstructionKind::Data(_) => vec![],
            InstructionKind::Goto(target) => {
                vec![*target]
            }
            InstructionKind::Assign(target, source) => {
                // Create a synthetic operation: target = source + 0
                vec![*target, *source]
            }
        }
    }

    pub fn immediate_arg(&self, index: usize) -> Option<i128> {
        let operands = self.operands();
        if index < operands.len() {
            operands[index].into().kind.get_immediate()
        } else {
            None
        }
    }

    pub fn is_jump(&self) -> bool {
        matches!(
            self.kind,
            InstructionKind::JumpIfTrue(_, _)
                | InstructionKind::JumpIfFalse(_, _)
                | InstructionKind::Goto(_)
        )
    }

    pub fn goto_address(&self) -> Option<T> {
        match &self.kind {
            InstructionKind::Goto(target) => Some(*target),
            _ => None,
        }
    }

    pub fn is_halt(&self) -> bool {
        matches!(self.kind, InstructionKind::Halt)
    }

    pub fn is_goto(&self) -> bool {
        matches!(self.kind, InstructionKind::Goto(_))
    }

    pub fn immediate_goto(&self) -> Option<usize> {
        self.goto_address()
            .and_then(|a| a.into().kind.get_immediate().map(|a| a as usize))
    }

    pub fn is_conditional_jump(&self) -> bool {
        matches!(
            self.kind,
            InstructionKind::JumpIfTrue(_, _) | InstructionKind::JumpIfFalse(_, _)
        )
    }

    pub fn conditional_jump_address(&self) -> Option<T> {
        match &self.kind {
            InstructionKind::JumpIfTrue(_, target) | InstructionKind::JumpIfFalse(_, target) => {
                Some(*target)
            }
            _ => None,
        }
    }

    pub fn conditional_jump_condition(&self) -> Option<T> {
        match &self.kind {
            InstructionKind::JumpIfTrue(cond, _) | InstructionKind::JumpIfFalse(cond, _) => {
                Some(*cond)
            }
            _ => None,
        }
    }

    pub fn conditional_jump_immediate_address(&self) -> Option<usize> {
        self.conditional_jump_address()
            .and_then(|a| a.into().kind.get_immediate().map(|a| a as usize))
    }

    pub fn relative_base_adjustment(&self) -> Option<i128> {
        match &self.kind {
            InstructionKind::AdjustRelativeBase(op) => (*op).into().kind.get_immediate(),
            _ => None,
        }
    }

    pub fn as_assignment(&self) -> Option<Assignment<T>> {
        match &self.kind {
            InstructionKind::Assign(target, source) => Some(Assignment {
                target: *target,
                source: *source,
            }),
            _ => None,
        }
    }

    pub fn parse(input: &[i128], offset: usize) -> Result<Instruction, ParseError> {
        if offset >= input.len() {
            return Err(ParseError::EndOfFile(offset));
        }
        let opcode_val = input[offset];
        let (opcode, operand_count) = match opcode_val % 100 {
            1 => (Opcode::Add, 3),
            2 => (Opcode::Mul, 3),
            3 => (Opcode::Input, 1),
            4 => (Opcode::Output, 1),
            5 => (Opcode::JumpIfTrue, 2),
            6 => (Opcode::JumpIfFalse, 2),
            7 => (Opcode::LessThan, 3),
            8 => (Opcode::Equals, 3),
            9 => (Opcode::AdjustRelativeBase, 1),
            99 => (Opcode::Halt, 0),
            _ => return Err(ParseError::InvalidOpcode(opcode_val as i128)),
        };

        if offset + operand_count >= input.len() {
            return Err(ParseError::EndOfFile(offset));
        }

        let operands: Vec<Operand> = (0..operand_count)
            .map(|i| -> Result<Operand, ParseError> {
                let kind = match input[offset] / 10_i128.pow(i as u32 + 2) % 10 {
                    0 => {
                        if input[offset + i + 1] == 0 {
                            Ok(OperandKind::Deref(offset + i + 1))
                        } else {
                            Ok(OperandKind::Memory(input[offset + i + 1]))
                        }
                    }
                    1 => Ok(OperandKind::Immediate(input[offset + i + 1])),
                    2 => Ok(OperandKind::RelativeMemory(input[offset + i + 1])),
                    m => Err(ParseError::InvalidMode(m)),
                }?;
                let debug_marker = match ((opcode_val / 100000) >> (8usize * i)) & 0xff {
                    0 => None,
                    x => Some((x as u8) as char),
                };
                Ok(Operand {
                    kind,
                    offset: offset + i + 1 as usize,
                    debug_marker,
                })
            })
            .collect::<Result<_, _>>()?;

        //
        // Create the instruction kind based on the opcode
        let kind = match opcode {
            Opcode::Add => InstructionKind::Add(operands[0], operands[1], operands[2]),
            Opcode::Mul => InstructionKind::Mul(operands[0], operands[1], operands[2]),
            Opcode::Input => InstructionKind::Input(operands[0]),
            Opcode::Output => InstructionKind::Output(operands[0]),
            Opcode::JumpIfTrue => InstructionKind::JumpIfTrue(operands[0], operands[1]),
            Opcode::JumpIfFalse => InstructionKind::JumpIfFalse(operands[0], operands[1]),
            Opcode::LessThan => InstructionKind::LessThan(operands[0], operands[1], operands[2]),
            Opcode::Equals => InstructionKind::Equals(operands[0], operands[1], operands[2]),
            Opcode::AdjustRelativeBase => InstructionKind::AdjustRelativeBase(operands[0]),
            Opcode::Halt => InstructionKind::Halt,
        };

        let instruction = Instruction {
            id: InstructionId::from(offset),
            span: Span::new(offset, offset + operand_count + 1),
            kind: simplify_instruction(kind),
        };

        Ok(instruction)
    }

    pub fn read_positions(&self) -> Vec<usize> {
        match &self.kind {
            InstructionKind::Add(_, _, _)
            | InstructionKind::Mul(_, _, _)
            | InstructionKind::LessThan(_, _, _)
            | InstructionKind::Equals(_, _, _) => vec![0, 1],
            InstructionKind::Input(_) => vec![],
            InstructionKind::Output(_) | InstructionKind::AdjustRelativeBase(_) => vec![0],
            InstructionKind::JumpIfTrue(_, _) | InstructionKind::JumpIfFalse(_, _) => vec![0, 1],
            InstructionKind::Halt => vec![],
            InstructionKind::Data(_) => vec![],
            InstructionKind::Goto(_) => vec![0],
            InstructionKind::Assign(_, _) => vec![1],
        }
    }

    pub fn write_positions(&self) -> Vec<usize> {
        match &self.kind {
            InstructionKind::Add(_, _, _)
            | InstructionKind::Mul(_, _, _)
            | InstructionKind::LessThan(_, _, _)
            | InstructionKind::Equals(_, _, _) => vec![2],
            InstructionKind::Input(_) => vec![0],
            InstructionKind::Output(_)
            | InstructionKind::AdjustRelativeBase(_)
            | InstructionKind::JumpIfTrue(_, _)
            | InstructionKind::JumpIfFalse(_, _)
            | InstructionKind::Halt
            | InstructionKind::Data(_)
            | InstructionKind::Goto(_) => vec![],
            InstructionKind::Assign(_, _) => vec![0],
        }
    }

    pub fn map_rw<C, R, W, S>(
        &self,
        context: &mut C,
        map_read: &mut R,
        map_write: &mut W,
    ) -> GenericInstruction<S>
    where
        R: FnMut(&mut C, &T) -> S,
        W: FnMut(&mut C, &T) -> S,
    {
        let kind = match &self.kind {
            InstructionKind::Add(a, b, c) => InstructionKind::Add(
                map_read(context, a),
                map_read(context, b),
                map_write(context, c),
            ),
            InstructionKind::Mul(a, b, c) => InstructionKind::Mul(
                map_read(context, a),
                map_read(context, b),
                map_write(context, c),
            ),
            InstructionKind::Input(a) => InstructionKind::Input(map_write(context, a)),
            InstructionKind::Output(a) => InstructionKind::Output(map_read(context, a)),
            InstructionKind::JumpIfTrue(a, b) => {
                InstructionKind::JumpIfTrue(map_read(context, a), map_read(context, b))
            }
            InstructionKind::JumpIfFalse(a, b) => {
                InstructionKind::JumpIfFalse(map_read(context, a), map_read(context, b))
            }
            InstructionKind::LessThan(a, b, c) => InstructionKind::LessThan(
                map_read(context, a),
                map_read(context, b),
                map_write(context, c),
            ),
            InstructionKind::Equals(a, b, c) => InstructionKind::Equals(
                map_read(context, a),
                map_read(context, b),
                map_write(context, c),
            ),
            InstructionKind::AdjustRelativeBase(a) => {
                InstructionKind::AdjustRelativeBase(map_read(context, a))
            }
            InstructionKind::Halt => InstructionKind::Halt,
            InstructionKind::Data(values) => InstructionKind::Data(values.clone()),
            InstructionKind::Goto(a) => InstructionKind::Goto(map_read(context, a)),
            InstructionKind::Assign(a, b) => {
                InstructionKind::Assign(map_write(context, a), map_read(context, b))
            }
        };

        GenericInstruction {
            id: self.id,
            span: self.span,
            kind,
        }
    }

    /// Returns a list of operands that are read by this instruction
    pub fn reads(&self) -> Vec<T> {
        let operands = self.operands();
        let read_positions = self.read_positions();

        read_positions
            .iter()
            .filter_map(|&pos| {
                if pos < operands.len() {
                    let op = operands[pos];
                    // Only include memory locations, not immediate values
                    if matches!(
                        op.into().kind,
                        OperandKind::Memory(_) | OperandKind::RelativeMemory(_)
                    ) {
                        Some(op)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns the operand that is written to by this instruction, if any
    pub fn writes(&self) -> Option<T> {
        let operands = self.operands();
        let write_positions = self.write_positions();

        if !write_positions.is_empty() && write_positions[0] < operands.len() {
            let op = operands[write_positions[0]];
            // Only include memory locations
            if matches!(
                op.into().kind,
                OperandKind::Memory(_) | OperandKind::RelativeMemory(_) | OperandKind::Deref(_)
            ) {
                Some(op)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn parse_program(prog: &[i128]) -> Vec<(usize, Self)>
    where
        T: From<Operand> + Copy,
    {
        let mut instructions = Vec::new();
        let mut i = 0;
        let mut in_data = false;

        while i < prog.len() {
            if in_data {
                // If we're in a data section, add as Data
                let data_instruction = GenericInstruction {
                    id: InstructionId::from(i),
                    span: Span::new(i, i + 1),
                    kind: InstructionKind::Data(vec![prog[i]]),
                };
                instructions.push((i, data_instruction));
                i += 1;
                continue;
            }

            match Self::parse(prog, i) {
                Ok(instruction) => {
                    let size = match &instruction.kind {
                        InstructionKind::Add(_, _, _)
                        | InstructionKind::Mul(_, _, _)
                        | InstructionKind::LessThan(_, _, _)
                        | InstructionKind::Equals(_, _, _) => 4,
                        InstructionKind::JumpIfTrue(_, _) | InstructionKind::JumpIfFalse(_, _) => 3,
                        InstructionKind::Input(_)
                        | InstructionKind::Output(_)
                        | InstructionKind::AdjustRelativeBase(_) => 2,
                        InstructionKind::Halt => 1,
                        InstructionKind::Data(values) => values.len(),
                        InstructionKind::Goto(_) => 3,
                        InstructionKind::Assign(_, _) => 4,
                    };

                    // Check if we're entering a data section
                    if let InstructionKind::AdjustRelativeBase(op) = &instruction.kind {
                        if let OperandKind::Immediate(t) = op.kind {
                            if t > 0 {
                                in_data = false;
                            }
                        }
                    }

                    // Convert to the target type
                    let converted_instruction = GenericInstruction {
                        id: instruction.id,
                        span: instruction.span,
                        kind: convert_instruction_kind(instruction.kind),
                    };

                    instructions.push((i, converted_instruction));
                    i += size;
                }
                Err(_) => {
                    // If parsing fails, consider it as data
                    in_data = true;
                    let data_instruction = GenericInstruction {
                        id: InstructionId::from(i),
                        span: Span::new(i, i + 1),
                        kind: InstructionKind::Data(vec![prog[i]]),
                    };
                    instructions.push((i, data_instruction));
                    i += 1;
                }
            }
        }

        // Coalesce adjacent data instructions
        coalesce_data_instructions(instructions, prog)
    }
}

// Helper function to simplify certain instruction patterns
fn simplify_instruction<T: Into<Operand>>(kind: InstructionKind<T>) -> InstructionKind<T>
where
    T: Copy,
{
    match kind {
        InstructionKind::JumpIfTrue(cond, target) => {
            if let OperandKind::Immediate(val) = cond.into().kind {
                if val != 0 {
                    return InstructionKind::Goto(target);
                }
            }
            kind
        }
        InstructionKind::JumpIfFalse(cond, target) => {
            if let OperandKind::Immediate(val) = cond.into().kind {
                if val == 0 {
                    return InstructionKind::Goto(target);
                }
            }
            kind
        }
        InstructionKind::Add(a, b, target) => {
            if let OperandKind::Immediate(0) = a.into().kind {
                return InstructionKind::Assign(target, b);
            }
            if let OperandKind::Immediate(0) = b.into().kind {
                return InstructionKind::Assign(target, a);
            }
            kind
        }
        InstructionKind::Mul(a, b, target) => {
            if let OperandKind::Immediate(1) = a.into().kind {
                return InstructionKind::Assign(target, b);
            }
            if let OperandKind::Immediate(1) = b.into().kind {
                return InstructionKind::Assign(target, a);
            }
            kind
        }
        _ => kind,
    }
}

// Helper function to convert instruction kind from one operand type to another
fn convert_instruction_kind<T, U>(kind: InstructionKind<T>) -> InstructionKind<U>
where
    T: Into<Operand> + Copy,
    U: From<Operand> + Copy,
{
    match kind {
        InstructionKind::Add(a, b, c) => {
            let a_op: Operand = a.into();
            let b_op: Operand = b.into();
            let c_op: Operand = c.into();
            InstructionKind::Add(U::from(a_op), U::from(b_op), U::from(c_op))
        }
        InstructionKind::Mul(a, b, c) => {
            let a_op: Operand = a.into();
            let b_op: Operand = b.into();
            let c_op: Operand = c.into();
            InstructionKind::Mul(U::from(a_op), U::from(b_op), U::from(c_op))
        }
        InstructionKind::Input(a) => {
            let a_op: Operand = a.into();
            InstructionKind::Input(U::from(a_op))
        }
        InstructionKind::Output(a) => {
            let a_op: Operand = a.into();
            InstructionKind::Output(U::from(a_op))
        }
        InstructionKind::JumpIfTrue(a, b) => {
            let a_op: Operand = a.into();
            let b_op: Operand = b.into();
            InstructionKind::JumpIfTrue(U::from(a_op), U::from(b_op))
        }
        InstructionKind::JumpIfFalse(a, b) => {
            let a_op: Operand = a.into();
            let b_op: Operand = b.into();
            InstructionKind::JumpIfFalse(U::from(a_op), U::from(b_op))
        }
        InstructionKind::LessThan(a, b, c) => {
            let a_op: Operand = a.into();
            let b_op: Operand = b.into();
            let c_op: Operand = c.into();
            InstructionKind::LessThan(U::from(a_op), U::from(b_op), U::from(c_op))
        }
        InstructionKind::Equals(a, b, c) => {
            let a_op: Operand = a.into();
            let b_op: Operand = b.into();
            let c_op: Operand = c.into();
            InstructionKind::Equals(U::from(a_op), U::from(b_op), U::from(c_op))
        }
        InstructionKind::AdjustRelativeBase(a) => {
            let a_op: Operand = a.into();
            InstructionKind::AdjustRelativeBase(U::from(a_op))
        }
        InstructionKind::Halt => InstructionKind::Halt,
        InstructionKind::Data(values) => InstructionKind::Data(values),
        InstructionKind::Goto(a) => {
            let a_op: Operand = a.into();
            InstructionKind::Goto(U::from(a_op))
        }
        InstructionKind::Assign(a, b) => {
            let a_op: Operand = a.into();
            let b_op: Operand = b.into();
            InstructionKind::Assign(U::from(a_op), U::from(b_op))
        }
    }
}

// Helper function to coalesce adjacent data instructions
fn coalesce_data_instructions<T>(
    instructions: Vec<(usize, GenericInstruction<T>)>,
    prog: &[i128],
) -> Vec<(usize, GenericInstruction<T>)>
where
    T: Copy,
{
    instructions
        .into_iter()
        .coalesce(|(addr1, inst1), (addr2, inst2)| {
            // Only coalesce adjacent data instructions
            match (&inst1.kind, &inst2.kind) {
                (InstructionKind::Data(_), InstructionKind::Data(_)) if addr1 + 1 == addr2 => {
                    // Create a new data instruction that spans both
                    let end_addr = addr2 + 1;
                    Ok((
                        addr1,
                        GenericInstruction {
                            id: inst1.id,
                            span: Span::new(addr1, end_addr),
                            kind: InstructionKind::Data(prog[addr1..end_addr].to_vec()),
                        },
                    ))
                }
                _ => Err(((addr1, inst1), (addr2, inst2))),
            }
        })
        .collect()
}

impl<T: fmt::Display> fmt::Display for GenericInstruction<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            InstructionKind::Add(a, b, c) => write!(f, "{} = {} + {}", c, a, b),
            InstructionKind::Mul(a, b, c) => write!(f, "{} = {} * {}", c, a, b),
            InstructionKind::Input(a) => write!(f, "{} = input()", a),
            InstructionKind::Output(a) => write!(f, "output({})", a),
            InstructionKind::JumpIfTrue(a, b) => write!(f, "if {} goto {}", a, b),
            InstructionKind::JumpIfFalse(a, b) => write!(f, "if !{} goto {}", a, b),
            InstructionKind::LessThan(a, b, c) => write!(f, "{} = {} < {}", c, a, b),
            InstructionKind::Equals(a, b, c) => write!(f, "{} = {} == {}", c, a, b),
            InstructionKind::AdjustRelativeBase(a) => write!(f, "R += {}", a),
            InstructionKind::Halt => write!(f, "halt"),
            InstructionKind::Data(values) => write!(f, "DATA {}", values.iter().format(", ")),
            InstructionKind::Goto(a) => write!(f, "goto {}", a),
            InstructionKind::Assign(a, b) => write!(f, "{} = {}", a, b),
        }
    }
}
