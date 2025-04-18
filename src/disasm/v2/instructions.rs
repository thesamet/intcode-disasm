#![deny(unused_attributes)]
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
    #[allow(dead_code)]
    pub fn get_memory(&self) -> Option<i128> {
        match self {
            OperandKind::Memory(value) => Some(*value),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn get_deref(&self) -> Option<usize> {
        match self {
            OperandKind::Deref(offset) => Some(*offset),
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

    /// Returns true if this is a variable operand, not an immediate value
    pub fn is_variable(&self) -> bool {
        !matches!(self, OperandKind::Immediate(_))
    }
}

impl fmt::Display for OperandKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperandKind::Memory(addr) => write!(f, "[{}]", addr),
            OperandKind::Immediate(val) => write!(f, "{}", val),
            OperandKind::RelativeMemory(offset) if *offset == 0 => write!(f, "[R]"),
            OperandKind::RelativeMemory(offset) if *offset > 0 => write!(f, "[R+{}]", offset),
            OperandKind::RelativeMemory(offset) => write!(f, "[R{}]", offset),
            OperandKind::Deref(offset) => write!(f, "[[{}]]", offset),
        }
    }
}

// Operand is a value that is passed as a positional argument to an instruction.
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
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
// *** Define the macro here, often placed before the impl block ***
macro_rules! generate_operand_match {
    // $kind_expr will be &self.kind or &mut self.kind
    // $index will be the index variable
    ($kind_expr:expr, $index:ident) => {
        // The type of reference (&T or &mut T) returned by Some(...)
        // depends on how $kind_expr was borrowed *before* calling the macro.
        match $kind_expr {
            // 3-operand instructions (arg1, arg2, destination)
            InstructionKind::Add(a, b, c) |
            InstructionKind::Mul(a, b, c) |
            InstructionKind::LessThan(a, b, c) |
            InstructionKind::Equals(a, b, c) => match $index {
                0 => Some(a), // arg1
                1 => Some(b), // arg2
                2 => Some(c), // destination
                _ => None,
            },
            // 1-operand instructions (destination)
            InstructionKind::Input(a) => match $index {
                0 => Some(a), // destination
                _ => None,
            },
            // 1-operand instructions (source/value)
            InstructionKind::Output(a) |
            InstructionKind::AdjustRelativeBase(a) => match $index {
                0 => Some(a), // source/value
                _ => None,
            },
            // 2-operand instructions (condition, target)
            InstructionKind::JumpIfTrue(a, b) |
            InstructionKind::JumpIfFalse(a, b) => match $index {
                0 => Some(a), // condition
                1 => Some(b), // target
                _ => None,
            },
            // Synthetic: Goto(target) derives from JumpIfTrue(1, target)
            InstructionKind::Goto(target) => match $index {
                // index 0 would be the constant 1 (not stored), index 1 is target
                1 => Some(target),
                _ => None,
            },
             // Synthetic: Assign(target, source) derives from Add(0, source, target) or Mul(1, source, target)
            InstructionKind::Assign(target, source) => match $index {
                 // index 0 is source, index 1 is constant 0/1 (not stored), index 2 is target
                0 => Some(source), // source operand
                2 => Some(target), // target operand (destination)
                _ => None,
            },
            // No positional operands for Halt or Data
            InstructionKind::Halt | InstructionKind::Data(_) => None,
        }
    };
}

impl<T> InstructionKind<T> {
    /// Gets an immutable reference to the operand at the given *positional index*.
    /// Use `read_positions` and `write_positions` to understand context.
    pub fn operand_at(&self, index: usize) -> Option<&T> {
        // Use the macro, passing an immutable reference to self.kind
        generate_operand_match!(&self, index)
    }

    /// Gets a mutable reference to the operand at the given *positional index*.
    /// Use `read_positions` and `write_positions` to understand context.
    pub fn operand_at_mut(&mut self, index: usize) -> Option<&mut T> {
        // Use the macro, passing a mutable reference to self.kind
        generate_operand_match!(self, index)
    }
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
    pub fn as_i128(&self) -> i128 {
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

impl<T: Into<Operand> + Clone> GenericInstruction<T> {
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
            InstructionKind::Goto(target) => Some(target.clone()),
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
                Some(target.clone())
            }
            _ => None,
        }
    }

    pub fn conditional_jump_condition(&self) -> Option<T> {
        match &self.kind {
            InstructionKind::JumpIfTrue(cond, _) | InstructionKind::JumpIfFalse(cond, _) => {
                Some(cond.clone())
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
            InstructionKind::AdjustRelativeBase(op) => op.clone().into().kind.get_immediate(),
            _ => None,
        }
    }

    pub fn as_assignment(&self) -> Option<Assignment<T>> {
        match &self.kind {
            InstructionKind::Assign(target, source) => Some(Assignment {
                target: target.clone(),
                source: source.clone(),
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
            _ => return Err(ParseError::InvalidOpcode(opcode_val)),
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
                    offset: offset + i + 1_usize,
                    debug_marker,
                })
            })
            .collect::<Result<_, _>>()?;

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
            InstructionKind::Goto(_) => vec![0, 1],
            InstructionKind::Assign(_, _) => vec![0, 1],
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
            InstructionKind::Assign(_, _) => vec![2],
        }
    }

    /// Maps operands based on read/write context, propagating the first error encountered.
    pub fn map_rw_result<C, R, W, S, E>(
        &self,
        context: &mut C,
        map_read: &mut R,
        map_write: &mut W,
    ) -> Result<GenericInstruction<S>, E>
    where
        R: FnMut(&mut C, &T) -> Result<S, E>,
        W: FnMut(&mut C, &T) -> Result<S, E>,
    {
        let kind_result = match &self.kind {
            InstructionKind::Add(a, b, c) => Ok(InstructionKind::Add(
                map_read(context, a)?,
                map_read(context, b)?,
                map_write(context, c)?,
            )),
            InstructionKind::Mul(a, b, c) => Ok(InstructionKind::Mul(
                map_read(context, a)?,
                map_read(context, b)?,
                map_write(context, c)?,
            )),
            InstructionKind::Input(a) => Ok(InstructionKind::Input(map_write(context, a)?)),
            InstructionKind::Output(a) => Ok(InstructionKind::Output(map_read(context, a)?)),
            InstructionKind::JumpIfTrue(a, b) => Ok(InstructionKind::JumpIfTrue(
                map_read(context, a)?,
                map_read(context, b)?,
            )),
            InstructionKind::JumpIfFalse(a, b) => Ok(InstructionKind::JumpIfFalse(
                map_read(context, a)?,
                map_read(context, b)?,
            )),
            InstructionKind::LessThan(a, b, c) => Ok(InstructionKind::LessThan(
                map_read(context, a)?,
                map_read(context, b)?,
                map_write(context, c)?,
            )),
            InstructionKind::Equals(a, b, c) => Ok(InstructionKind::Equals(
                map_read(context, a)?,
                map_read(context, b)?,
                map_write(context, c)?,
            )),
            InstructionKind::AdjustRelativeBase(a) => {
                Ok(InstructionKind::AdjustRelativeBase(map_read(context, a)?))
            }
            InstructionKind::Halt => Ok(InstructionKind::Halt),
            InstructionKind::Data(values) => Ok(InstructionKind::Data(values.clone())),
            InstructionKind::Goto(a) => Ok(InstructionKind::Goto(map_read(context, a)?)),
            InstructionKind::Assign(a, b) => Ok(InstructionKind::Assign(
                map_write(context, a)?,
                map_read(context, b)?,
            )),
        };

        kind_result.map(|kind| GenericInstruction {
            id: self.id,
            span: self.span,
            kind,
        })
    }

    /// Maps operands based on read/write context using infallible closures.
    /// Panics if the closures panic.
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
        // Wrap the infallible closures to return Result<_, Infallible>
        let mut map_read_res = |ctx: &mut C, arg: &T| -> Result<S, core::convert::Infallible> {
            Ok(map_read(ctx, arg))
        };
        let mut map_write_res = |ctx: &mut C, arg: &T| -> Result<S, core::convert::Infallible> {
            Ok(map_write(ctx, arg))
        };

        // Call map_rw_result and unwrap (safe because error type is Infallible)
        self.map_rw_result(context, &mut map_read_res, &mut map_write_res)
            .unwrap()
    }
    /// Returns a list of operands that are read by this instruction
    pub fn reads(&self) -> Vec<T> {
        let read_positions = self.read_positions();

        read_positions
            .iter()
            .filter_map(|&pos| {
                let op = self.kind.operand_at(pos)?;

                // Only include memory locations, not immediate values
                if matches!(
                    op.clone().into().kind,
                    OperandKind::Memory(_) | OperandKind::RelativeMemory(_) | OperandKind::Deref(_)
                ) {
                    Some(op.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns the operand that is written to by this instruction, if any
    pub fn writes(&self) -> Option<T> {
        let write_positions = self.write_positions();

        if write_positions.is_empty() {
            return None;
        };
        let Some(op) = self.kind.operand_at(write_positions[0]) else {
            panic!("No operand at write position {}", write_positions[0]);
        };

        Some(op.clone())
    }
}

// Helper function to simplify certain instruction patterns
pub fn simplify_instruction<T: Into<Operand> + Clone>(
    kind: InstructionKind<T>,
) -> InstructionKind<T> {
    match kind.clone() {
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
            if let OperandKind::Immediate(0) = a.clone().into().kind {
                return InstructionKind::Assign(target, b);
            }
            if let OperandKind::Immediate(0) = b.into().kind {
                return InstructionKind::Assign(target, a);
            }
            kind
        }
        InstructionKind::Mul(a, b, target) => {
            if let OperandKind::Immediate(1) = a.clone().into().kind {
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
