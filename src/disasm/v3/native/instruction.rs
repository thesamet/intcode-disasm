use super::operand::{Operand, OperandKind};
use crate::disasm::v3::{common::Span, id_types::NativeInstructionId};
use core::fmt;
use itertools::Itertools;
use thiserror::Error;

/// An enumeration of all instruction types, with their operands
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum NativeInstructionKind<T> {
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
            NativeInstructionKind::Add(a, b, c) |
            NativeInstructionKind::Mul(a, b, c) |
            NativeInstructionKind::LessThan(a, b, c) |
            NativeInstructionKind::Equals(a, b, c) => match $index {
                0 => Some(a), // arg1
                1 => Some(b), // arg2
                2 => Some(c), // destination
                _ => None,
            },
            // 1-operand instructions (destination)
            NativeInstructionKind::Input(a) => match $index {
                0 => Some(a), // destination
                _ => None,
            },
            // 1-operand instructions (source/value)
            NativeInstructionKind::Output(a) |
            NativeInstructionKind::AdjustRelativeBase(a) => match $index {
                0 => Some(a), // source/value
                _ => None,
            },
            // 2-operand instructions (condition, target)
            NativeInstructionKind::JumpIfTrue(a, b) |
            NativeInstructionKind::JumpIfFalse(a, b) => match $index {
                0 => Some(a), // condition
                1 => Some(b), // target
                _ => None,
            },
            // Synthetic: Goto(target) derives from JumpIfTrue(1, target)
            NativeInstructionKind::Goto(target) => match $index {
                // index 0 would be the constant 1 (not stored), index 1 is target
                1 => Some(target),
                _ => None,
            },
             // Synthetic: Assign(target, source) derives from Add(0, source, target) or Mul(1, source, target)
            NativeInstructionKind::Assign(target, source) => match $index {
                 // index 0 is source, index 1 is constant 0/1 (not stored), index 2 is target
                0 => Some(source), // source operand
                2 => Some(target), // target operand (destination)
                _ => None,
            },
            // No positional operands for Halt or Data
            NativeInstructionKind::Halt | NativeInstructionKind::Data(_) => None,
        }
    };
}

impl<T> NativeInstructionKind<T> {
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
pub struct GenericNativeInstruction<T> {
    /// The instruction ID
    pub id: NativeInstructionId,
    /// The span of the instruction in the image
    pub span: Span,
    /// The instruction kind with its operands
    pub kind: NativeInstructionKind<T>,
}

pub type NativeInstruction = GenericNativeInstruction<Operand>;

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

impl<T: Into<Operand> + Clone> GenericNativeInstruction<T> {
    pub fn opcode(&self) -> Opcode {
        match &self.kind {
            NativeInstructionKind::Add(_, _, _) => Opcode::Add,
            NativeInstructionKind::Mul(_, _, _) => Opcode::Mul,
            NativeInstructionKind::Input(_) => Opcode::Input,
            NativeInstructionKind::Output(_) => Opcode::Output,
            NativeInstructionKind::JumpIfTrue(_, _) => Opcode::JumpIfTrue,
            NativeInstructionKind::JumpIfFalse(_, _) => Opcode::JumpIfFalse,
            NativeInstructionKind::LessThan(_, _, _) => Opcode::LessThan,
            NativeInstructionKind::Equals(_, _, _) => Opcode::Equals,
            NativeInstructionKind::AdjustRelativeBase(_) => Opcode::AdjustRelativeBase,
            NativeInstructionKind::Halt => Opcode::Halt,
            NativeInstructionKind::Data(_) => Opcode::Add, // Default to Add for backward compatibility
            NativeInstructionKind::Goto(_) => Opcode::JumpIfTrue,
            NativeInstructionKind::Assign(_, _) => Opcode::Add,
        }
    }

    pub fn is_jump(&self) -> bool {
        matches!(
            self.kind,
            NativeInstructionKind::JumpIfTrue(_, _)
                | NativeInstructionKind::JumpIfFalse(_, _)
                | NativeInstructionKind::Goto(_)
        )
    }

    pub fn goto_address(&self) -> Option<T> {
        match &self.kind {
            NativeInstructionKind::Goto(target) => Some(target.clone()),
            _ => None,
        }
    }

    pub fn is_halt(&self) -> bool {
        matches!(self.kind, NativeInstructionKind::Halt)
    }

    pub fn is_goto(&self) -> bool {
        matches!(self.kind, NativeInstructionKind::Goto(_))
    }

    pub fn immediate_goto(&self) -> Option<usize> {
        self.goto_address()
            .and_then(|a| a.into().kind.get_immediate().map(|a| a as usize))
    }

    pub fn is_conditional_jump(&self) -> bool {
        matches!(
            self.kind,
            NativeInstructionKind::JumpIfTrue(_, _) | NativeInstructionKind::JumpIfFalse(_, _)
        )
    }

    pub fn conditional_jump_address(&self) -> Option<T> {
        match &self.kind {
            NativeInstructionKind::JumpIfTrue(_, target)
            | NativeInstructionKind::JumpIfFalse(_, target) => Some(target.clone()),
            _ => None,
        }
    }

    pub fn conditional_jump_condition(&self) -> Option<T> {
        match &self.kind {
            NativeInstructionKind::JumpIfTrue(cond, _)
            | NativeInstructionKind::JumpIfFalse(cond, _) => Some(cond.clone()),
            _ => None,
        }
    }

    pub fn conditional_jump_immediate_address(&self) -> Option<usize> {
        self.conditional_jump_address()
            .and_then(|a| a.into().kind.get_immediate().map(|a| a as usize))
    }

    pub fn relative_base_adjustment(&self) -> Option<i128> {
        match &self.kind {
            NativeInstructionKind::AdjustRelativeBase(op) => op.clone().into().kind.get_immediate(),
            _ => None,
        }
    }

    pub fn as_assignment(&self) -> Option<Assignment<T>> {
        match &self.kind {
            NativeInstructionKind::Assign(target, source) => Some(Assignment {
                target: target.clone(),
                source: source.clone(),
            }),
            _ => None,
        }
    }

    pub fn parse(input: &[i128], offset: usize) -> Result<NativeInstruction, ParseError> {
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
                            Ok(OperandKind::Memory(input[offset + i + 1] as usize))
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
            Opcode::Add => NativeInstructionKind::Add(operands[0], operands[1], operands[2]),
            Opcode::Mul => NativeInstructionKind::Mul(operands[0], operands[1], operands[2]),
            Opcode::Input => NativeInstructionKind::Input(operands[0]),
            Opcode::Output => NativeInstructionKind::Output(operands[0]),
            Opcode::JumpIfTrue => NativeInstructionKind::JumpIfTrue(operands[0], operands[1]),
            Opcode::JumpIfFalse => NativeInstructionKind::JumpIfFalse(operands[0], operands[1]),
            Opcode::LessThan => {
                NativeInstructionKind::LessThan(operands[0], operands[1], operands[2])
            }
            Opcode::Equals => NativeInstructionKind::Equals(operands[0], operands[1], operands[2]),
            Opcode::AdjustRelativeBase => NativeInstructionKind::AdjustRelativeBase(operands[0]),
            Opcode::Halt => NativeInstructionKind::Halt,
        };

        let instruction = NativeInstruction {
            id: NativeInstructionId::from(offset),
            span: Span::new(offset, offset + operand_count + 1),
            kind: simplify_instruction(kind),
        };

        Ok(instruction)
    }

    pub fn read_positions(&self) -> Vec<usize> {
        match &self.kind {
            NativeInstructionKind::Add(_, _, _)
            | NativeInstructionKind::Mul(_, _, _)
            | NativeInstructionKind::LessThan(_, _, _)
            | NativeInstructionKind::Equals(_, _, _) => vec![0, 1],
            NativeInstructionKind::Input(_) => vec![],
            NativeInstructionKind::Output(_) | NativeInstructionKind::AdjustRelativeBase(_) => {
                vec![0]
            }
            NativeInstructionKind::JumpIfTrue(_, _) | NativeInstructionKind::JumpIfFalse(_, _) => {
                vec![0, 1]
            }
            NativeInstructionKind::Halt => vec![],
            NativeInstructionKind::Data(_) => vec![],
            NativeInstructionKind::Goto(_) => vec![0, 1],
            NativeInstructionKind::Assign(_, _) => vec![0, 1],
        }
    }

    pub fn write_positions(&self) -> Vec<usize> {
        match &self.kind {
            NativeInstructionKind::Add(_, _, _)
            | NativeInstructionKind::Mul(_, _, _)
            | NativeInstructionKind::LessThan(_, _, _)
            | NativeInstructionKind::Equals(_, _, _) => vec![2],
            NativeInstructionKind::Input(_) => vec![0],
            NativeInstructionKind::Output(_)
            | NativeInstructionKind::AdjustRelativeBase(_)
            | NativeInstructionKind::JumpIfTrue(_, _)
            | NativeInstructionKind::JumpIfFalse(_, _)
            | NativeInstructionKind::Halt
            | NativeInstructionKind::Data(_)
            | NativeInstructionKind::Goto(_) => vec![],
            NativeInstructionKind::Assign(_, _) => vec![2],
        }
    }

    /// Maps operands based on read/write context, propagating the first error encountered.
    pub fn map_rw_result<C, R, W, S, E>(
        &self,
        context: &mut C,
        map_read: &mut R,
        map_write: &mut W,
    ) -> Result<GenericNativeInstruction<S>, E>
    where
        R: FnMut(&mut C, &T) -> Result<S, E>,
        W: FnMut(&mut C, &T) -> Result<S, E>,
    {
        let kind_result = match &self.kind {
            NativeInstructionKind::Add(a, b, c) => Ok(NativeInstructionKind::Add(
                map_read(context, a)?,
                map_read(context, b)?,
                map_write(context, c)?,
            )),
            NativeInstructionKind::Mul(a, b, c) => Ok(NativeInstructionKind::Mul(
                map_read(context, a)?,
                map_read(context, b)?,
                map_write(context, c)?,
            )),
            NativeInstructionKind::Input(a) => {
                Ok(NativeInstructionKind::Input(map_write(context, a)?))
            }
            NativeInstructionKind::Output(a) => {
                Ok(NativeInstructionKind::Output(map_read(context, a)?))
            }
            NativeInstructionKind::JumpIfTrue(a, b) => Ok(NativeInstructionKind::JumpIfTrue(
                map_read(context, a)?,
                map_read(context, b)?,
            )),
            NativeInstructionKind::JumpIfFalse(a, b) => Ok(NativeInstructionKind::JumpIfFalse(
                map_read(context, a)?,
                map_read(context, b)?,
            )),
            NativeInstructionKind::LessThan(a, b, c) => Ok(NativeInstructionKind::LessThan(
                map_read(context, a)?,
                map_read(context, b)?,
                map_write(context, c)?,
            )),
            NativeInstructionKind::Equals(a, b, c) => Ok(NativeInstructionKind::Equals(
                map_read(context, a)?,
                map_read(context, b)?,
                map_write(context, c)?,
            )),
            NativeInstructionKind::AdjustRelativeBase(a) => Ok(
                NativeInstructionKind::AdjustRelativeBase(map_read(context, a)?),
            ),
            NativeInstructionKind::Halt => Ok(NativeInstructionKind::Halt),
            NativeInstructionKind::Data(values) => Ok(NativeInstructionKind::Data(values.clone())),
            NativeInstructionKind::Goto(a) => {
                Ok(NativeInstructionKind::Goto(map_read(context, a)?))
            }
            NativeInstructionKind::Assign(a, b) => Ok(NativeInstructionKind::Assign(
                map_write(context, a)?,
                map_read(context, b)?,
            )),
        };

        kind_result.map(|kind| GenericNativeInstruction {
            id: self.id,
            span: self.span,
            kind,
        })
    }

    /// Maps operands based on read/write context using infallible closures.
    pub fn map_rw<C, R, W, S>(
        &self,
        context: &mut C,
        mut map_read: R,
        mut map_write: W,
    ) -> GenericNativeInstruction<S>
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
    kind: NativeInstructionKind<T>,
) -> NativeInstructionKind<T> {
    match kind.clone() {
        NativeInstructionKind::JumpIfTrue(cond, target) => {
            if let OperandKind::Immediate(val) = cond.into().kind {
                if val != 0 {
                    return NativeInstructionKind::Goto(target);
                }
            }
            kind
        }
        NativeInstructionKind::JumpIfFalse(cond, target) => {
            if let OperandKind::Immediate(val) = cond.into().kind {
                if val == 0 {
                    return NativeInstructionKind::Goto(target);
                }
            }
            kind
        }
        NativeInstructionKind::Add(a, b, target) => {
            if let OperandKind::Immediate(0) = a.clone().into().kind {
                return NativeInstructionKind::Assign(target, b);
            }
            if let OperandKind::Immediate(0) = b.into().kind {
                return NativeInstructionKind::Assign(target, a);
            }
            kind
        }
        NativeInstructionKind::Mul(a, b, target) => {
            if let OperandKind::Immediate(1) = a.clone().into().kind {
                return NativeInstructionKind::Assign(target, b);
            }
            if let OperandKind::Immediate(1) = b.into().kind {
                return NativeInstructionKind::Assign(target, a);
            }
            kind
        }
        _ => kind,
    }
}

impl<T: fmt::Display> fmt::Display for GenericNativeInstruction<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            NativeInstructionKind::Add(a, b, c) => write!(f, "{c} = {a} + {b}"),
            NativeInstructionKind::Mul(a, b, c) => write!(f, "{c} = {a} * {b}"),
            NativeInstructionKind::Input(a) => write!(f, "{a} = input()"),
            NativeInstructionKind::Output(a) => write!(f, "output({a})"),
            NativeInstructionKind::JumpIfTrue(a, b) => write!(f, "if {a} goto {b}"),
            NativeInstructionKind::JumpIfFalse(a, b) => write!(f, "if !{a} goto {b}"),
            NativeInstructionKind::LessThan(a, b, c) => write!(f, "{c} = {a} < {b}"),
            NativeInstructionKind::Equals(a, b, c) => write!(f, "{c} = {a} == {b}"),
            NativeInstructionKind::AdjustRelativeBase(a) => write!(f, "R += {a}"),
            NativeInstructionKind::Halt => write!(f, "halt"),
            NativeInstructionKind::Data(values) => write!(f, "DATA {}", values.iter().format(", ")),
            NativeInstructionKind::Goto(a) => write!(f, "goto {a}"),
            NativeInstructionKind::Assign(a, b) => write!(f, "{a} = {b}"),
        }
    }
}
