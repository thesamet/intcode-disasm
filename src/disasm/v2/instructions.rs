use core::fmt;

use thiserror::Error;

use super::{id_types::define_id_type, Span};

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

    pub fn get_deref(&self) -> Option<usize> {
        match self {
            OperandKind::Deref(offset) => Some(*offset),
            _ => None,
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
    #[error("Unexpected opcode {0} after R adjustment")]
    UnexpectedOpAfterAdjustment(Instruction),
    #[error("Instruction does not match the expected pattern")]
    NoMatch,
}

define_id_type!(InstructionId);
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Instruction {
    // Basic structural info (always available)
    pub id: InstructionId,
    pub span: Span,
    pub opcode: Opcode,
    operands: Vec<Operand>,
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.opcode)?;
        for operand in &self.operands {
            write!(f, " {:?}", operand.offset)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Assignment {
    pub target: Operand,
    pub source: Operand,
}

impl Instruction {
    pub fn immediate_arg(&self, index: usize) -> Option<i128> {
        self.operands[index].kind.get_immediate()
    }

    pub fn memory_arg(&self, index: usize) -> Option<i128> {
        self.operands[index].kind.get_memory()
    }

    pub fn relative_memory_arg(&self, index: usize) -> Option<i128> {
        self.operands[index].kind.get_relative_memory()
    }

    pub fn is_jump(&self) -> bool {
        match self.opcode {
            Opcode::JumpIfTrue | Opcode::JumpIfFalse => true,
            _ => false,
        }
    }

    pub fn goto_address(&self) -> Option<Operand> {
        match self.opcode {
            Opcode::JumpIfTrue if self.immediate_arg(0).is_some_and(|v| v != 0) => {
                Some(self.operands[1])
            }
            Opcode::JumpIfFalse if self.immediate_arg(0).is_some_and(|v| v == 0) => {
                Some(self.operands[1])
            }
            _ => None,
        }
    }

    pub fn is_halt(&self) -> bool {
        self.opcode == Opcode::Halt
    }

    pub fn is_goto(&self) -> bool {
        self.goto_address().is_some()
    }

    pub fn immediate_goto(&self) -> Option<usize> {
        self.goto_address()
            .and_then(|a| a.kind.get_immediate().map(|a| a as usize))
    }

    pub fn is_conditional_jump(&self) -> bool {
        (self.opcode == Opcode::JumpIfTrue || self.opcode == Opcode::JumpIfFalse) && !self.is_goto()
    }

    pub fn conditional_jump_address(&self) -> Option<Operand> {
        if !self.is_conditional_jump() {
            return None;
        }
        Some(self.operands[1])
    }

    pub fn conditional_jump_condition(&self) -> Option<Operand> {
        if !self.is_conditional_jump() {
            return None;
        }
        Some(self.operands[0])
    }

    pub fn conditional_jump_immediate_address(&self) -> Option<usize> {
        if !self.is_conditional_jump() {
            return None;
        }
        self.immediate_arg(1).map(|a| a as usize)
    }

    pub fn relative_base_adjustment(&self) -> Option<i128> {
        if self.opcode != Opcode::AdjustRelativeBase {
            return None;
        }
        self.immediate_arg(0)
    }

    pub fn as_assignment(&self) -> Option<Assignment> {
        match self.opcode {
            Opcode::Add => {
                if let Some(0) = self.operands[0].kind.get_immediate() {
                    Some(Assignment {
                        target: self.operands[2],
                        source: self.operands[1],
                    })
                } else if let Some(0) = self.operands[1].kind.get_immediate() {
                    Some(Assignment {
                        target: self.operands[2],
                        source: self.operands[0],
                    })
                } else {
                    None
                }
            }
            Opcode::Mul => {
                if let Some(1) = self.operands[0].kind.get_immediate() {
                    Some(Assignment {
                        target: self.operands[2],
                        source: self.operands[1],
                    })
                } else if let Some(1) = self.operands[1].kind.get_immediate() {
                    Some(Assignment {
                        target: self.operands[2],
                        source: self.operands[0],
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn parse(input: &[i128], offset: usize) -> Result<Instruction, ParseError> {
        if offset >= input.len() {
            return Err(ParseError::EndOfFile(offset));
        }
        let opcode = input[offset];
        let operand_count = match opcode % 100 {
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
            _ => return Err(ParseError::InvalidOpcode(opcode as i128)),
        };
        if offset + operand_count >= input.len() {
            return Err(ParseError::EndOfFile(offset));
        }
        let operands = (0..operand_count)
            .map(|i| -> Result<Operand, ParseError> {
                let kind = match input[offset] / 10_i128.pow(i as u32 + 2) % 10 {
                    0 => Ok(OperandKind::Memory(input[offset + i + 1])),
                    1 => Ok(OperandKind::Immediate(input[offset + i + 1])),
                    2 => Ok(OperandKind::RelativeMemory(input[offset + i + 1])),
                    m => Err(ParseError::InvalidMode(m)),
                }?;
                let debug_marker = match ((opcode / 100000) >> (8usize * i)) & 0xff {
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
        Ok(Instruction {
            id: InstructionId::from(offset),
            span: Span::new(offset, offset + operand_count + 1),
            opcode: Opcode::from_i128(opcode % 100)?,
            operands,
        })
    }
}
