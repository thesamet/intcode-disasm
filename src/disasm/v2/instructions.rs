use core::fmt;

use thiserror::Error;

use super::{id_types::define_id_type, Span};

/// Debug information for an instruction
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct DebugInfo {
    /// Optional marker character for this instruction
    pub marker: Option<char>,
    /// Optional source line information
    pub source_line: Option<usize>,
}

define_id_type!(InstructionId);
/// A generic instruction that can use different operand types
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct GenericInstruction<T> {
    /// The instruction ID
    pub id: InstructionId,
    /// The span of the instruction in the image
    pub span: Span,
    /// The opcode
    pub opcode: Opcode,
    /// The operands
    pub operands: Vec<T>,
    /// Optional debug information
    pub debug_info: Option<DebugInfo>,
}

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

pub trait HasOperand {
    fn operand(&self) -> &Operand;

    fn kind(&self) -> &OperandKind {
        &self.operand().kind
    }
}

impl HasOperand for Operand {
    fn operand(&self) -> &Operand {
        self
    }
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

pub type Instruction = GenericInstruction<Operand>;

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
pub struct Assignment<T> {
    pub target: T,
    pub source: T,
}

impl<T: HasOperand + Copy + Clone> GenericInstruction<T> {
    pub fn immediate_arg(&self, index: usize) -> Option<i128> {
        self.operands[index].kind().get_immediate()
    }

    pub fn memory_arg(&self, index: usize) -> Option<i128> {
        self.operands[index].kind().get_memory()
    }

    pub fn relative_memory_arg(&self, index: usize) -> Option<i128> {
        self.operands[index].kind().get_relative_memory()
    }

    pub fn is_jump(&self) -> bool {
        match self.opcode {
            Opcode::JumpIfTrue | Opcode::JumpIfFalse => true,
            _ => false,
        }
    }

    pub fn goto_address(&self) -> Option<T> {
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
            .and_then(|a| a.kind().get_immediate().map(|a| a as usize))
    }

    pub fn is_conditional_jump(&self) -> bool {
        (self.opcode == Opcode::JumpIfTrue || self.opcode == Opcode::JumpIfFalse) && !self.is_goto()
    }

    pub fn conditional_jump_address(&self) -> Option<T> {
        if !self.is_conditional_jump() {
            return None;
        }
        Some(self.operands[1])
    }

    pub fn conditional_jump_condition(&self) -> Option<T> {
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

    pub fn as_assignment(&self) -> Option<Assignment<T>> {
        match self.opcode {
            Opcode::Add => {
                if let Some(0) = self.operands[0].kind().get_immediate() {
                    Some(Assignment {
                        target: self.operands[2],
                        source: self.operands[1],
                    })
                } else if let Some(0) = self.operands[1].kind().get_immediate() {
                    Some(Assignment {
                        target: self.operands[2],
                        source: self.operands[0],
                    })
                } else {
                    None
                }
            }
            Opcode::Mul => {
                if let Some(1) = self.operands[0].kind().get_immediate() {
                    Some(Assignment {
                        target: self.operands[2],
                        source: self.operands[1],
                    })
                } else if let Some(1) = self.operands[1].kind().get_immediate() {
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
        let operands: Vec<Operand> = (0..operand_count)
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
        // Check if any operands have debug markers
        let debug_markers: Vec<_> = operands.iter().filter_map(|op| op.debug_marker).collect();

        let debug_info = if !debug_markers.is_empty() {
            Some(DebugInfo {
                marker: debug_markers.first().cloned(),
                source_line: None,
            })
        } else {
            None
        };

        Ok(Instruction {
            id: InstructionId::from(offset),
            span: Span::new(offset, offset + operand_count + 1),
            opcode: Opcode::from_i128(opcode % 100)?,
            operands,
            debug_info,
        })
    }

    pub fn read_positions(&self) -> Vec<usize> {
        let mut positions = Vec::new();
        match self.opcode {
            Opcode::Add | Opcode::Mul | Opcode::LessThan | Opcode::Equals => {
                positions.push(0); // Arg 1
                positions.push(1); // Arg 2
            }
            Opcode::Input => {}
            Opcode::Output => {
                positions.push(0); // Arg 1
            }
            Opcode::JumpIfTrue | Opcode::JumpIfFalse => {
                positions.push(0); // Arg 1
                positions.push(1); // Arg 1
            }
            Opcode::AdjustRelativeBase => {
                positions.push(0); // Value to adjust by
            }
            Opcode::Halt => {} // No reads
        };
        positions
    }

    pub fn write_positions(&self) -> Vec<usize> {
        let mut positions = Vec::new();
        match self.opcode {
            Opcode::Add | Opcode::Mul | Opcode::LessThan | Opcode::Equals => {
                positions.push(2); // Destination
            }
            Opcode::Input => {
                positions.push(0); // Destination
            }
            Opcode::Output => {}
            Opcode::JumpIfTrue | Opcode::JumpIfFalse => {}
            Opcode::AdjustRelativeBase => {} // Modifies R register implicitly, not an operand location
            Opcode::Halt => {}               // No writes
        };
        positions
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
        let mut new_operands = Vec::new();
        for (i, op) in self.operands.iter().enumerate() {
            if self.read_positions().contains(&i) {
                new_operands.push(map_read(context, &op));
            } else {
                new_operands.push(map_write(context, &op));
            }
        }
        GenericInstruction {
            id: self.id,
            span: self.span,
            opcode: self.opcode,
            operands: new_operands,
            debug_info: self.debug_info,
        }
    }

    /// Returns a list of operands that are read by this instruction.
    /// Does not include immediate values, only operands representing memory locations.
    pub fn reads(&self) -> Vec<&T> {
        let mut reads = Vec::new();
        match self.opcode {
            Opcode::Add | Opcode::Mul | Opcode::LessThan | Opcode::Equals => {
                reads.push(&self.operands[0]); // Arg 1
                reads.push(&self.operands[1]); // Arg 2
            }
            Opcode::Input => {
                // Input reads from external source, not an operand location
            }
            Opcode::Output => {
                reads.push(&self.operands[0]); // Value to output
            }
            Opcode::JumpIfTrue | Opcode::JumpIfFalse => {
                reads.push(&self.operands[0]); // Condition
                                               // The jump target (operands[1]) is also technically "read" if it's not immediate,
                                               // but data flow usually focuses on values used *in* computation or conditions.
                                               // Let's include it if it's not immediate, as its value determines control flow.
                reads.push(&self.operands[1]); // Jump target
            }
            Opcode::AdjustRelativeBase => {
                reads.push(&self.operands[0]); // Value to adjust by
            }
            Opcode::Halt => {} // No reads
        }

        // Filter out immediate values as they don't represent memory locations being read.
        // Also filter Deref for now, as handling them requires pointer analysis.
        // We *do* include Memory and RelativeMemory kinds.
        reads
            .into_iter()
            .filter(|op| {
                matches!(
                    op.kind(),
                    OperandKind::Memory(_) | OperandKind::RelativeMemory(_)
                )
            })
            // .filter(|op| !matches!(op.kind, OperandKind::Immediate(_) | OperandKind::Deref(_)))
            .collect()
    }

    /// Returns the operand that is written to by this instruction, if any.
    pub fn writes(&self) -> Option<&T> {
        let target_operand = match self.opcode {
            Opcode::Add | Opcode::Mul | Opcode::LessThan | Opcode::Equals => {
                Some(&self.operands[2]) // Destination
            }
            Opcode::Input => {
                Some(&self.operands[0]) // Destination
            }
            // Opcodes that don't write to an operand location
            Opcode::Output
            | Opcode::JumpIfTrue
            | Opcode::JumpIfFalse
            | Opcode::AdjustRelativeBase // Modifies R register implicitly, not an operand location
            | Opcode::Halt => None,
        };

        // Filter out writes to non-memory locations (shouldn't happen with current opcodes)
        // and Deref (requires pointer analysis to know the target).
        target_operand.filter(|op| {
            matches!(
                op.kind(),
                OperandKind::Memory(_) | OperandKind::RelativeMemory(_)
            )
        })
        // .filter(|op| !matches!(op.kind, OperandKind::Immediate(_) | OperandKind::Deref(_)))
    }
}
