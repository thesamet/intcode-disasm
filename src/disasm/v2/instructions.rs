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

define_id_type!(OperandId);
// Operand is a value that is passed as a positional argument to an instruction.
#[derive(Debug, Clone)]
pub struct Operand {
    id: OperandId,
    kind: OperandKind,
    offset: usize,
    debug_marker: Option<char>,
}

define_id_type!(InstructionId);
#[derive(Debug, Clone)]
pub struct Instruction {
    // Basic structural info (always available)
    pub id: InstructionId,
    pub span: Span,
    pub opcode: u8,
    pub operands: Vec<Operand>,
}

impl Instruction {}
