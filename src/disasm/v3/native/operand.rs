use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub enum OperandKind {
    Memory(usize),
    Immediate(i128),
    RelativeMemory(i128),
    Pointer(usize),
    Deref(usize),
}

impl OperandKind {
    pub fn get_memory(&self) -> Option<usize> {
        match self {
            OperandKind::Memory(value) => Some(*value),
            _ => None,
        }
    }

    #[expect(dead_code)]
    fn get_pointer(&self) -> Option<usize> {
        match self {
            OperandKind::Pointer(offset) => Some(*offset),
            _ => None,
        }
    }

    #[expect(dead_code)]
    fn get_deref(&self) -> Option<usize> {
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
            OperandKind::Pointer(offset) => write!(f, "p{}", offset),
            OperandKind::Deref(offset) => write!(f, "*p{}", offset),
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
