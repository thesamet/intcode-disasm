pub mod instruction;
pub mod operand;

pub use instruction::{
    Assignment, GenericNativeInstruction, NativeInstruction, NativeInstructionKind, Opcode,
    ParseError,
};
pub use operand::{Operand, OperandKind};
