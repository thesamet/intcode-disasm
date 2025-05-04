
// Forward all definitions to the v3 native module
pub use crate::disasm::v3::native::{
    Assignment, GenericNativeInstruction, NativeInstruction, NativeInstructionKind, Opcode,
    Operand, OperandKind, ParseError,
};

// Also forward the ID type
pub use crate::disasm::v3::id_types::NativeInstructionId;
