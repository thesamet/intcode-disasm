// Forward all definitions to the v3 LIR module
pub use crate::disasm::v3::lir::{
    BinaryOperator, Expression, Instruction, InstructionNode, MemoryReference, MemoryReferenceInfo,
    ReadAddressExtractor, UnaryOperator,
};

// Forward relevant ID types from v3
pub use crate::disasm::v3::id_types::{InstructionId, PointerId};
