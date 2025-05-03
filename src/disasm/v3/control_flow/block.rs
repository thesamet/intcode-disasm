use crate::disasm::v3::common::Span;
use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v2::instructions::{InstructionNode, MemoryReference};
use crate::disasm::v2::native::NativeInstruction;
use crate::disasm::v2::control_flow::{NextKind, PredecessorKind};

/// A block in the control flow graph
#[derive(Debug, Clone)]
pub struct Block {
    pub id: BlockId,
    /// To which function does this block belong?
    pub containing_function_id: FunctionId,
    pub span: Span,
    pub native_instructions: Vec<NativeInstruction>,
    pub low_instructions: Vec<InstructionNode<MemoryReference>>,

    /// Control flow information
    pub next: NextKind<MemoryReference>,
    pub predecessors: Vec<PredecessorKind<MemoryReference>>,
}
