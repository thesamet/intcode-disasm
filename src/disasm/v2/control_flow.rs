pub use crate::disasm::v3::control_flow::{Function, NextKind, PredecessorKind};
use crate::disasm::v3::FunctionId;

use super::{
    data_flow::BlockDataFlow,
    instructions::{InstructionNode, MemoryReference},
    native::{NativeInstruction, Operand},
    BlockId, Span,
};

/// A block in the control flow graph
#[derive(Debug, Clone)]
pub struct Block {
    pub id: BlockId,
    // To which function does this block belong?
    pub containing_function_id: FunctionId,
    pub span: Span,
    pub native_instructions: Vec<NativeInstruction>,
    pub low_instructions: Vec<InstructionNode<MemoryReference>>,

    // CFG Information (added by ControlFlowGraphBuilder)
    pub native_next: NextKind<Operand>,
    pub next: NextKind<MemoryReference>,
    pub predecessors: Vec<PredecessorKind<MemoryReference>>,

    // Dataflow information (added by DataFlowAnalyzer)
    pub data_flow: Option<BlockDataFlow>,
}

/// Information about a function call for control flow analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionCallInfo<T> {
    /// The operand holding the function address (could be immediate or variable).
    pub function_addr: T,
}
