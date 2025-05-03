use crate::disasm::v2::control_flow::{NextKind, PredecessorKind};
use crate::disasm::v2::instructions::InstructionNode;
use crate::disasm::v2::ssa_form::{PhiFunction, SsaMemoryReference, VersionRegistry};
use crate::disasm::v3::data_flow::DataFlowBlock;
use crate::disasm::v3::id_types::BlockId;

/// Represents a basic block in SSA form
#[derive(Debug, Clone)]
pub struct SsaBlock {
    /// Original block ID
    pub original_id: BlockId,
    /// Phi functions at the start of this block
    pub phi_functions: Vec<PhiFunction>,
    // Instructions in SSA form
    pub instructions: Vec<InstructionNode<SsaMemoryReference>>,
    // Start state: the state of all versioned variables at the start of this block
    pub start_state: VersionRegistry, // Track only versioned variables
    /// End state: the state of all versioned variables at the end of this block
    pub end_state: VersionRegistry, // Track only versioned variables
    /// Control flow information using SSA operands
    pub next: NextKind<SsaMemoryReference>,
    pub predecessors: Vec<PredecessorKind<SsaMemoryReference>>,
}
