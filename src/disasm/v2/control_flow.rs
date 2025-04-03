use super::{
    instructions::{Instruction, Operand},
    model::{BlockId, FunctionId},
};
use crate::disasm::low_ir::Span; // Assuming Span might be useful later

// Describes how control flow leaves a block
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextKind<T = Operand> {
    // Block always falls through to the immediately following block
    Follows(BlockId),
    // Unconditional jump to a target determined by the operand
    Goto(T),
    // A function call sequence ([R]=ret; goto target)
    FunctionCall(FunctionCall<T>),
    // Conditional jump based on an operand
    Condition(Condition<T>),
    // Function returns ([R]-=N; goto [R])
    Return,
    // Program halts
    Halt,
    // Control flow path is unknown (e.g., jump target is not immediate/calculable yet)
    Unknown,
}

// Describes how control flow enters a block
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredecessorKind {
    // Entered from the immediately preceding block
    FollowsFrom(BlockId),
    // Entered via an unconditional jump from the source block
    GotoFrom(BlockId),
    // Entered because a function call made in the source block returns here
    FunctionCallReturns(FunctionCall),
    // Entered because the condition in the source block was *false* (fall-through)
    ConditionalFollow(Condition),
    // Entered because the condition in the source block was *true* (jump taken)
    ConditionalJump(Condition),
}

impl PredecessorKind {
    /// Gets the ID of the block where this predecessor originates.
    pub fn source_block_id(&self) -> BlockId {
        match self {
            PredecessorKind::FollowsFrom(id) => *id,
            PredecessorKind::GotoFrom(id) => *id,
            PredecessorKind::FunctionCallReturns(call) => call.calling_block,
            PredecessorKind::ConditionalFollow(cond) => cond.from_block,
            PredecessorKind::ConditionalJump(cond) => cond.from_block,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCall<T = Operand> {
    pub calling_block: BlockId,
    // The operand representing the function address (can be immediate or indirect)
    pub function_addr: T,
    pub return_block: BlockId, // The block execution resumes at after the call
    // The state of all variables at call site (empty for now, filled by SSA conversion)
    pub call_site_state: Option<std::collections::HashMap<crate::disasm::v2::instructions::OperandKind, T>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition<T = Operand> {
    pub from_block: BlockId,        // Block containing the conditional jump
    pub condition_operand: T,       // The operand being tested
    pub jump_if_true: bool,         // True for `if x`, False for `if !x`
    pub target_block: BlockId,      // Block jumped to if condition met
    pub follows_block: BlockId,     // Block fallen through to if condition not met
}

impl<T> Default for NextKind<T> {
    fn default() -> Self {
        NextKind::Unknown
    }
}

/// A block in the control flow graph
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub id: BlockId,
    // To which function does this block belong?
    pub containing_function_id: FunctionId,
    pub span: Span,
    pub instructions: Vec<Instruction>,

    // CFG Information (added by ControlFlowGraphBuilder)
    pub next: NextKind<Operand>,
    pub predecessors: Vec<PredecessorKind>,
}

impl Block {
    pub fn new(
        id: BlockId,
        containing_function_id: FunctionId,
        span: Span,
        instructions: Vec<Instruction>,
        next: NextKind<Operand>,
    ) -> Self {
        Self {
            id,
            containing_function_id,
            span,
            instructions,
            next,
            predecessors: Vec::new(),
        }
    }
}
