// Use v3 types
use crate::disasm::v3::common::{FunctionCall, Span}; // Keep common types here
use crate::disasm::v3::id_types::{BlockId, FunctionId}; // Added InstructionId
use crate::disasm::v3::lir::{
    Expression,
    InstructionNode,
    MemoryReference,
    ReadAddressExtractor, // Use LIR types
};
use crate::disasm::v3::model::{Model, ModelState};
use crate::disasm::v3::InstructionId;

// use crate::disasm::v3::native::NativeInstruction; // Removed - unresolved

/// A block in the control flow graph
#[derive(Debug, Clone)]
pub struct Block {
    pub id: BlockId,
    /// To which function does this block belong?
    pub containing_function_id: FunctionId,
    pub span: Span,
    // pub native_instructions: Vec<NativeInstruction>, // Removed - unresolved
    pub low_instructions: Vec<InstructionNode<MemoryReference>>, // v3 common MemoryReference

    /// Control flow information
    pub next: NextKind<MemoryReference>, // v3 common MemoryReference
    pub predecessors: Vec<PredecessorKind<MemoryReference>>, // v3 common MemoryReference
}

// Add Debug derive here
#[derive(Debug, Clone, Copy)]
pub struct BlockView<'a, S: ModelState> {
    pub model: &'a Model<S>,
    block: &'a Block,
}

impl<'a, S: ModelState> BlockView<'a, S> {
    pub fn new(model: &'a Model<S>, block: &'a Block) -> Self {
        Self { model, block }
    }

    pub fn block_id(&self) -> BlockId {
        self.block.id
    }

    pub fn containing_function_id(&self) -> FunctionId {
        self.block.containing_function_id
    }

    pub fn span(&self) -> &Span {
        &self.block.span
    }

    pub fn low_instructions(&self) -> &'a [InstructionNode<MemoryReference>] {
        &self.block.low_instructions
    }

    pub fn next(&self) -> &'a NextKind<MemoryReference> {
        &self.block.next
    }

    pub fn predecessors(&self) -> &'a [PredecessorKind<MemoryReference>] {
        &self.block.predecessors
    }
}

// Describes how control flow leaves a block
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NextKind<T>
where
    T: Clone + PartialEq + Eq + std::hash::Hash,
{
    // Block always falls through to the immediately following block
    Follows(BlockId),
    // Unconditional jump to a target within the current function.
    Goto(BlockId),
    // A function call sequence ([R]=ret; goto target)
    FunctionCall(FunctionCall<T>),
    // Conditional jump based on an operand
    Condition(Condition<T>),
    // Function returns ([R]-=N; goto [R])
    Return,
    // Program halts
    Halt,
    // Control flow path is unknown (e.g., jump target is not immediate/calculable yet)
    #[default]
    Unknown,
}

impl<T> NextKind<T>
where
    T: Clone + PartialEq + Eq + std::hash::Hash + ReadAddressExtractor,
{
    pub fn map<F, S>(&self, map: &mut F) -> NextKind<S>
    where
        F: FnMut(&T) -> S,
        S: Clone + PartialEq + Eq + std::hash::Hash,
    {
        match self {
            NextKind::Follows(id) => NextKind::Follows(*id),
            NextKind::Goto(block_id) => NextKind::Goto(*block_id),
            NextKind::FunctionCall(call) => NextKind::FunctionCall(call.map(map)),
            NextKind::Condition(cond) => NextKind::Condition(cond.map(map)),
            NextKind::Return => NextKind::Return,
            NextKind::Halt => NextKind::Halt,
            NextKind::Unknown => NextKind::Unknown,
        }
    }

    pub fn successors(&self) -> Vec<BlockId> {
        match self {
            NextKind::Follows(id) => vec![*id],
            NextKind::Goto(block_id) => vec![*block_id],
            NextKind::FunctionCall(call) => vec![call.return_block],
            NextKind::Condition(cond) => vec![cond.target_block, cond.follows_block],
            NextKind::Return => vec![],
            NextKind::Halt => vec![],
            NextKind::Unknown => vec![],
        }
    }

    pub fn as_function_call(&self) -> Option<&FunctionCall<T>> {
        match self {
            NextKind::FunctionCall(call) => Some(call),
            _ => None,
        }
    }

    pub fn collect_read_addresses(&self) -> Vec<&T> {
        match self {
            NextKind::Follows(_) => vec![],
            NextKind::Goto(_) => vec![],
            NextKind::FunctionCall(call) => call.function_addr.collect_read_addresses(),
            NextKind::Condition(cond) => cond.condition_operand.collect_read_addresses(),
            NextKind::Return => vec![],
            NextKind::Halt => vec![],
            NextKind::Unknown => vec![],
        }
    }
}

// Describes how control flow enters a block
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PredecessorKind<T>
where
    T: Clone + PartialEq + Eq + std::hash::Hash,
{
    // Entered from the immediately preceding block
    FollowsFrom(BlockId),
    // Entered via an unconditional jump from the source block
    GotoFrom(BlockId),
    // Entered because a function call made in the source block returns here
    FunctionCallReturns(FunctionCall<T>),
    // Entered because the condition in the source block was *false* (fall-through)
    ConditionalFollow(Condition<T>),
    // Entered because the condition in the source block was *true* (jump taken)
    ConditionalJump(Condition<T>),
}

impl<T: Clone + PartialEq + Eq + std::hash::Hash> PredecessorKind<T> {
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

    pub fn get_function_call_returns(&self) -> Option<&FunctionCall<T>> {
        match self {
            PredecessorKind::FunctionCallReturns(call) => Some(call),
            _ => None,
        }
    }

    pub fn goto_from(&self) -> Option<BlockId> {
        match self {
            PredecessorKind::GotoFrom(id) => Some(*id),
            _ => None,
        }
    }

    pub fn map<F, S>(&self, map: &mut F) -> PredecessorKind<S>
    where
        F: FnMut(&T) -> S,
        S: Clone + PartialEq + Eq + std::hash::Hash,
    {
        match self {
            PredecessorKind::FollowsFrom(id) => PredecessorKind::FollowsFrom(*id),
            PredecessorKind::GotoFrom(id) => PredecessorKind::GotoFrom(*id),
            PredecessorKind::FunctionCallReturns(call) => {
                PredecessorKind::FunctionCallReturns(call.map(map))
            }
            PredecessorKind::ConditionalFollow(cond) => {
                PredecessorKind::ConditionalFollow(cond.map(map))
            }
            PredecessorKind::ConditionalJump(cond) => {
                PredecessorKind::ConditionalJump(cond.map(map))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Condition<T> {
    pub from_block: BlockId,              // Block containing the conditional jump
    pub condition_operand: Expression<T>, // The operand being tested
    pub jump_if_true: bool,               // True for `if x`, False for `if !x`
    pub target_block: BlockId,            // Block jumped to if condition met
    pub follows_block: BlockId,           // Block fallen through to if condition not met
    pub instruction_id: InstructionId,    // The instructin id of this condition.
}

impl<T> Condition<T> {
    pub fn map<F, S>(&self, map: &mut F) -> Condition<S>
    where
        F: FnMut(&T) -> S,
        T: Clone,
    {
        Condition {
            from_block: self.from_block,
            condition_operand: self.condition_operand.map(map),
            jump_if_true: self.jump_if_true,
            target_block: self.target_block,
            follows_block: self.follows_block,
            instruction_id: self.instruction_id,
        }
    }
}
