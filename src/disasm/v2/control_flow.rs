use super::{
    instructions::{Instruction, Operand},
    model::{BlockId, FunctionId},
    Span,
};

// Describes how control flow leaves a block
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextKind<T>
where
    T: Copy + Clone + PartialEq + Eq + std::hash::Hash,
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
    Unknown,
}

impl<T> NextKind<T>
where
    T: Copy + Clone + PartialEq + Eq + std::hash::Hash,
{
    pub fn map<F, S>(&self, map: &mut F) -> NextKind<S>
    where
        F: FnMut(T) -> S,
        S: Copy + Clone + PartialEq + Eq + std::hash::Hash,
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
}

// Describes how control flow enters a block
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredecessorKind<T>
where
    T: Copy + Clone + PartialEq + Eq + std::hash::Hash,
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

impl<T: Copy + Clone + PartialEq + Eq + std::hash::Hash> PredecessorKind<T> {
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

    fn map<F, S>(self, map: &mut F) -> PredecessorKind<S>
    where
        F: FnMut(T) -> S,
        S: Copy + Clone + PartialEq + Eq + std::hash::Hash,
    {
        match self {
            PredecessorKind::FollowsFrom(id) => PredecessorKind::FollowsFrom(id),
            PredecessorKind::GotoFrom(id) => PredecessorKind::GotoFrom(id),
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
pub struct FunctionCall<T>
where
    T: Copy + Clone + PartialEq + Eq + std::hash::Hash,
{
    pub calling_block: BlockId,
    // The operand representing the function address (can be immediate or indirect)
    pub function_addr: T,
    pub return_block: BlockId, // The block execution resumes at after the call
}

impl<T: Copy + Clone + PartialEq + Eq + std::hash::Hash> FunctionCall<T> {
    pub fn new(calling_block: BlockId, function_addr: T, return_block: BlockId) -> Self {
        Self {
            calling_block,
            function_addr,
            return_block,
        }
    }
    pub fn map<F, S>(&self, map: &mut F) -> FunctionCall<S>
    where
        F: FnMut(T) -> S,
        S: Copy + Clone + PartialEq + Eq + std::hash::Hash,
    {
        FunctionCall {
            calling_block: self.calling_block,
            function_addr: map(self.function_addr),
            return_block: self.return_block,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition<T> {
    pub from_block: BlockId,    // Block containing the conditional jump
    pub condition_operand: T,   // The operand being tested
    pub jump_if_true: bool,     // True for `if x`, False for `if !x`
    pub target_block: BlockId,  // Block jumped to if condition met
    pub follows_block: BlockId, // Block fallen through to if condition not met
}

impl<T> Condition<T> {
    pub fn map<F, S>(&self, map: &mut F) -> Condition<S>
    where
        F: FnMut(T) -> S,
        T: Copy + Clone,
    {
        Condition {
            from_block: self.from_block,
            condition_operand: map(self.condition_operand),
            jump_if_true: self.jump_if_true,
            target_block: self.target_block,
            follows_block: self.follows_block,
        }
    }
}

impl<T> Default for NextKind<T>
where
    T: Copy + Clone + PartialEq + Eq + std::hash::Hash,
{
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
    pub predecessors: Vec<PredecessorKind<Operand>>,
}
