use crate::disasm::v3::{id_types::BlockId, lir::Expression, InstructionId}; // Added InstructionId

/// Represents a function call with its source and target information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionCall<T> {
    /// The block ID where the call originates from.
    pub calling_block: BlockId,
    /// The expression representing the function address being called.
    pub function_addr: Expression<T>,
    /// The block ID where execution will continue after the function returns.
    pub return_block: BlockId,
    /// The instruction ID of the call instruction.
    pub instruction_id: InstructionId,
}

impl<T: Clone + PartialEq + Eq + std::hash::Hash> FunctionCall<T> {
    pub fn new(
        calling_block: BlockId,
        function_addr: Expression<T>,
        return_block: BlockId,
        instruction_id: InstructionId,
    ) -> Self {
        Self {
            calling_block,
            function_addr,
            return_block,
            instruction_id,
        }
    }

    pub fn map<F, S>(&self, map: &mut F) -> FunctionCall<S>
    where
        F: FnMut(&T) -> S,
        T: Clone,
    {
        FunctionCall {
            calling_block: self.calling_block,
            function_addr: self.function_addr.map(map),
            return_block: self.return_block,
            instruction_id: self.instruction_id,
        }
    }
}
