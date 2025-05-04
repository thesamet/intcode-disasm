use std::collections::HashMap;
use crate::disasm::v3::id_types::BlockId;
use super::Expression;

/// Represents a function call with its source and target information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionCall<T> {
    /// The block ID where the call originates from.
    pub calling_block: BlockId,
    /// The expression representing the function address being called.
    pub function_addr: Expression<T>,
    /// The block ID where execution will continue after the function returns.
    pub return_block: BlockId,
}

impl<T: Clone + PartialEq + Eq + std::hash::Hash> FunctionCall<T> {
    pub fn new(
        calling_block: BlockId,
        function_addr: Expression<T>,
        return_block: BlockId,
    ) -> Self {
        Self {
            calling_block,
            function_addr,
            return_block,
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
        }
    }
}

/// Contains flow data about call sites.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallSiteInfo {
    // The set of positive offsets `n` identifying return value locations `[R+n]`
    // that are read by subsequent blocks having access to the function's return state.
    pub return_values_accessed: HashMap<i128, crate::disasm::v3::id_types::InstructionId>,
}

impl CallSiteInfo {
    pub fn new() -> Self {
        Self::default()
    }
}
