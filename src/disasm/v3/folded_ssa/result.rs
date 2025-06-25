use std::collections::HashMap;

use crate::disasm::v3::{
    lir::InstructionNode, model::add_block_view_when, ssa::SsaMemoryReference, BlockId, NextKind,
};

/// The overall result of the "Folded SSA" pipeline phase.
/// This phase transforms SSA instructions to have richer expressions by folding temporaries.
/// The result is still structurally an `SsaResult`, but the content of `SsaBlock`s
/// (specifically instructions and potentially phi functions) reflects the folded state.
#[derive(Debug, Clone)]

pub struct FoldedSsaResult {
    pub blocks: HashMap<BlockId, FoldedSsaBlock>,
}

impl FoldedSsaResult {
    pub fn new(blocks: HashMap<BlockId, FoldedSsaBlock>) -> Self {
        FoldedSsaResult { blocks }
    }
}

add_block_view_when!(FoldedSsa, folded_ssa);

#[derive(Debug, Clone)]
pub struct FoldedSsaBlock {
    pub instructions: Vec<InstructionNode<SsaMemoryReference>>,
    pub next: NextKind<SsaMemoryReference>,
}
