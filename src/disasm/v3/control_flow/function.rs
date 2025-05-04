use super::block::{Block, BlockView};
use crate::disasm::v3::{
    id_types::{BlockId, FunctionId},
    model::{Model, ModelState},
};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Function {
    pub function_id: FunctionId,
    pub entry_block: BlockId,
    pub stack_size: usize,

    // The block containing the R -= N; goto [R] sequence.
    // Function may not have a return block. For example, if it reaches the end of the image, is a loop, or it halts.
    pub return_block: Option<BlockId>,
    blocks: HashMap<BlockId, Block>,
}

impl Function {
    pub fn new(
        function_id: FunctionId,
        entry_block: BlockId,
        stack_size: usize,
        return_block: Option<BlockId>,
        blocks: HashMap<BlockId, Block>,
    ) -> Self {
        Self {
            function_id,
            entry_block,
            stack_size,
            return_block,
            blocks,
        }
    }

    pub fn all_block_ids(&self) -> impl Iterator<Item = &BlockId> {
        self.blocks.keys()
    }
}

#[derive(Debug, Copy, Clone)] // Add Copy and Clone
pub struct FunctionView<'a, S: ModelState> {
    pub model: &'a Model<S>,
    function: &'a Function,
}

impl<'a, S: ModelState> FunctionView<'a, S> {
    pub fn new(model: &'a Model<S>, function: &'a Function) -> Self {
        Self { model, function }
    }

    pub fn function_id(&self) -> FunctionId {
        self.function.function_id
    }

    pub fn entry_block(&self) -> BlockId {
        self.function.entry_block
    }

    pub fn stack_size(&self) -> usize {
        self.function.stack_size
    }

    pub fn all_block_ids(&self) -> impl Iterator<Item = &'a BlockId> {
        self.function.all_block_ids()
    }

    pub fn return_block(&self) -> Option<BlockId> {
        self.function.return_block
    }

    pub fn block(&self, block_id: &BlockId) -> BlockView<'a, S> {
        let block = self
            .function
            .blocks
            .get(block_id)
            .unwrap_or_else(|| panic!("Could not find {block_id} in {}", self.function_id()));
        BlockView::new(self.model, block)
    }

    pub fn blocks(&self) -> impl Iterator<Item = (BlockId, BlockView<'a, S>)> {
        // It's critical that the block views in the returned itetaror declared to have the lifetime 'a,
        // of the model and not this FunctionView, so they can outlast it.  This is useful for nested iterator
        // where the containing function view is not passed over.
        self.function
            .blocks
            .iter()
            .map(|(id, block)| (*id, BlockView::new(self.model, block)))
    }
}
