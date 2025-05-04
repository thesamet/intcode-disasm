use std::fmt::Debug;

/// Trait for view types that provide read-only access to model components
pub trait ModelView<T> {
    /// Get a reference to the underlying data
    fn data(&self) -> &T;
}

// Add Debug derive here
#[derive(Debug, Clone, Copy)]
pub struct BlockView<'a, S: ModelState> {
    model: &'a Model<S>,
    block: &'a Block,
}

impl<'a, S: ModelState> BlockView<'a, S> {
    pub fn new(model: &'a Model<S>, block: &'a Block) -> Self {
        Self { model, block }
    }

    pub fn block_id(&self) -> BlockId {
        self.block.id
    }

    pub fn span(&self) -> Span {
        self.block.span
    }

    pub fn native_instructions(&self) -> &[NativeInstruction] {
        &self.block.native_instructions
    }

    pub fn low_instructions(&self) -> &[InstructionNode<MemoryReference>] {
        &self.block.low_instructions
    }

    pub fn next(&self) -> &NextKind<MemoryReference> {
        &self.block.next
    }

    pub fn predecessors(&self) -> &[PredecessorKind<MemoryReference>] {
        &self.block.predecessors
    }

    pub fn containing_function_id(&self) -> FunctionId {
        self.block.containing_function_id
    }
}

// Add Debug derive here
#[derive(Debug, Clone, Copy)]
pub struct FunctionView<'a, S: ModelState> {
    model: &'a Model<S>,
    function: &'a Function,
}

impl<'a, S: ModelState> FunctionView<'a, S> {
    pub fn new(model: &'a Model<S>, function: &'a Function) -> Self {
        Self { model, function }
    }

    pub fn function_id(&self) -> FunctionId {
        self.function.id
    }

    pub fn entry_block_id(&self) -> BlockId {
        self.function.entry_block
    }

    pub fn stack_size(&self) -> usize {
        self.function.stack_size
    }

    pub fn return_block_id(&self) -> Option<BlockId> {
        self.function.return_block
    }

    pub fn block(&self, block_id: &BlockId) -> BlockView<'a, S> {
        let block = self.function.blocks.get(block_id).unwrap_or_else(|| {
            panic!(
                "Block {:?} not found in function {:?}",
                block_id,
                self.function_id()
            )
        });
        BlockView::new(self.model, block)
    }

    pub fn blocks(&self) -> impl Iterator<Item = (&BlockId, BlockView<'a, S>)> {
        self.function
            .blocks
            .iter()
            .map(|(id, block)| (id, BlockView::new(self.model, block)))
    }
}

// --- Add view implementations for specific model states ---

impl<'a> BlockView<'a, DataFlowComplete> {
    pub fn data_flow(&self) -> Option<&DataFlowBlock> {
        self.model
            .data_flow_result()
            .and_then(|df| df.blocks.get(&self.block.id))
    }
}

impl<'a> BlockView<'a, SsaComplete> {
    pub fn ssa(&self) -> Option<&SsaBlock> {
        self.model
            .ssa_result()
            .and_then(|ssa| ssa.blocks.get(&self.block.id))
    }
}

impl<'a> BlockView<'a, FunctionCallComplete> {
    pub fn call_site_info(&self) -> Option<&CallSiteInfo> {
        self.model
            .function_call_analysis_result()
            .and_then(|fca| fca.blocks.get(&self.block.id))
    }
}

impl<'a> FunctionView<'a, FunctionCallComplete> {
    pub fn callee_info(&self) -> Option<&CalleeInfo> {
        self.model
            .function_call_analysis_result()
            .and_then(|fca| fca.functions.get(&self.function.id))
    }
}
