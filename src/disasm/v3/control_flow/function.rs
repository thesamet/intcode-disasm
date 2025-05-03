use std::collections::HashMap;
use crate::disasm::v3::id_types::{BlockId, FunctionId};
use super::block::Block;

#[derive(Debug, Clone)]
pub struct Function {
    pub function_id: FunctionId,
    pub entry_block: BlockId,
    pub stack_size: usize,

    // The block containing the R -= N; goto [R] sequence.
    // Function may not have a return block. For example, if it reaches the end of the image, is a loop, or it halts.
    pub return_block: Option<BlockId>,
    pub blocks: HashMap<BlockId, Block>,
}
