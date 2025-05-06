use crate::disasm::v3::Block;
use std::collections::HashMap;

pub use crate::disasm::v3::common::{FunctionCall, Span};
pub use crate::disasm::v3::id_types::*;

#[derive(Debug, Clone)]
pub struct Function {
    // Basic structural info (always available)
    pub function_id: FunctionId,
    pub entry_block: BlockId,

    // Discovered by control flow analysis
    pub stack_size: usize,
    pub all_block_ids: Vec<BlockId>, // list of blocks in this function

    // The block containing the R -= N; goto [R] sequence.
    // Function may not have a return block. For example, if it reaches the end of the image, is a loop, or it halts.
    pub return_block: Option<BlockId>,

    pub blocks: HashMap<BlockId, Block>,
}
