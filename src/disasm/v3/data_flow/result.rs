use std::collections::HashMap;
use crate::disasm::v3::id_types::BlockId;
use super::block::DataFlowBlock;

#[derive(Debug, Clone, Default)]
pub struct DataFlowResult {
    pub blocks: HashMap<BlockId, DataFlowBlock>,
}

impl DataFlowResult {
    pub fn new() -> Self {
        Self::default()
    }
}
