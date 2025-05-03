use std::collections::HashMap;
use crate::disasm::v3::id_types::BlockId;
use super::block::DataFlowBlock;

#[derive(Debug, Clone)]
pub struct DataFlowResult {
    pub blocks: HashMap<BlockId, DataFlowBlock>,
}
