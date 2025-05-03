use std::collections::HashMap;
use crate::disasm::v3::id_types::BlockId;
use super::block::SsaBlock;

#[derive(Debug, Clone)]
pub struct SsaResult {
    pub blocks: HashMap<BlockId, SsaBlock>,
}
