use super::types::SsaBlock;
use crate::disasm::v3::id_types::BlockId;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SsaResult {
    pub blocks: HashMap<BlockId, SsaBlock>,
}
