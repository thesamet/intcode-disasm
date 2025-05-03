mod block;
mod result;
mod converter;

pub use block::SsaBlock;
pub use result::SsaResult;
pub use converter::SsaConverter;

use crate::disasm::v3::id_types::BlockId;
use crate::disasm::v3::model::{HasSsaResult, Model, ModelState};

impl<S: ModelState> Model<S>
where
    S: HasSsaResult,
{
    pub fn ssa_result(&self) -> &SsaResult {
        // This would access the actual result stored in the model
        // For now it's a placeholder
        unimplemented!("Access to SSA result not yet implemented")
    }
}

// Add trait implementations for BlockView to access SSA information
impl<'a, S: ModelState> super::control_flow::BlockView<'a, S>
where
    S: HasSsaResult,
{
    pub fn ssa(&self) -> &SsaBlock {
        unimplemented!("Access to block SSA not yet implemented")
    }
}
