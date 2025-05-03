mod block;
mod result;
mod analyzer;

pub use block::DataFlowBlock;
pub use result::DataFlowResult;
pub use analyzer::DataFlowAnalyzer;

use crate::disasm::v3::id_types::BlockId;
use crate::disasm::v3::model::{HasDataFlowResult, Model, ModelState};

impl<S: ModelState> Model<S>
where
    S: HasDataFlowResult,
{
    pub fn data_flow_result(&self) -> &DataFlowResult {
        // This would access the actual result stored in the model
        // For now it's a placeholder
        unimplemented!("Access to data flow result not yet implemented")
    }
}

// Add trait implementations for BlockView to access data flow information
impl<'a, S: ModelState> super::control_flow::BlockView<'a, S>
where
    S: HasDataFlowResult,
{
    pub fn data_flow(&self) -> &DataFlowBlock {
        unimplemented!("Access to block data flow not yet implemented")
    }
}
