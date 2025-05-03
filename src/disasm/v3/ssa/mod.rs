mod block;
mod result;
mod converter;

pub use block::SsaBlock;
pub use result::SsaResult;
pub use converter::SsaConverter;

use crate::disasm::v3::model::{Model, DataFlowComplete, SsaComplete};
use std::collections::HashMap;

impl SsaConverter {
    pub fn analyze(model: Model<DataFlowComplete>) -> Model<SsaComplete> {
        // Create the SSA result
        let result = SsaResult {
            blocks: HashMap::new(),
        };
        
        // Return a new model with the updated state
        Model {
            image_scanner_result: model.image_scanner_result,
            control_flow_graph_result: model.control_flow_graph_result,
            data_flow_result: model.data_flow_result,
            ssa_result: Some(result),
            function_call_analysis_result: None,
            marker: std::marker::PhantomData,
        }
    }
}
