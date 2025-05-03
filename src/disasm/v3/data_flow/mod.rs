mod block;
mod result;
mod analyzer;

pub use block::DataFlowBlock;
pub use result::DataFlowResult;
pub use analyzer::DataFlowAnalyzer;

use crate::disasm::v3::model::{Model, ControlFlowGraphComplete, DataFlowComplete};
use std::collections::HashMap;

impl DataFlowAnalyzer {
    pub fn analyze(model: Model<ControlFlowGraphComplete>) -> Model<DataFlowComplete> {
        // Create the data flow result
        let result = DataFlowResult {
            blocks: HashMap::new(),
        };
        
        // Return a new model with the updated state
        Model {
            image_scanner_result: model.image_scanner_result,
            control_flow_graph_result: model.control_flow_graph_result,
            data_flow_result: Some(result),
            ssa_result: None,
            function_call_analysis_result: None,
            marker: std::marker::PhantomData,
        }
    }
}
