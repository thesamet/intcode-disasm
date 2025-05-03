mod result;
mod analyzer;

pub use result::FunctionCallAnalysisResult;
pub use analyzer::FunctionCallAnalyzer;

use crate::disasm::v3::model::{Model, SsaComplete, FunctionCallComplete};
use std::collections::HashMap;

impl FunctionCallAnalyzer {
    pub fn analyze(model: Model<SsaComplete>) -> Model<FunctionCallComplete> {
        // Create the function call analysis result
        let result = FunctionCallAnalysisResult {
            functions: HashMap::new(),
            blocks: HashMap::new(),
        };
        
        // Return a new model with the updated state
        Model {
            image_scanner_result: model.image_scanner_result,
            control_flow_graph_result: model.control_flow_graph_result,
            data_flow_result: model.data_flow_result,
            ssa_result: model.ssa_result,
            function_call_analysis_result: Some(result),
            marker: std::marker::PhantomData,
        }
    }
}
