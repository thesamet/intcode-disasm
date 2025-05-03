use crate::disasm::v3::model::{Model, SsaComplete, FunctionCallComplete};
use crate::disasm::Error;
use super::result::FunctionCallAnalysisResult;
use std::collections::HashMap;

/// Analyzes function calls in the program
pub struct FunctionCallAnalyzer;

impl FunctionCallAnalyzer {
    pub fn new() -> Self {
        Self {}
    }
    
    pub fn run(&self, model: Model<SsaComplete>) -> Result<Model<FunctionCallComplete>, Error> {
        let model = self.analyze(model)?;
        Ok(model)
    }
    
    fn analyze(&self, model: Model<SsaComplete>) -> Result<Model<FunctionCallComplete>, Error> {
        // Create the function call analysis result
        let result = FunctionCallAnalysisResult {
            functions: HashMap::new(),
            blocks: HashMap::new(),
        };
        
        // Return a new model with the updated state
        Ok(Model {
            image_scanner_result: model.image_scanner_result,
            control_flow_graph_result: model.control_flow_graph_result,
            data_flow_result: model.data_flow_result,
            ssa_result: model.ssa_result,
            function_call_analysis_result: Some(result),
            marker: std::marker::PhantomData,
        })
    }
}
