use crate::disasm::v3::model::{Model, SsaComplete, FunctionCallComplete};
use crate::disasm::Error;
use super::result::FunctionCallAnalysisResult;
use std::collections::HashMap;

/// Analyzes function calls in the program
pub struct FunctionCallAnalyzer {
    model: Model<SsaComplete>,
}

impl FunctionCallAnalyzer {
    pub fn new(model: Model<SsaComplete>) -> Self {
        Self { model }
    }
    
    pub fn run(model: Model<SsaComplete>) -> Result<Model<FunctionCallComplete>, Error> {
        let analyzer = Self::new(model);
        analyzer.analyze()
    }
    
    fn analyze(&self) -> Result<Model<FunctionCallComplete>, Error> {
        // Create the function call analysis result
        let result = FunctionCallAnalysisResult {
            functions: HashMap::new(),
            blocks: HashMap::new(),
        };
        
        // Return a new model with the updated state
        Ok(Model {
            image_scanner_result: self.model.image_scanner_result.clone(),
            control_flow_graph_result: Some(self.model.control_flow_graph_result().clone()), // Wrap in Some
            data_flow_result: Some(self.model.data_flow_result().clone()), // Wrap in Some
            ssa_result: Some(self.model.ssa_result().clone()), // Wrap in Some
            function_call_analysis_result: Some(result),
            marker: std::marker::PhantomData,
        })
    }
}
