use super::result::FunctionCallAnalysisResult;
use crate::disasm::v3::model::{FunctionCallComplete, Model, SsaComplete};
use crate::disasm::Error;
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

    fn analyze(self) -> Result<Model<FunctionCallComplete>, Error> {
        // Create the function call analysis result
        let result = FunctionCallAnalysisResult {
            functions: HashMap::new(),
            blocks: HashMap::new(),
        };

        // Return a new model with the updated state
        Ok(self.model.with_function_call_analysis_result(result))
    }
}
