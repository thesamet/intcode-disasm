mod result;
mod analyzer;

pub use result::FunctionCallAnalysisResult;
pub use analyzer::FunctionCallAnalyzer;

use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v3::model::{HasFunctionCallAnalysisResult, Model, ModelState};
use crate::disasm::v3::listeners::function_call_analyzer::{CallSiteInfo, CalleeInfo};

impl<S: ModelState> Model<S>
where
    S: HasFunctionCallAnalysisResult,
{
    pub fn function_call_analysis_result(&self) -> &FunctionCallAnalysisResult {
        // This would access the actual result stored in the model
        // For now it's a placeholder
        unimplemented!("Access to function call analysis result not yet implemented")
    }
}

// Add trait implementations for views to access function call information
impl<'a, S: ModelState> super::control_flow::FunctionView<'a, S>
where
    S: HasFunctionCallAnalysisResult,
{
    pub fn callee_info(&self) -> &CalleeInfo {
        unimplemented!("Access to callee info not yet implemented")
    }
}

impl<'a, S: ModelState> super::control_flow::BlockView<'a, S>
where
    S: HasFunctionCallAnalysisResult,
{
    pub fn call_site_info(&self) -> &CallSiteInfo {
        unimplemented!("Access to call site info not yet implemented")
    }
}
