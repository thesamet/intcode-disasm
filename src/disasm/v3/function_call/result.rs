use crate::disasm::v3::control_flow::FunctionView;
use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v3::listeners::function_call_analyzer::{CallSiteInfo, CalleeInfo};
use crate::disasm::v3::model::{add_block_view_when, HasFunctionCallAnalysisResult, ModelState};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct FunctionCallAnalysisResult {
    pub functions: HashMap<FunctionId, CalleeInfo>,
    pub blocks: HashMap<BlockId, CallSiteInfo>,
}

add_block_view_when!(FunctionCallAnalysis, call_site_info, CallSiteInfo);
