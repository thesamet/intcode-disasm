use std::collections::HashMap;
use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v3::listeners::function_call_analyzer::{CallSiteInfo, CalleeInfo};

#[derive(Debug, Clone)]
pub struct FunctionCallAnalysisResult {
    pub functions: HashMap<FunctionId, CalleeInfo>,
    pub blocks: HashMap<BlockId, CallSiteInfo>,
}
