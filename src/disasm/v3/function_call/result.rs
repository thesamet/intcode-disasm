use crate::disasm::v3::common::CallSiteInfo;
use crate::disasm::v3::control_flow::FunctionView;
use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v3::lir::MemoryReference;
// Use LIR MemoryReference
use crate::disasm::v3::model::{add_block_view_when, HasFunctionCallAnalysisResult, ModelState};
use std::collections::HashMap;

/// Information about a function when it's being called (Callee's perspective).
/// Based on v2 CalleeInfo.
#[derive(Debug, Clone, Default, PartialEq, Eq)] // Added derives
pub struct CalleeInfo {
    // Made public
    /// Parameters expected by this function.
    /// Maps the parameter offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within *this function* that represents the *first read* of that parameter,
    /// typically near the function entry.
    // TODO: Replace VersionedMemoryReference with the appropriate v3 SSA type when available
    pub parameter_entry_vars: HashMap<i128, MemoryReference>, // Placeholder type

    /// Return values defined by this function.
    /// Maps the return offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within *this function* that represents the *last write* to that location before returning.
    // TODO: Replace VersionedMemoryReference with the appropriate v3 SSA type when available
    pub return_writes: HashMap<i128, MemoryReference>, // Placeholder type
}

#[derive(Debug, Clone)]
pub struct FunctionCallAnalysisResult {
    pub functions: HashMap<FunctionId, CalleeInfo>, // Use v3 CalleeInfo
    pub blocks: HashMap<BlockId, CallSiteInfo>,     // Use v3 CallSiteInfo
}

impl FunctionCallAnalysisResult {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            blocks: HashMap::new(),
        }
    }
}

add_block_view_when!(FunctionCallAnalysis, call_site_info, CallSiteInfo);
// Add add_function_view_when for CalleeInfo
macro_rules! add_function_view_when {
     ($result_type:ident, $result_var:ident, $info_type:ty) => {
         paste::paste! {
             impl<'a, S: crate::disasm::v3::model::ModelState> crate::disasm::v3::control_flow::FunctionView<'a, S>
             where
                 S: crate::disasm::v3::model::[<Has $result_type Result>],
             {
                 pub fn $result_var(&self) -> &$info_type {
                     self.model
                         .[<$result_type:snake:lower _result>]()
                         .functions
                         .get(&self.function_id())
                         .unwrap_or_else(|| {
                             panic!(
                                 "Could not find {} information for function {}",
                                 stringify!($result_var),
                                 self.function_id()
                             )
                         })
                 }
             }
         }
     };
 }
pub(crate) use add_function_view_when;

add_function_view_when!(FunctionCallAnalysis, callee_info, CalleeInfo);
