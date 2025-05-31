use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v3::lir::Expression;
use crate::disasm::v3::ssa::{SsaMemoryReference, VersionedMemoryReference};
// Use LIR MemoryReference
use crate::disasm::v3::model::add_block_view_when;
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
    pub parameter_entry_vars: HashMap<i128, VersionedMemoryReference>, // Placeholder type

    /// Return values defined by this function.
    /// Maps the return offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within *this function* that represents the *last write* to that location before returning.
    pub return_writes: HashMap<i128, VersionedMemoryReference>, // Placeholder type
}

#[derive(Debug, Clone)]
pub struct CallSiteInfo {
    pub calling_block_id: BlockId, // Block containing the call instruction.
    pub calling_function_id: FunctionId, // Function containing the call.

    /// The target function being called, if directly known (e.g., `goto @label`).
    /// This would be the FunctionId of the callee. None for indirect calls.
    pub target_function_id: Option<FunctionId>,

    /// The SSA variable representing the target address for indirect calls (`goto [addr]`).
    pub target_address_var: Option<Expression<SsaMemoryReference>>,

    /// Arguments provided *by the caller* before the call.
    /// Maps the argument offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within the *caller function* that holds the value written to that location.
    pub argument_writes: HashMap<i128, VersionedMemoryReference>,

    /// Return values accessed *by the caller* after the call returns.
    /// Maps the return offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within the *caller function* that reads the value from that location.
    pub return_reads: HashMap<i128, VersionedMemoryReference>,

    /// BlockId where execution resumes in the caller after the function returns.
    pub return_block_id: BlockId,

    /// Maps caller's argument write VersionedAddressable to callee's parameter entry VersionedAddressable.
    /// Only populated for direct calls.
    pub parameter_map: HashMap<VersionedMemoryReference, VersionedMemoryReference>,

    /// Maps caller's return read VersionedAddressable to callee's parameter entry VersionedAddressable.
    /// Only populated for direct calls.
    pub return_map: HashMap<VersionedMemoryReference, VersionedMemoryReference>,
}

#[derive(Debug, Clone)]
pub struct FunctionCallAnalysisResult {
    pub functions: HashMap<FunctionId, CalleeInfo>, // Use v3 CalleeInfo
    pub blocks: HashMap<BlockId, CallSiteInfo>,     // Use v3 CallSiteInfo
}

impl Default for FunctionCallAnalysisResult {
    fn default() -> Self {
        Self::new()
    }
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
             impl<'a, S: crate::disasm::v3::model::ModelState> crate::disasm::v3::cfg::FunctionView<'a, S>
             where
                 S: crate::disasm::v3::model::[<Has $result_type Result>],
             {
                 pub fn $result_var(&self) -> &'a $info_type {
                     self.model
                         .[<$result_type:snake:lower _result>]()
                         .functions
                         .get(&self.function_id())
                         .as_ref()
                         .unwrap()
                 }
             }
         }
     };
 }
pub(crate) use add_function_view_when;

add_function_view_when!(FunctionCallAnalysis, callee_info, CalleeInfo);
