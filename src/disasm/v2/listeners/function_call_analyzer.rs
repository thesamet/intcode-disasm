use std::collections::HashMap;

use crate::disasm::v2::{
    model::{BlockId, FunctionId},
    ssa_form::SsaVar,
};

/// Top-level result container for function call analysis.
pub struct FunctionCallAnalysis {
    /// Information about each function primarily from its perspective as a *callee*.
    /// Keyed by the FunctionId of the callee.
    pub callee_info: HashMap<FunctionId, CalleeInfo>,

    /// Information about each specific call instruction site.
    /// Keyed by the BlockId containing the function call instruction (`goto @func` or `goto [addr]`).
    pub call_site_info: HashMap<BlockId, CallSiteInfo>,
}

/// Information about a function when it's being called (Callee's perspective).
#[derive(Debug, Clone)]
pub struct CalleeInfo {
    pub function_id: FunctionId,
    pub entry_block: BlockId, // BlockId where the function code starts.

    /// Parameters expected by this function.
    /// Maps the parameter offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within *this function* that represents the *first read* of that parameter.
    pub parameter_reads: HashMap<i128, SsaVar>,

    /// Return values defined by this function.
    /// Maps the return offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within *this function* that represents the *last write* to that location before returning.
    pub return_writes: HashMap<i128, SsaVar>,
}

/// Information about a specific location where a function call occurs (Caller's perspective).
#[derive(Debug, Clone)]
pub struct CallSiteInfo {
    pub calling_block_id: BlockId, // Block containing the call instruction.
    pub calling_function_id: FunctionId, // Function containing the call.

    /// The target function being called, if directly known (e.g., `goto @label`).
    /// This would be the FunctionId of the callee. None for indirect calls.
    pub target_function_id: Option<FunctionId>,

    /// The SSA variable representing the target address for indirect calls (`goto [addr]`).
    pub target_address_var: Option<SsaVar>,

    /// Arguments provided *by the caller* before the call.
    /// Maps the argument offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within the *caller function* that holds the value written to that location.
    pub argument_writes: HashMap<i128, SsaVar>,

    /// Return values accessed *by the caller* after the call returns.
    /// Maps the return offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within the *caller function* that reads the value from that location.
    pub return_reads: HashMap<i128, SsaVar>,

    /// BlockId where execution resumes in the caller after the function returns.
    pub return_block_id: BlockId,
}
