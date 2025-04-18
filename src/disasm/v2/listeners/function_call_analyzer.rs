use crate::disasm::v2::{
    control_flow::NextKind,
    dispatching::{EventCollector, EventListener},
    events::{self, Event},
    instructions::OperandKind,
    model::{BlockId, FunctionId, ProgramModel},
    ssa_form::{SsaFunction, SsaOperand, SsaResult, SsaVar},
};
use itertools::Itertools;
use log::{debug, trace};
use std::collections::{HashMap, HashSet};

/// Top-level result container for function call analysis.
#[derive(Debug, Clone, Default)]
pub struct FunctionCallAnalysis {
    /// Information about each function primarily from its perspective as a *callee*.
    /// Keyed by the FunctionId of the callee.
    pub callee_info: HashMap<FunctionId, CalleeInfo>,

    /// Information about each specific call instruction site.
    /// Keyed by the BlockId containing the function call instruction (`goto @func` or `goto [addr]`).
    pub call_site_info: HashMap<BlockId, CallSiteInfo>,
}

impl FunctionCallAnalysis {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Information about a function when it's being called (Callee's perspective).
#[derive(Debug, Clone)]
pub struct CalleeInfo {
    /// Parameters expected by this function.
    /// Maps the parameter offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within *this function* that represents the *first read* of that parameter,
    /// typically near the function entry.
    pub parameter_entry_vars: HashMap<i128, SsaVar>,

    /// Return values defined by this function.
    /// Maps the return offset `n` (from `[R+n]`, n > 0) to the SSA variable
    /// within *this function* that represents the *last write* to that location before returning.
    pub return_writes: HashMap<i128, SsaVar>,
}

/// Information about a specific location where a function call occurs (Caller's perspective).
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CallSiteInfo {
    pub calling_block_id: BlockId, // Block containing the call instruction.
    pub calling_function_id: FunctionId, // Function containing the call.

    /// The target function being called, if directly known (e.g., `goto @label`).
    /// This would be the FunctionId of the callee. None for indirect calls.
    pub target_function_id: Option<FunctionId>,

    /// The SSA variable representing the target address for indirect calls (`goto [addr]`).
    pub target_address_var: Option<SsaOperand>,

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

    /// Maps caller's argument write SsaVar to callee's parameter entry SsaVar.
    /// Only populated for direct calls.
    pub parameter_map: HashMap<SsaVar, SsaVar>,

    /// Maps callee's return write SsaVar to caller's return read SsaVar.
    /// Only populated for direct calls.
    pub return_map: HashMap<SsaVar, SsaVar>,
}

impl FunctionCallAnalysis {
    pub fn get_effective_return_values(&self, function_id: FunctionId) -> Option<Vec<SsaVar>> {
        let callers_csi = self
            .call_site_info
            .values()
            .filter(|c| c.target_function_id == Some(function_id))
            .collect_vec();
        if callers_csi.is_empty() {
            None
        } else {
            let mut return_reads = HashSet::new();
            for csi in callers_csi {
                return_reads.extend(csi.return_map.keys());
            }

            Some(return_reads.iter().sorted().cloned().collect())
        }
    }
}

fn find_lowest_version_ssa_var(function: &SsaFunction, kind: &OperandKind) -> Option<SsaVar> {
    let mut min_var: Option<SsaVar> = None;

    let min_var_version =
        |min_var: Option<SsaVar>| min_var.as_ref().map(|var| var.version).unwrap_or(0);

    for block in function.blocks.values() {
        // Check Phi results
        for phi in &block.phi_functions {
            if &phi.result.to_operand().kind == kind
                && (min_var.is_none() || phi.result.version < min_var_version(min_var))
            {
                min_var = Some(phi.result);
            }
            // Check Phi inputs
            for input_var in phi.inputs.values() {
                if &input_var.to_operand().kind == kind
                    && (min_var.is_none() || input_var.version < min_var_version(min_var))
                {
                    min_var = Some(*input_var);
                }
            }
        }
        // Check instruction operands
        for instr in &block.instructions {
            // Consider all read operands.
            let operands_in_instr = instr.reads();
            for var in operands_in_instr {
                if let SsaOperand::Variable(var) = var {
                    if &var.to_operand().kind == kind
                        && (min_var.is_none() || var.version < min_var_version(min_var))
                    {
                        min_var = Some(var);
                    }
                }
            }
        }
    }
    min_var
}

#[derive(Default)]
pub struct FunctionCallAnalyzer {}

impl FunctionCallAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    fn analyze(&self, model: &ProgramModel, ssa_result: &SsaResult) -> FunctionCallAnalysis {
        let mut analysis = FunctionCallAnalysis::new();

        // --- Phase 1: Analyze Callees (Revised) ---
        for (&function_id, function) in &ssa_result.functions {
            let entry_block_id = model.get_function(function.original_id).entry_block;
            let return_block_id = model.get_function(function.original_id).return_block;
            let stack_size = model.get_function(function.original_id).stack_size as i128;

            let mut parameter_entry_vars: HashMap<i128, SsaVar> = HashMap::new();

            // Analyze parameters using live_in at entry block
            let entry_flow = model
                .get_data_flow_result()
                .expect("Data flow result not found")
                .block_results
                .get(&entry_block_id)
                .unwrap();
            for live_kind in &entry_flow.live_in {
                if let OperandKind::RelativeMemory(offset) = live_kind {
                    if *offset < 0 {
                        // Found a potential parameter offset `n`
                        // Now find the SsaVar with the lowest version for this kind in the function
                        if let Some(entry_var) = find_lowest_version_ssa_var(function, live_kind) {
                            parameter_entry_vars.insert(*offset + stack_size, entry_var);
                        } else {
                            panic!("Function {}: OperandKind {:?} is live_in at entry, but no corresponding SsaVar found.", function_id, live_kind);
                        }
                    }
                }
            }

            let return_writes = if let Some(return_block_id) = return_block_id {
                model
                    .get_ssa_result()
                    .unwrap()
                    .functions
                    .get(&function_id)
                    .unwrap()
                    .blocks
                    .get(&return_block_id)
                    .unwrap()
                    .end_state
                    .iter()
                    .filter_map(|(k, v)| {
                        k.get_relative_memory().filter(|r| *r < 0).map(|r| (r, *v))
                    })
                    .collect()
            } else {
                HashMap::new()
            };

            analysis.callee_info.insert(
                function_id,
                CalleeInfo {
                    parameter_entry_vars, // Renamed from parameter_reads
                    return_writes,
                },
            );
            trace!(
                "Function {}: CalleeInfo generated. Params: {}, Returns: {}",
                function_id,
                analysis.callee_info[&function_id]
                    .parameter_entry_vars
                    .len(),
                analysis.callee_info[&function_id].return_writes.len()
            );
        }

        // --- Phase 2: Analyze Call Sites ---
        for (&calling_function_id, function) in &ssa_result.functions {
            for (&calling_block_id, block) in &function.blocks {
                if let NextKind::FunctionCall(call) = &block.next {
                    trace!(
                        "Analyzing call site in block {} (func {})",
                        calling_block_id,
                        calling_function_id
                    );
                    let argument_writes: HashMap<i128, SsaVar> = model
                        .get_ssa_result()
                        .unwrap()
                        .functions
                        .get(&calling_function_id)
                        .unwrap()
                        .blocks
                        .get(&calling_block_id)
                        .unwrap()
                        .end_state
                        .iter()
                        .filter_map(|(k, v)| {
                            k.get_relative_memory().filter(|r| *r > 0).map(|r| (r, *v))
                        })
                        .collect();
                    let mut return_reads: HashMap<i128, SsaVar> = HashMap::new();
                    let mut target_address_var: Option<SsaOperand> = None;
                    let mut target_function_id: Option<FunctionId> = None;

                    // Determine Target Function
                    match call.function_addr.to_operand().kind {
                        OperandKind::Immediate(addr) => {
                            target_function_id = Some(FunctionId::from(addr as usize));
                        }
                        _ => {
                            // Indirect call
                            target_address_var = Some(call.function_addr);
                        }
                    }

                    // Find Return Reads (first reads of [R+n] in return block)
                    let return_values_accessed = model
                        .get_data_flow_result()
                        .unwrap()
                        .block_results
                        .get(&call.calling_block)
                        .unwrap()
                        .call_site_info
                        .clone()
                        .unwrap()
                        .return_values_accessed;

                    for (offset, instr_id) in return_values_accessed {
                        let instr = function
                            .blocks
                            .values()
                            .flat_map(|b| b.instructions.iter())
                            .find(|i| i.id == instr_id)
                            .unwrap();
                        let read_var = *instr
                            .reads()
                            .iter()
                            .find(|r| r.to_operand().kind.get_relative_memory() == Some(offset))
                            .unwrap();
                        return_reads
                            .entry(offset)
                            .or_insert(*read_var.as_variable().unwrap());
                    }
                    let (parameter_map, return_map) =
                        if let Some(target_function_id) = target_function_id {
                            populate_call_site_maps(
                                target_function_id,
                                &analysis,
                                model,
                                &argument_writes,
                                &return_reads,
                            )
                        } else {
                            (HashMap::new(), HashMap::new())
                        };
                    analysis.call_site_info.insert(
                        calling_block_id,
                        CallSiteInfo {
                            calling_block_id,
                            calling_function_id,
                            target_function_id,
                            target_address_var,
                            argument_writes,
                            return_reads,
                            return_block_id: call.return_block,
                            parameter_map,
                            return_map,
                        },
                    );
                }
            }
        }

        analysis
    }
}

fn populate_call_site_maps(
    target_id: FunctionId,
    analysis: &FunctionCallAnalysis,
    model: &ProgramModel,
    argument_writes: &HashMap<i128, SsaVar>,
    return_reads: &HashMap<i128, SsaVar>,
) -> (HashMap<SsaVar, SsaVar>, HashMap<SsaVar, SsaVar>) {
    let mut parameter_map = HashMap::new();
    let mut return_map = HashMap::new();
    let Some(callee_info) = analysis.callee_info.get(&target_id) else {
        panic!("Missing callee info for function {}", target_id);
    };

    let Some(target_function) = model.get_functions().get(&target_id) else {
        panic!("Missing function details for function {}", target_id);
    };

    let k = target_function.stack_size as i128; // Get stack adjustment 'k'

    // Build parameter map: Caller Argument Write (+caller_offset) -> Callee Parameter Entry Read (+caller_offset - k)
    for (caller_offset, caller_arg_var) in argument_writes {
        // Calculate the corresponding negative offset used by the callee
        let callee_offset = caller_offset - k;
        if let Some(callee_param_var) = callee_info.parameter_entry_vars.get(&callee_offset) {
            parameter_map.insert(*caller_arg_var, *callee_param_var);
        }
    }

    // Build return map: Callee Return Write (+caller_offset - k) -> Caller Return Read (+caller_offset)
    for (caller_offset, caller_ret_var) in return_reads {
        // Calculate the corresponding negative offset used by the callee for the write
        let callee_offset = caller_offset - k;
        if let Some(callee_ret_var) = callee_info.return_writes.get(&callee_offset) {
            // Note the key/value order: Callee Write -> Caller Read
            return_map.insert(*callee_ret_var, *caller_ret_var);
        }
    }
    (parameter_map, return_map)
}

impl EventListener<Event, ProgramModel> for FunctionCallAnalyzer {
    fn on_event(
        &mut self,
        model: &mut ProgramModel,
        event: Event,
        collector: &mut EventCollector<Event>,
    ) {
        if let Event::SsaConversionComplete(_) = event {
            debug!("Starting function call analysis...");
            if let Some(ssa_result) = model.get_ssa_result() {
                let analysis_result = self.analyze(model, ssa_result);
                model.set_function_call_analysis(analysis_result);
                debug!("Function call analysis complete.");
                collector.publish(events::FunctionCallAnalysisComplete {});
            } else {
                log::error!(
                    "Cannot perform function call analysis: SSA result not found in model."
                );
            }
        }
    }
}
