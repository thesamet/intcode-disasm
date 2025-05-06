use std::collections::{HashMap, HashSet};

use itertools::Itertools;
use log::{info, trace};

use crate::disasm::{
    v2::ssa_form::{MemoryReferenceType, SsaMemoryReference, VersionedMemoryReference},
    v3::{
        control_flow::FunctionView,
        data_flow::OriginationPoint,
        function_call::result::{CallSiteInfo, CalleeInfo},
        lir::{memory_reference::MemoryReferenceInfo, Expression, ReadAddressExtractor},
        model::{FunctionCallAnalysisComplete, Model, SsaComplete},
        FunctionId, InstructionId, NextKind,
    },
    Error,
};

use super::FunctionCallAnalysisResult;

/// Analyzes function calls in the program
pub struct FunctionCallAnalyzer {
    model: Model<SsaComplete>,
}

impl FunctionCallAnalyzer {
    pub fn new(model: Model<SsaComplete>) -> Self {
        Self { model }
    }

    pub fn run(model: Model<SsaComplete>) -> Result<Model<FunctionCallAnalysisComplete>, Error> {
        Self::new(model).analyze()
    }

    fn analyze(self) -> Result<Model<FunctionCallAnalysisComplete>, Error> {
        info!("Analyzing function calls");
        let mut analysis = FunctionCallAnalysisResult::new();

        // --- Phase 1: Analyze Callees (Revised) ---
        for (function_id, function) in self.model.functions() {
            let entry_block_id = function.entry_block();
            let return_block_id = function.return_block();
            let stack_size = function.stack_size() as i128;

            let mut parameter_entry_vars: HashMap<i128, VersionedMemoryReference> = HashMap::new();

            // Analyze parameters using live_in at entry block
            let entry_flow = function.block(&entry_block_id).data_flow();
            for (live_addressable, points) in &entry_flow.live_in {
                let Ok(live_kind) = MemoryReferenceType::try_from(live_addressable)
                // Use TryFrom
                else {
                    continue;
                };
                let Some(offset) = (&live_kind).to_memory_reference().as_stack_relative() else {
                    // Call trait method on reference
                    continue;
                };
                if offset >= 0
                    || !points
                        .iter()
                        .any(|p| *p != OriginationPoint::FunctionOutput)
                {
                    continue;
                }
                // Found a potential parameter offset `n`
                // Now find the VersionedAddressable with the lowest version for this kind in the function
                if let Some(entry_var) = find_lowest_version_of(&function, &live_kind) {
                    parameter_entry_vars.insert(offset + stack_size, entry_var);
                } else {
                    panic!("Function {function_id}: OperandKind {live_kind:?} is live_in at entry, but no corresponding VersionedAddressable found.");
                }
            }

            let return_writes = if let Some(return_block_id) = return_block_id {
                function
                    .block(&return_block_id)
                    .ssa()
                    .end_state
                    .iter_versions()
                    .filter(|(k, _)| k.is_local_or_parameter())
                    .filter_map(|(k, v)| k.as_stack_relative().map(|r| (r, *v)))
                    .collect()
            } else {
                HashMap::new()
            };

            analysis.functions.insert(
                function_id,
                CalleeInfo {
                    parameter_entry_vars, // Renamed from parameter_reads
                    return_writes,
                },
            );
        }

        // --- Phase 2: Analyze Call Sites ---
        for (calling_function_id, function) in self.model.functions() {
            for (calling_block_id, block) in function.blocks() {
                if let NextKind::FunctionCall(call) = &block.ssa().next {
                    trace!(
                        "Analyzing call site in block {} (func {})",
                        calling_block_id,
                        calling_function_id
                    );
                    let argument_writes: HashMap<i128, VersionedMemoryReference> = self
                        .model
                        .function(&calling_function_id)
                        .block(&calling_block_id)
                        .ssa()
                        .end_state
                        .iter_versions()
                        .filter_map(|(k, v)| {
                            k.as_stack_relative().filter(|r| *r > 0).map(|r| (r, *v))
                        })
                        .collect();
                    let mut return_reads: HashMap<i128, VersionedMemoryReference> = HashMap::new();
                    let mut target_address_var: Option<Expression<SsaMemoryReference>> = None;
                    let mut target_function_id: Option<FunctionId> = None;

                    // Determine Target Function
                    match call.function_addr {
                        Expression::Constant(addr) => {
                            target_function_id = self.model.function_id_by_address(addr as usize);
                            assert!(target_function_id.is_some());
                        }
                        _ => {
                            // Indirect call
                            target_address_var = Some(call.function_addr.clone());
                        }
                    }

                    // Find Return Reads (first reads of [R+n] in return block)
                    let return_values_accessed: &HashMap<i128, InstructionId> = function
                        .block(&call.calling_block)
                        .data_flow()
                        .return_values_accessed
                        .as_ref()
                        .unwrap();

                    for (offset, instr_id) in return_values_accessed {
                        let instr = function
                            .blocks()
                            .find_map(|(_, b)| {
                                b.ssa()
                                    .instructions
                                    .iter()
                                    .find(|i| i.id == *instr_id)
                                    .map(|i| i)
                            })
                            .unwrap();
                        // Manually extract reads like in find_lowest_version_of
                        let mut reads_in_instr: Vec<&SsaMemoryReference> = Vec::new();
                        if let Some(target) = instr.kind.get_write_address() {
                            reads_in_instr.extend(target.extract_read_addresses());
                        }
                        reads_in_instr.extend(
                            instr
                                .kind
                                .collect_source_expressions()
                                .iter()
                                .flat_map(|expr| expr.collect_read_addresses()),
                        );

                        let read_var = *reads_in_instr
                            .iter()
                            // Dereference r once here
                            .filter_map(|r| (*r).as_versioned())
                            .find(|r| r.as_stack_relative() == Some(*offset))
                            .expect("Could not find read variable for return value");
                        return_reads.entry(*offset).or_insert(read_var);
                    }
                    println!("Target function ID: {target_function_id:?}");
                    println!("analysis.functions: {:?}", analysis.functions);
                    let (parameter_map, return_map) =
                        if let Some(target_function_id) = target_function_id {
                            build_call_site_maps(
                                target_function_id,
                                &analysis.functions[&target_function_id],
                                &self.model,
                                &argument_writes,
                                &return_reads,
                            )
                        } else {
                            (HashMap::new(), HashMap::new())
                        };
                    analysis.blocks.insert(
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

        // Return a new model with the updated state
        Ok(self.model.with_function_call_analysis_result(analysis))
    }
}

impl FunctionCallAnalysisResult {
    pub fn get_effective_return_values(
        &self,
        function_id: FunctionId,
    ) -> Option<Vec<(i128, VersionedMemoryReference)>> {
        let callers_csi = self
            .blocks
            .values()
            .filter(|c| c.target_function_id == Some(function_id))
            .collect_vec();
        if callers_csi.is_empty() {
            None
        } else {
            let mut return_reads: HashSet<(i128, VersionedMemoryReference)> = HashSet::new();
            for csi in callers_csi {
                return_reads.extend(
                    csi.return_reads
                        .iter()
                        .map(|(k, v)| (*k, csi.return_map[v])),
                );
            }

            Some(return_reads.iter().sorted().cloned().collect())
        }
    }
}

fn find_lowest_version_of(
    function: &FunctionView<SsaComplete>,
    kind: &MemoryReferenceType,
) -> Option<VersionedMemoryReference> {
    let mut min_var: Option<VersionedMemoryReference> = None;

    let min_var_version = |min_var: Option<VersionedMemoryReference>| {
        min_var.as_ref().map(|var| var.version).unwrap_or(0)
    };

    for (_, block) in function.blocks() {
        // Check Phi results
        for phi in &block.ssa().phi_functions {
            if &phi.result.kind == kind
                && (min_var.is_none() || phi.result.version < min_var_version(min_var))
            {
                min_var = Some(phi.result);
            }
            // Check Phi inputs
            for input_var in phi.inputs.values() {
                if &input_var.kind == kind
                    && (min_var.is_none() || input_var.version < min_var_version(min_var))
                {
                    min_var = Some(*input_var);
                }
            }
        }
        // Check instruction operands (manual extraction for v2::Instruction)
        for instr_node in &block.ssa().instructions {
            let mut reads_in_instr: Vec<&SsaMemoryReference> = Vec::new();

            // Extract reads from write target (for Deref)
            if let Some(target) = instr_node.kind.get_write_address() {
                reads_in_instr.extend(target.extract_read_addresses());
            }
            // Extract reads from source expressions
            reads_in_instr.extend(
                instr_node
                    .kind
                    .collect_source_expressions()
                    .iter()
                    .flat_map(|expr| expr.collect_read_addresses()),
            );

            for ssa_mem_ref in reads_in_instr {
                if let Some(var) = ssa_mem_ref.as_versioned() {
                    if &var.kind == kind
                        && (min_var.is_none() || var.version < min_var_version(min_var))
                    {
                        min_var = Some(*var);
                    }
                }
            }
        }
    }
    min_var
}

fn build_call_site_maps(
    target_id: FunctionId,
    callee_info: &CalleeInfo,
    model: &Model<SsaComplete>,
    argument_writes: &HashMap<i128, VersionedMemoryReference>,
    return_reads: &HashMap<i128, VersionedMemoryReference>,
) -> (
    HashMap<VersionedMemoryReference, VersionedMemoryReference>,
    HashMap<VersionedMemoryReference, VersionedMemoryReference>,
) {
    let mut parameter_map = HashMap::new();
    let mut return_map = HashMap::new();

    let target_function = model.function(&target_id);

    let k = target_function.stack_size() as i128; // Get stack adjustment 'k'

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
            // Note the key/value order: Caller Read -> Callee Write
            return_map.insert(*caller_ret_var, *callee_ret_var);
        }
    }
    (parameter_map, return_map)
}

#[cfg(test)]
mod tests {
    use crate::disasm::{
        parser,
        test_utils::init_logging,
        v2::pretty_print::pretty_print_ssa,
        v3::{
            analysis,
            model::{FunctionCallAnalysisComplete, Model},
            FunctionId,
        },
    };

    struct TestContext {
        model: Model<FunctionCallAnalysisComplete>,
    }

    impl TestContext {
        fn new(assembly: &str) -> Self {
            init_logging();
            let binary = parser::compile(assembly);
            let model = analysis::binary_to_function_calls(binary).unwrap();

            // Extract the main function (always at ID 0)

            TestContext { model }
        }
    }

    #[test]
    fn test_negative_write_not_adding_arg() {
        let assembly = r#"
            R += 3
            [R-2] = 10
            R -= 3
            goto [R]
            "#;
        let ctx = TestContext::new(assembly);
        let call_info = ctx.model.function(&FunctionId::from(0)).callee_info();
        assert_eq!(call_info.parameter_entry_vars.len(), 0);
    }

    #[test]
    fn test_negative_write_multiple_paths() {
        let assembly = r#"
            R += 3
            [R-2] = 10
            [R] = @end
            goto @somefunc
            end:
            R -= 3
            goto [R]

        somefunc:
            R += 2
            R -= 2
            goto [R]
            "#;
        let ctx = TestContext::new(assembly);
        let call_info = ctx.model.function(&FunctionId::from(0)).callee_info();
        pretty_print_ssa(&ctx.model);
        assert_eq!(call_info.parameter_entry_vars.len(), 0);
    }

    #[test]
    fn test_negative_write_adding_arg_if_is_read() {
        let assembly = r#"
            R += 3
            [R-2] = [R-2] + 1
            R -= 3
            goto [R]
            "#;
        let ctx = TestContext::new(assembly);
        let call_info = ctx.model.function(&FunctionId::from(0)).callee_info();
        assert_eq!(call_info.parameter_entry_vars.len(), 1);
    }

    #[test]
    fn test_nested_if_else() {
        let _assembly = r#"
            R += 100                      ; 0: Initial R adjustment for main function
            [R-1] = 10                    ; 2: x = 10
            [R-2] = [R-1] < 5             ; 6: cond1 = (x < 5)
            if ![R-2] goto @else_outer    ; 10: if !cond1 goto else_outer

            ; Then branch of outer if
            [R-3] = [R-1] < 15            ; 13: cond2 = (x < 15)
            if ![R-3] goto @else_inner    ; 17: if !cond2 goto else_inner

            ; Then branch of inner if
            [R-4] = 1                     ; 20: result = 1
            goto @end_inner               ; 24:

            else_inner:
            ; Else branch of inner if
            [R-4] = 2                     ; 27: result = 2

            end_inner:
            goto @end_outer               ; 31:

            else_outer:
            ; Else branch of outer if
            [R-4] = 3                     ; 34: result = 3

            end_outer:
            output([R-4])                 ; 38: output(result)
            R -= 100                      ; 40:
            goto [R]                      ; 42:
        "#;

        let ctx = TestContext::new(_assembly);
        // pretty_print_ssa(&ctx.model);
        assert_eq!(
            ctx.model
                .function(&FunctionId::new(0))
                .callee_info()
                .parameter_entry_vars
                .len(),
            0
        );
    }
}
