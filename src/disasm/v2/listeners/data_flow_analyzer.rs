use std::collections::HashMap;
use std::collections::HashSet;

use itertools::Itertools;
use log::debug;

use crate::disasm::v2::control_flow::Block;
use crate::disasm::v2::data_flow::{
    BlockDataFlow, BlockNativeDataFlow, CallSiteInfo, Definition, NativeCallSiteInfo,
    NativeDefinition, NativeOriginationPoint, OriginationPoint,
};
use crate::disasm::v2::events::DataFlowAnalysisPhaseComplete;
use crate::disasm::v2::events::FunctionDataFlowAnalysisComplete;
use crate::disasm::v2::instructions::Expression;
use crate::disasm::v2::instructions::Instruction;
use crate::disasm::v2::instructions::MemoryReference;
use crate::disasm::v2::instructions::MemoryReferenceInfo;
use crate::disasm::v2::model::Function;
use crate::disasm::v2::native::{Operand, OperandKind};
use crate::disasm::v2::ssa_form::MemoryReferenceType;
use crate::disasm::v2::{
    control_flow::NextKind,
    data_flow::DataFlowResult,
    events::{self, FunctionCfgBuilt, ModelEventListener},
    model::{BlockId, ProgramModel},
};
use crate::disasm::v3::common::FunctionCall;
use crate::disasm::v3::FunctionId;

pub struct DataFlowAnalyzer {}

impl DataFlowAnalyzer {
    pub fn new() -> Self {
        DataFlowAnalyzer {}
    }

    /// Performs the main data flow analysis passes for a given function.
    fn analyze_function(model: &ProgramModel, func_id: FunctionId, df_result: &mut DataFlowResult) {
        let func = model.get_function(func_id);
        let block_ids = &func.all_block_ids;

        // Pass 1: Initialize gen, use_before_def and function_returns_in for each block
        Self::initialize_gen_use_func_in(model, block_ids, df_result);

        // Pass 2: compute function_returns_out and function_returns_in for all blocks (forward analysis)
        Self::run_function_returns_analysis(model, block_ids, df_result);

        // Pass 3: Reaching Definitions (Forward Analysis)
        Self::run_reaching_definitions_analysis(model, func, df_result);

        // Pass 4: Liveness Analysis (Backward Analysis)
        Self::run_liveness_analysis(model, func, block_ids, df_result);

        debug!("Data Flow Analysis passes complete for {}", func_id);
    }

    /// Pass 1: Initializes gen, use_before_def and function_returns_in sets for all blocks in the function.
    fn initialize_gen_use_func_in(
        model: &ProgramModel,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
    ) {
        for &block_id in block_ids {
            let block = model.get_block(block_id);
            let block_flow = df_result.block_results.entry(block_id).or_default();
            let low_flow = df_result.low_block_results.entry(block_id).or_default();

            let mut defined_in_block = HashSet::new();
            let mut low_defined_in_block = HashSet::new();

            block_flow.writes_above_r = false;
            low_flow.writes_above_r = false;

            for instr in &block.low_instructions {
                // Calculate USE for this instruction
                for r in instr.kind.collect_read_addresses().into_iter() {
                    if !low_defined_in_block.contains(r) {
                        low_flow.use_before_def.insert((*r).clone(), instr.id);
                    }
                }

                // Calculate GEN for this instruction
                if let Some(write_operand) = instr.kind.get_write_address() {
                    low_flow
                        .gen
                        .insert(write_operand.clone(), (instr.id, write_operand.clone()));
                    low_defined_in_block.insert(write_operand.clone());

                    if let Some(n) = write_operand.as_stack_relative() {
                        if n > 0 {
                            low_flow.writes_above_r = true;
                        }
                    }
                }
            }

            for instr in &block.native_instructions {
                // Calculate USE for this instruction
                for read_operand in instr.reads() {
                    if !defined_in_block.contains(&read_operand.kind) {
                        block_flow
                            .use_before_def
                            .insert(read_operand.kind, instr.id);
                    }
                }

                // Calculate GEN for this instruction
                if let Some(write_operand) = instr.writes() {
                    block_flow
                        .gen
                        .insert(write_operand.kind, (instr.id, write_operand.clone()));
                    defined_in_block.insert(write_operand.kind);
                    if let Some(n) = write_operand.kind.get_relative_memory() {
                        if n > 0 {
                            block_flow.writes_above_r = true;
                        }
                    }
                }
            }

            // Low-level function returns
            low_flow.function_returns_in = block
                .predecessors
                .iter()
                .filter_map(|p| p.get_function_call_returns())
                .cloned()
                .collect();

            debug!(
                "Block {}: GEN={:?}, USE={:?}",
                block_id,
                block_flow.gen.keys().collect::<Vec<_>>(),
                block_flow.use_before_def
            );
        }
    }

    // Pass 2: calculate function returns
    fn run_function_returns_analysis(
        model: &ProgramModel,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            for &block_id in block_ids {
                // Low-level function returns
                let new_low_func_in =
                    Self::calculate_low_function_returns_in(model, block_id, df_result);

                // Update low-level block's IN set if changed
                let low_flow = df_result.low_block_results.get_mut(&block_id).unwrap();
                if new_low_func_in != low_flow.function_returns_in {
                    debug!("Block {:?}: Low FunctionReturnsIn changed", block_id);
                    low_flow.function_returns_in = new_low_func_in.clone();
                    changed = true;
                }
                if !low_flow.writes_above_r && low_flow.function_returns_out != new_low_func_in {
                    low_flow.function_returns_out = new_low_func_in;
                    changed = true;
                }
            }
        }
    }

    fn calculate_low_function_returns_in(
        model: &ProgramModel,
        block_id: BlockId,
        df_result: &DataFlowResult,
    ) -> HashSet<FunctionCall<MemoryReference>> {
        let block = model.get_block(block_id);
        let low_flow = df_result.low_block_results.get(&block_id).unwrap();
        let mut new_func_in = low_flow.function_returns_in.clone();

        // If this block is a return from a function call, we do not change new_func_in
        if !block
            .predecessors
            .iter()
            .any(|p| p.get_function_call_returns().is_some())
        {
            for pred in block.predecessors.iter() {
                // Update block's IN set if changed
                let pred_block_id = pred.source_block_id();
                let pred_block = df_result.low_block_results.get(&pred_block_id).unwrap();
                let pred_function_returns_out = pred_block.function_returns_out.clone();
                new_func_in.extend(pred_function_returns_out);
            }
        }
        new_func_in
    }

    /// Pass 3: Computes Reaching Definitions iteratively.
    fn run_reaching_definitions_analysis(
        model: &ProgramModel,
        func: &Function,
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            for block_id in &func.all_block_ids {
                let block = model.get_block(*block_id);
                // Low-level definitions
                let new_low_defs_in = Self::calculate_low_defs_in(func, block, df_result);

                // Update low-level block's IN set if changed
                let low_flow = df_result.low_block_results.get_mut(&block_id).unwrap();
                if new_low_defs_in != low_flow.defs_in {
                    debug!("Block {:?}: Low DefsIn changed", block_id);
                    low_flow.defs_in = new_low_defs_in;
                    changed = true; // Continue iteration if IN changed
                }

                // Calculate low-level OUT set: OUT = (IN - KILL) U GEN
                let low_killed_kinds: HashSet<&MemoryReference> = low_flow.gen.keys().collect();
                let mut low_current_defs_out = low_flow.defs_in.clone();
                low_current_defs_out.retain(|def| !low_killed_kinds.contains(&def.kind));

                // Add low-level GEN set
                for (kind, (instruction_id, _)) in &low_flow.gen {
                    low_current_defs_out.insert(Definition {
                        source: OriginationPoint::Instruction(*instruction_id),
                        kind: kind.clone(),
                        block_id: *block_id,
                    });
                }

                // In we call a function at the end of the block, this block doesn't let [R+n]
                // defintions flow forward.
                if matches!(block.next, NextKind::FunctionCall(_)) {
                    low_current_defs_out.retain(|d| !d.kind.is_outgoing_parameter());
                }

                // Update low-level block's OUT set if changed
                if low_current_defs_out != low_flow.defs_out {
                    debug!("Block {:?}: Low DefsOut changed", block_id);
                    low_flow.defs_out = low_current_defs_out;
                    changed = true;
                }
            }
        }
    }

    /// Calculates the low-level Defs-In set for a single block based on its predecessors.
    fn calculate_low_defs_in(
        function: &Function,
        block: &Block,
        df_result: &DataFlowResult,
    ) -> HashSet<Definition> {
        let mut new_defs_in = HashSet::new();

        for pred_kind in &block.predecessors {
            let pred_block_id = pred_kind.source_block_id();
            let pred_block = df_result.low_block_results.get(&pred_block_id);
            let pred_flow = pred_block.as_ref().unwrap();

            new_defs_in.extend(pred_flow.defs_out.iter().cloned());
        }

        if function.entry_block == block.id {
            // Create synthetic definitions for any potential input parameters
            // to this function. We take the union of all the use_before_def sets
            // for all blocks in the function, since it is a superset (which is still
            // smaller than all the reads).
            for &other_block_id in &function.all_block_ids {
                let other_flow = df_result.low_block_results.get(&other_block_id).unwrap();
                new_defs_in.extend(
                    other_flow
                        .use_before_def
                        .keys()
                        .filter(|k| (*k).is_local_or_parameter())
                        .map(|k| Definition {
                            source: OriginationPoint::FunctionInput,
                            kind: k.clone(),
                            block_id: block.id,
                        }),
                )
            }
        }

        new_defs_in
    }

    /// Pass 4: Computes Liveness iteratively.
    fn run_liveness_analysis(
        model: &ProgramModel,
        function: &Function,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            // Iterate backwards - often converges faster for backward analyses like liveness
            for &block_id in block_ids.iter().rev() {
                // Native liveness
                let new_live_out = Self::calculate_live_out(model, function, block_id, df_result);

                // Update block's OUT set if changed
                let block_flow = df_result.block_results.get_mut(&block_id).unwrap();
                if new_live_out != block_flow.live_out {
                    debug!(
                        "Block {:?}: LiveOut changed to {:?}",
                        block_id, new_live_out
                    );
                    block_flow.live_out = new_live_out;
                    changed = true; // Continue iteration
                }

                // Calculate IN set: IN = USE U ((OUT U potential_function_call_params) - DEF)
                // potential_function_call_params are all incoming positive relative memory operands
                // if there is a function call at this block.
                let defined_kinds: HashSet<OperandKind> = block_flow.gen.keys().cloned().collect();
                let mut current_live_in = block_flow.live_out.clone();
                // add potential_function_call_params.
                if model
                    .get_block(block_id)
                    .native_next
                    .as_function_call()
                    .is_some()
                {
                    for d in &block_flow.defs_in {
                        if d.kind.is_positive_relative_memory() {
                            current_live_in
                                .entry(d.kind)
                                .or_insert_with(HashSet::new)
                                .insert(d.source);
                        }
                    }
                }
                current_live_in.retain(|kind, _| !defined_kinds.contains(kind));
                for (k, v) in &block_flow.use_before_def {
                    current_live_in
                        .entry(*k)
                        .or_insert_with(HashSet::new)
                        .insert(NativeOriginationPoint::Instruction(*v));
                }

                // Update block's IN set if changed
                if current_live_in != block_flow.live_in {
                    debug!(
                        "Block {:?}: LiveIn changed to {:?}",
                        block_id, current_live_in
                    );
                    block_flow.live_in = current_live_in;
                    changed = true;
                }

                // Low-level liveness
                let new_low_live_out =
                    Self::calculate_low_live_out(model, function, block_id, df_result);

                // Update low-level block's OUT set if changed
                let low_flow = df_result.low_block_results.get_mut(&block_id).unwrap();
                if new_low_live_out != low_flow.live_out {
                    debug!("Block {:?}: Low LiveOut changed", block_id);
                    low_flow.live_out = new_low_live_out;
                    changed = true; // Continue iteration
                }

                // Calculate low-level IN set
                let low_defined_kinds: HashSet<MemoryReference> =
                    low_flow.gen.keys().cloned().collect();
                let mut low_current_live_in = low_flow.live_out.clone();

                // Add potential_function_call_params for low-level
                if model.get_block(block_id).next.as_function_call().is_some() {
                    for d in &low_flow.defs_in {
                        if d.kind.is_outgoing_parameter() {
                            low_current_live_in
                                .entry(d.kind.clone())
                                .or_insert_with(HashSet::new)
                                .insert(d.source);
                        }
                    }
                }

                low_current_live_in.retain(|kind, _| !low_defined_kinds.contains(kind));
                for (k, v) in &low_flow.use_before_def {
                    low_current_live_in
                        .entry(k.clone())
                        .or_insert_with(HashSet::new)
                        .insert(OriginationPoint::Instruction(*v));
                }

                // Update low-level block's IN set if changed
                if low_current_live_in != low_flow.live_in {
                    debug!("Block {:?}: Low LiveIn changed", block_id);
                    low_flow.live_in = low_current_live_in;
                    changed = true;
                }
            }
        }
    }

    /// Calculates the Live-Out set for a single block based on its successors' Live-In sets.
    fn calculate_live_out(
        model: &ProgramModel,
        function: &Function,
        block_id: BlockId,
        df_result: &DataFlowResult, // Read-only access for successor IN sets
    ) -> HashMap<OperandKind, HashSet<NativeOriginationPoint>> {
        let block = model.get_block(block_id);
        let mut new_live_out = HashMap::new();

        for succ_id in block.native_next.successors() {
            for (k, v) in &df_result.block_results.get(&succ_id).unwrap().live_in {
                new_live_out
                    .entry(*k)
                    .or_insert_with(HashSet::new)
                    .extend(v);
            }
        }

        if Some(block_id) == function.return_block {
            // If this is a function return, we need to add all potential return arguments
            // to live out So we will have phi's automatically created for them at the right junctions.
            // We mark the live out as "FunctionOutput" to indicate that it is a return value.
            // This prevents from potential return values to appear as function inputs by propogating
            // to the entry point's live in.
            for block in &function.all_block_ids {
                let dfr = df_result.block_results.get(block).unwrap();
                for gen in dfr.gen.keys().filter(|k| k.is_negative_relative_memory()) {
                    new_live_out
                        .entry(*gen)
                        .or_insert_with(HashSet::new)
                        .insert(NativeOriginationPoint::FunctionOutput);
                }
            }
        }

        new_live_out
    }

    /// Calculates the low-level Live-Out set for a single block based on its successors' Live-In sets.
    fn calculate_low_live_out(
        model: &ProgramModel,
        function: &Function,
        block_id: BlockId,
        df_result: &DataFlowResult,
    ) -> HashMap<MemoryReference, HashSet<OriginationPoint>> {
        let block = model.get_block(block_id);
        let mut new_live_out = HashMap::new();

        for succ_id in block.next.successors() {
            let succ_block = df_result.low_block_results.get(&succ_id).unwrap();
            for (k, v) in &succ_block.live_in {
                new_live_out
                    .entry(k.clone())
                    .or_insert_with(HashSet::new)
                    .extend(v);
            }
        }

        if Some(block_id) == function.return_block {
            // If this is a function return, add potential return arguments to live out
            for &block_id in &function.all_block_ids {
                let low_flow = df_result.low_block_results.get(&block_id).unwrap();
                for gen in low_flow.gen.keys().filter(|k| k.is_stack_relative()) {
                    new_live_out
                        .entry(gen.clone())
                        .or_insert_with(HashSet::new)
                        .insert(OriginationPoint::FunctionOutput);
                }
            }
        }

        new_live_out
    }
}

impl ModelEventListener for DataFlowAnalyzer {
    fn on_function_cfg_built(
        &mut self,
        model: &mut ProgramModel,
        event: FunctionCfgBuilt,
        sender: &mut events::Sender,
    ) -> Result<(), crate::disasm::Error> {
        debug!("Starting Data Flow Analysis for {:?}", event.function_id);

        // Create a temporary result container for this function's analysis
        // Note: We'll modify the global result directly later, but this structure helps organize.
        let mut df_result_for_function = DataFlowResult::new();
        // Initialize block entries for this function
        let function = model.get_function(event.function_id);
        for block_id in &function.all_block_ids {
            df_result_for_function
                .block_results
                .insert(*block_id, BlockNativeDataFlow::new());
            df_result_for_function
                .low_block_results
                .insert(*block_id, BlockDataFlow::new());
            if let NextKind::FunctionCall(_) = model.get_block(*block_id).next {
                df_result_for_function
                    .block_results
                    .get_mut(block_id)
                    .unwrap()
                    .call_site_info = Some(NativeCallSiteInfo::new());
                df_result_for_function
                    .low_block_results
                    .get_mut(block_id)
                    .unwrap()
                    .call_site_info = Some(CallSiteInfo::new());
            }
        }

        // Perform analysis directly on the global result structure within the model
        DataFlowAnalyzer::analyze_function(model, event.function_id, &mut df_result_for_function);

        // If there is use of undefined [R+n] values, we check it comes from a function, and
        // that function is unique.
        for block_id in &function.all_block_ids {
            // Update low-level call site info
            let br = df_result_for_function
                .low_block_results
                .get_mut(&block_id)
                .unwrap();
            let return_usages_in_block = br
                .use_before_def
                .iter()
                .filter_map(|(k, v)| k.as_stack_relative().map(|i| (i, *v)))
                .filter(|&(n, _)| n > 0)
                .collect_vec();
            if !return_usages_in_block.is_empty() {
                assert_eq!(br.function_returns_in.len(), 1);
                let calling_block = br.function_returns_in.iter().next().unwrap().calling_block;
                let calling_block_flow = df_result_for_function
                    .low_block_results
                    .get_mut(&calling_block)
                    .unwrap();
                calling_block_flow
                    .call_site_info
                    .as_mut()
                    .unwrap()
                    .return_values_accessed
                    .extend(return_usages_in_block.clone());
            }
        }

        for (block_id, low_flow) in df_result_for_function.low_block_results {
            model.get_block_mut(block_id).data_flow = Some(low_flow);
        }

        if model.get_data_flow_result().is_none() {
            model.set_data_flow_result(DataFlowResult::new());
        }
        let global_results = model.get_data_flow_result_mut().unwrap(); // Now safe to unwrap
        global_results
            .block_results
            .extend(df_result_for_function.block_results);

        // Publish completion event for this function
        sender.publish(FunctionDataFlowAnalysisComplete {
            function_id: event.function_id,
        });
        debug!("Data Flow Analysis committed for {}", event.function_id);
        Ok(())
    }

    fn on_control_flow_analysis_phase_complete(
        &mut self,
        _model: &mut ProgramModel,
        _event: events::ControlFlowAnalysisPhaseComplete,
        sender: &mut events::Sender,
    ) -> Result<(), crate::disasm::Error> {
        sender.publish(DataFlowAnalysisPhaseComplete {});
        Ok(())
    }
}
