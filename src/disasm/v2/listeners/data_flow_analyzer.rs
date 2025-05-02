use std::collections::HashMap;
use std::collections::HashSet;

use itertools::Itertools;
use log::debug;

use crate::disasm::v2::control_flow::Block;
use crate::disasm::v2::control_flow::FunctionCall;
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
    model::{BlockId, FunctionId, ProgramModel},
};

pub struct DataFlowAnalyzer {}

impl DataFlowAnalyzer {
    pub fn new() -> Self {
        DataFlowAnalyzer {}
    }

    /// Performs the main data flow analysis passes for a given function.
    fn analyze_function(model: &ProgramModel, func_id: FunctionId, df_result: &mut DataFlowResult) {
        let func = model.get_function(func_id);
        let block_ids = &func.blocks;

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
                let target_sources = match &instr.kind {
                    Instruction::Assign {
                        target: MemoryReference::Deref(expr),
                        ..
                    } => expr
                        .collect_read_addresses()
                        .into_iter()
                        .map(|r| r.clone())
                        .collect(),
                    _ => vec![],
                };
                for r in instr
                    .kind
                    .collect_read_addresses()
                    .into_iter()
                    .chain(target_sources.iter())
                {
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
            for block_id in &func.blocks {
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
            for &other_block_id in &function.blocks {
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
            for block in &function.blocks {
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
            for &block_id in &function.blocks {
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
        for block_id in &function.blocks {
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
        for block_id in &function.blocks {
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
// TODO: Add tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::{
        parser,
        test_utils::init_logging,
        v2::{
            data_flow::NativeOriginationPoint,
            dispatching::EventPublisher,
            events::Event,
            instructions::PointerId,
            listeners::{
                control_flow_graph_builder::ControlFlowGraphBuilder, image_scanner::ImageScanner,
            },
            model::*,
            native::{NativeInstructionId, OperandKind},
        },
    };
    use itertools::Itertools;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    // Helper to setup model, run CFG build, and then data flow analysis
    fn setup_and_analyze(assembly_code: &str) -> ProgramModel {
        init_logging();
        let binary = parser::compile(assembly_code);
        let mut model = ProgramModel::new();
        let mut publisher = EventPublisher::<Event, ProgramModel>::new();

        // Register listeners needed *before* data flow
        publisher.add_listener(Box::new(ImageScanner::new()));
        publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
        publisher.add_listener(Box::new(DataFlowAnalyzer::new()));

        model.load_image(&binary, &mut publisher);
        publisher.process_events(&mut model).unwrap();
        model // Return model with CFG and DataFlow results
    }

    // Helper to create an OperandKind for assertions
    fn mem_kind(addr: i128) -> OperandKind {
        OperandKind::Memory(addr as usize)
    }
    fn rel_kind(offset: i128) -> OperandKind {
        OperandKind::RelativeMemory(offset)
    }
    fn imm_kind(val: i128) -> OperandKind {
        OperandKind::Immediate(val)
    }

    // Helper to create a Definition for assertions
    fn def(instr_id: usize, location: OperandKind, block_id: usize) -> NativeDefinition {
        NativeDefinition {
            source: NativeOriginationPoint::Instruction(NativeInstructionId::from(instr_id)),
            kind: location,
            block_id: BlockId::from(block_id),
        }
    }

    #[test]
    fn test_simple_sequence() {
        let model = setup_and_analyze(
            r#"
            ; func @ 0
            R += 2          ; 0
            [100] = 5       ; 2 ; Def A: [100]=5 (@0, i2)
            [101] = [100]   ; 6 ; Use A, Def B: [101]=[100] (@0, i6)
            output [101]    ; 10; Use B
            R -= 2          ; 12; Block 12 starts here
            goto [R]        ; 14
            "#,
        );

        let block0_id = BlockId::from(0);
        let block12_id = BlockId::from(12); // Return block

        let block0 = model.get_block(block0_id);
        let block12 = model.get_block(block12_id);

        let flow0 = block0
            .data_flow
            .as_ref()
            .expect("Block 0 data flow missing");
        let flow12 = block12
            .data_flow
            .as_ref()
            .expect("Block 12 data flow missing");

        // --- Block 0 ---
        // GEN/USE
        assert_eq!(flow0.gen.len(), 2, "GEN length should be 2");
        assert!(
            flow0.gen.contains_key(&MemoryReference::Global(100)),
            "GEN should contain [100]"
        );
        assert!(
            flow0.gen.contains_key(&MemoryReference::Global(101)),
            "GEN should contain [101]"
        );
        assert!(flow0.use_before_def.is_empty(), "USE @ B0");

        // Reaching Defs
        assert!(flow0.defs_in.is_empty(), "DefsIn @ B0");

        // Check that defs_out contains definitions for [100] and [101]
        let defs_out_kinds: HashSet<_> =
            flow0.defs_out.iter().map(|def| def.kind.clone()).collect();
        assert!(
            defs_out_kinds.contains(&MemoryReference::Global(100)),
            "DefsOut should contain [100]"
        );
        assert!(
            defs_out_kinds.contains(&MemoryReference::Global(101)),
            "DefsOut should contain [101]"
        );

        // --- Block 12 (Return) ---
        // GEN/USE
        assert!(flow12.gen.is_empty(), "GEN @ B12");

        // Reaching Defs
        let defs_in_kinds: HashSet<_> = flow12.defs_in.iter().map(|def| def.kind.clone()).collect();
        assert!(
            defs_in_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn should contain [100]"
        );
        assert!(
            defs_in_kinds.contains(&MemoryReference::Global(101)),
            "DefsIn should contain [101]"
        );

        // DefsOut should be the same as DefsIn for this block
        assert_eq!(flow12.defs_out.len(), flow12.defs_in.len(), "DefsOut @ B12");

        // Liveness (Placeholder check)
        assert!(flow12.live_out.is_empty(), "LiveOut @ B12"); // Nothing live after return
    }

    #[test]
    fn test_if_else() {
        let model = setup_and_analyze(
            r#"
             ; func @ 0
             R += 3                ; 0
             [100] = 1             ; 2  ; Def A (@0, i2)
             if [100] goto @true   ; 6  ; Use A
             ; false branch @ 9
             [101] = 10            ; 9  ; Def B (@9, i9)
             goto @merge           ; 13
             ; true branch @ 16
             true:
             [101] = 20            ; 16 ; Def C (@16, i16)
             ; merge block @ 20
             merge:
             output [101]          ; 20 ; Use B or C
             R -= 3                ; 22 ; Return block starts
             goto [R]              ; 24
             "#,
        );

        let block0_id = BlockId::from(0);
        let block9_id = BlockId::from(9); // False branch
        let block16_id = BlockId::from(16); // True branch
        let block20_id = BlockId::from(20); // Merge block
        let block22_id = BlockId::from(22); // Return block

        let block0 = model.get_block(block0_id);
        let block9 = model.get_block(block9_id);
        let block16 = model.get_block(block16_id);
        let block20 = model.get_block(block20_id);
        let block22 = model.get_block(block22_id);

        let flow0 = block0.data_flow.as_ref().unwrap();
        let flow9 = block9.data_flow.as_ref().unwrap();
        let flow16 = block16.data_flow.as_ref().unwrap();
        let flow20 = block20.data_flow.as_ref().unwrap();
        let flow22 = block22.data_flow.as_ref().unwrap();

        // --- Check Defs reaching merge block (Block 20) ---
        // Check that defs_in contains definitions for [100] and [101]
        let defs_in20_kinds: HashSet<_> =
            flow20.defs_in.iter().map(|def| def.kind.clone()).collect();
        assert!(
            defs_in20_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn should contain [100]"
        );
        assert!(
            defs_in20_kinds.contains(&MemoryReference::Global(101)),
            "DefsIn should contain [101]"
        );

        // Check that there are definitions for [101] from both branches
        let defs_in20_block_ids: HashSet<_> = flow20
            .defs_in
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(101))
            .map(|def| def.block_id)
            .collect();
        assert!(
            defs_in20_block_ids.contains(&block9_id),
            "DefsIn should contain [101] from block 9"
        );
        assert!(
            defs_in20_block_ids.contains(&block16_id),
            "DefsIn should contain [101] from block 16"
        );

        // --- Check USE in merge block (Block 20) ---
        assert_eq!(
            flow20
                .use_before_def
                .keys()
                .cloned()
                .collect::<HashSet<_>>(),
            [MemoryReference::Global(101)].iter().cloned().collect(),
            "USE @ B20"
        );
        assert!(flow20.gen.is_empty(), "GEN @ B20"); // Output doesn't generate defs

        // --- Check GEN in branches ---
        assert!(
            flow9.gen.contains_key(&MemoryReference::Global(101)),
            "GEN @ B9 should contain [101]"
        );
        assert!(
            flow16.gen.contains_key(&MemoryReference::Global(101)),
            "GEN @ B16 should contain [101]"
        );

        // --- Check Defs reaching branches ---
        // Only Def A ([100]) reaches both branches
        let defs_in9_kinds: HashSet<_> = flow9.defs_in.iter().map(|def| def.kind.clone()).collect();
        let defs_in16_kinds: HashSet<_> =
            flow16.defs_in.iter().map(|def| def.kind.clone()).collect();

        assert!(
            defs_in9_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn @ B9 should contain [100]"
        );
        assert!(
            !defs_in9_kinds.contains(&MemoryReference::Global(101)),
            "DefsIn @ B9 should not contain [101]"
        );

        assert!(
            defs_in16_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn @ B16 should contain [100]"
        );
        assert!(
            !defs_in16_kinds.contains(&MemoryReference::Global(101)),
            "DefsIn @ B16 should not contain [101]"
        );

        // --- Check Defs out of merge block (Block 20) ---
        // Defs from branches should reach, Def A also. Output generates nothing new.
        let defs_out20_kinds: HashSet<_> =
            flow20.defs_out.iter().map(|def| def.kind.clone()).collect();
        assert!(
            defs_out20_kinds.contains(&MemoryReference::Global(100)),
            "DefsOut @ B20 should contain [100]"
        );
        assert!(
            defs_out20_kinds.contains(&MemoryReference::Global(101)),
            "DefsOut @ B20 should contain [101]"
        );

        // --- Check Defs into return block (Block 22) ---
        let defs_in22_kinds: HashSet<_> =
            flow22.defs_in.iter().map(|def| def.kind.clone()).collect();
        assert!(
            defs_in22_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn @ B22 should contain [100]"
        );
        assert!(
            defs_in22_kinds.contains(&MemoryReference::Global(101)),
            "DefsIn @ B22 should contain [101]"
        );
    }

    #[test]
    fn test_loop() {
        let model = setup_and_analyze(
            r#"
             ; func @ 0
             R += 2          ; 0
             [100] = 5       ; 2  ; Def A (@0, i2)
             loop_start:         ; block @ 6
             output [100]    ; 6  ; Use A or C
             [100] = [100] + -1 ; 8  ; Use A or C, Def C (@6, i8)
             if [100] goto @loop_start ; 12 ; Use C
             ; exit block @ 15
             R -= 2          ; 15 ; Return block starts
             goto [R]        ; 17
             "#,
        );

        let block0_id = BlockId::from(0); // Init
        let block6_id = BlockId::from(6); // Loop body + condition
        let block15_id = BlockId::from(15); // Exit/Return block

        let block0 = model.get_block(block0_id);
        let block6 = model.get_block(block6_id);
        let block15 = model.get_block(block15_id);

        let flow0 = block0.data_flow.as_ref().unwrap();
        let flow6 = block6.data_flow.as_ref().unwrap();
        let flow15 = block15.data_flow.as_ref().unwrap();

        // --- Check Defs reaching loop header/body (Block 6) ---
        // Should receive Def A from block 0 AND Def C from loop back edge
        let defs_in6_sources: HashSet<_> = flow6
            .defs_in
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(100))
            .map(|def| {
                (
                    def.block_id,
                    matches!(def.source, OriginationPoint::Instruction(_)),
                )
            })
            .collect();

        // Should have a definition from block 0 and from block 6 itself (loop back edge)
        assert!(
            defs_in6_sources.contains(&(block0_id, true)),
            "DefsIn @ B6 should contain [100] from block 0"
        );
        assert!(
            defs_in6_sources.contains(&(block6_id, true)),
            "DefsIn @ B6 should contain [100] from block 6 (loop back edge)"
        );

        // --- Check USE in loop block (Block 6) ---
        // output reads [100], addition reads [100], if reads [100]
        assert_eq!(
            flow6.use_before_def.keys().cloned().collect::<HashSet<_>>(),
            [MemoryReference::Global(100)].iter().cloned().collect(),
            "USE @ B6"
        );

        // --- Check GEN in loop block (Block 6) ---
        // The last write to [100] is in this block
        assert!(
            flow6.gen.contains_key(&MemoryReference::Global(100)),
            "GEN @ B6 should contain [100]"
        );

        // --- Check Defs out of loop block (Block 6) ---
        // This is DefsIn(6) - KilledDefs(6) U GenDefs(6)
        // Should only contain the definition from this block
        let defs_out6_blocks: HashSet<_> = flow6
            .defs_out
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(100))
            .map(|def| def.block_id)
            .collect();

        assert_eq!(
            defs_out6_blocks,
            [block6_id].iter().cloned().collect(),
            "DefsOut @ B6 should only contain [100] from block 6"
        );

        // --- Check Defs into exit block (Block 15) ---
        // Comes from the 'if' condition failing in block 6. Should receive DefsOut(6).
        let defs_in15_blocks: HashSet<_> = flow15
            .defs_in
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(100))
            .map(|def| def.block_id)
            .collect();

        assert_eq!(
            defs_in15_blocks,
            [block6_id].iter().cloned().collect(),
            "DefsIn @ B15 should only contain [100] from block 6"
        );
    }

    #[test]
    fn test_function_call_return_values() {
        let model = setup_and_analyze(
            r#"
                    ; main @ 0
                    R += 3          ; 0
                    [100] = 50      ; 2  ; Def A: [100]=50 (@0, i2)
                    [R+1] = [100]   ; 6  ; Def B: [R+1]=[100] (@0, i6)
                    [R+2] = 99      ; 10 ; Def C: [R+2]=99 (@0, i10)
                    [R] = @ret      ; 14 ; Setup return addr
                    goto @callee    ; 18 ; Call callee (func address 30, immediate)
                    ret:                ; block @ 21
                    output [R+1]    ; 21 ; Use RetDef D
                    output [R+2]    ; 23 ; Use RetDef E
                    R -= 3          ; 25 ; Return block starts
                    goto [R]        ; 27

                    ; callee @ 30
                    callee:
                    R += 5          ; 30 ; Stack size 2
                    [R-3] = [R-3] + 1 ; 32 ; Modify arg1 ([R+1]->[R-3]), store in ret slot 1 ([R-3])
                    [R-4] = [R-4] * 2 ; 36 ; Modify arg2 ([R+2]->[R-4]), store in ret slot 2 ([R-4])
                                           ; Note: callee writes to R-3 and R-4 which map to caller's R+1 and R+2
                    R -= 5          ; 40 ; Return block starts
                    goto [R]        ; 42
                    "#,
        );

        let block0_id = BlockId::from(0); // main entry + call setup
        let block21_id = BlockId::from(21); // main return block
        let block25_id = BlockId::from(25); // main actual return sequence

        let block0 = model.get_block(block0_id);
        let block21 = model.get_block(block21_id);
        let block25 = model.get_block(block25_id);

        let flow0 = block0.data_flow.as_ref().unwrap();
        let flow21 = block21.data_flow.as_ref().unwrap();
        let flow25 = block25.data_flow.as_ref().unwrap();

        // --- Check USE in return block (Block 21) ---
        // This determines potential_returns for the call from block 0
        assert_eq!(
            flow21.use_before_def.keys().sorted().collect::<Vec<_>>(),
            [
                MemoryReference::StackRelative(1),
                MemoryReference::StackRelative(2)
            ]
            .iter()
            .sorted()
            .collect::<Vec<_>>(),
            "USE @ B21"
        );

        // --- Check Defs reaching return block (Block 21) ---
        let defs_in21_kinds: HashSet<_> =
            flow21.defs_in.iter().map(|def| def.kind.clone()).collect();

        // Should contain [100] but not [R+1] or [R+2] which are killed by the call
        assert!(
            defs_in21_kinds.contains(&MemoryReference::Global(100)),
            "DefsIn @ B21 should contain [100]"
        );
        assert!(
            !defs_in21_kinds.contains(&MemoryReference::StackRelative(1)),
            "DefsIn @ B21 should not contain [R+1] from before call"
        );
        assert!(
            !defs_in21_kinds.contains(&MemoryReference::StackRelative(2)),
            "DefsIn @ B21 should not contain [R+2] from before call"
        );

        // Check for function return info
        assert!(
            !flow21.function_returns_in.is_empty(),
            "Block 21 should have function returns"
        );

        // --- Check Defs out of return block (Block 21) ---
        // Should be same as DefsIn, since output doesn't kill/gen memory defs
        assert_eq!(flow21.defs_out.len(), flow21.defs_in.len(), "DefsOut @ B21");

        // --- Check Defs into actual return sequence (Block 25) ---
        assert_eq!(flow25.defs_in.len(), flow21.defs_out.len(), "DefsIn @ B25");

        // Check that call site info is properly populated
        assert!(
            flow0.call_site_info.is_some(),
            "Call site info should be present"
        );
        let call_site_info = flow0.call_site_info.as_ref().unwrap();

        // Should have return values accessed for [R+1] and [R+2]
        assert!(
            call_site_info.return_values_accessed.contains_key(&1),
            "Call site should record [R+1] as accessed"
        );
        assert!(
            call_site_info.return_values_accessed.contains_key(&2),
            "Call site should record [R+2] as accessed"
        );
    }

    #[test]
    fn test_unused_write_killed() {
        let model = setup_and_analyze(
            r#"
                     ; func @ 0
                     R += 2          ; 0
                     [100] = 5       ; 2 ; Def A
                     [100] = 10      ; 6 ; Def B (kills A)
                     output [100]    ; 10; Use B
                     R -= 2          ; 12
                     goto [R]        ; 14
                     "#,
        );
        let block0_id = BlockId::from(0);
        let block12_id = BlockId::from(12); // Return block

        let block0 = model.get_block(block0_id);
        let block12 = model.get_block(block12_id);

        let flow0 = block0.data_flow.as_ref().unwrap();
        let flow12 = block12.data_flow.as_ref().unwrap();

        // GEN should only contain the *last* write
        assert_eq!(flow0.gen.len(), 1, "GEN should only contain one entry");
        assert!(
            flow0.gen.contains_key(&MemoryReference::Global(100)),
            "GEN should contain [100]"
        );

        // Defs Out should only contain one definition for [100]
        let defs_out0_for_100: Vec<_> = flow0
            .defs_out
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(100))
            .collect();

        assert_eq!(
            defs_out0_for_100.len(),
            1,
            "DefsOut @ B0 should contain exactly one definition for [100]"
        );
        assert_eq!(
            defs_out0_for_100[0].block_id, block0_id,
            "DefsOut @ B0 should contain definition from block 0"
        );

        // Defs In for return block should only contain one definition for [100]
        let defs_in12_for_100: Vec<_> = flow12
            .defs_in
            .iter()
            .filter(|def| def.kind == MemoryReference::Global(100))
            .collect();

        assert_eq!(
            defs_in12_for_100.len(),
            1,
            "DefsIn @ B12 should contain exactly one definition for [100]"
        );
        assert_eq!(
            defs_in12_for_100[0].block_id, block0_id,
            "DefsIn @ B12 should contain definition from block 0"
        );
    }

    #[test]
    fn test_multiple_function_calls() {
        let model = setup_and_analyze(
            r#"
            R += 3              ; 0
            [R] = 9             ; 2
            goto @func0         ; 6
            if ![1129] goto @cont  ; 9
            [R+1] = 316         ; 12
            [R] = 23            ; 16
            goto @func2         ; 20
            goto 92             ; 23
            cont:
            [R-1] = 0           ; 26
            p36 = [R-1] + 0     ; 30
            [R+1] = *p36        ; 34
            [R+2] = 0           ; 38
            [R+3] = 0           ; 42
            [R] = 53            ; 46
            goto @func3         ; 50
            if ![R+1] goto 70   ; 53
            p66 = [R-1] + 40    ; 56
            [R] = 67            ; 60
            goto *p66           ; 64
            goto 92             ; 67
            [R-1] = [R-1] + 1   ; 70
            [R-2] = [R-1] < 7   ; 74
            if [R-2] goto 30    ; 78
            [R+1] = 177         ; 81
            [R] = 92            ; 85
            goto @func2         ; 89
            R += -3             ; 92
            goto [R]            ; 94
            func0:
            R += 2              ; func0 @ 97
            output [R-1]
            R -= 2
            goto [R]
            func1:
            R += 2              ; func1 @ 106
            output [R-1]
            R -= 2
            goto [R]
            func2:
            R += 2              ; func2 @ 115
            output [R-1]
            R -= 2
            goto [R]
            func3:
            R += 2              ; func3 @ 124
            output [R-1]
            R -= 2
            goto [R]
        "#,
        );

        // Test blocks after function calls contain the expected return definitions
        // The function call at offset 50 to func3 (addr 124) generates return definitions
        // that propagate to specific blocks

        // Blocks that SHOULD have function returns from func3 (addr 124)
        let func3_returns_blocks = [
            BlockId::from(30),
            BlockId::from(53), // Direct return target
            BlockId::from(56), // Reachable through control flow
            BlockId::from(70),
            BlockId::from(81),
        ];

        // Check which blocks have function returns from func3
        let blocks_with_func3_returns: Vec<BlockId> = func3_returns_blocks
            .iter()
            .filter(|&&block_id| {
                let block = model.get_block(block_id);
                let flow = block.data_flow.as_ref().unwrap();

                flow.function_returns_in.iter().any(|fc| {
                    if let Expression::Constant(addr) = &fc.function_addr {
                        *addr == 124
                    } else {
                        false
                    }
                })
            })
            .cloned()
            .sorted()
            .collect();

        assert_eq!(
            blocks_with_func3_returns,
            func3_returns_blocks.to_vec(),
            "Blocks that should have function returns from func3 do have them"
        );

        // Test there are no return values from calls that haven't happened yet
        let cont_block = BlockId::from(26);
        let cont_block_data = model.get_block(cont_block);
        let cont_flow = cont_block_data.data_flow.as_ref().unwrap();

        // Block 26 (cont:) should not have any function return definitions from func2
        let cont_block_func2_returns = cont_flow.function_returns_in.iter().any(|fc| {
            if let Expression::Constant(addr) = &fc.function_addr {
                *addr == 115 // func2 address
            } else {
                false
            }
        });

        assert!(
            !cont_block_func2_returns,
            "Block 26 should not have function return definitions from func2"
        );

        // Block 53 should have definition for [R+1] from func3 specifically
        let block53 = BlockId::from(53);
        let block53_data = model.get_block(block53);
        let block53_flow = block53_data.data_flow.as_ref().unwrap();

        // Check for function return from func3 (address 124)
        let func3_returns = block53_flow
            .function_returns_in
            .iter()
            .filter(|fc| {
                if let Expression::Constant(addr) = &fc.function_addr {
                    *addr == 124
                } else {
                    false
                }
            })
            .collect::<Vec<_>>();

        // Verify we have at least one function return from func3
        assert!(
            !func3_returns.is_empty(),
            "Block 53 should have at least one return definition from func3"
        );

        // Verify block53 has [R+1] in use_before_def, indicating it's reading a return value
        assert!(
            block53_flow
                .use_before_def
                .contains_key(&MemoryReference::StackRelative(1)),
            "Block 53 should have [R+1] in use_before_def as a return value from func3"
        );

        // Verify the calling block has 1 ([R+1]) in its call_site_info.return_values_accessed
        let calling_block = func3_returns[0].calling_block;
        let calling_block_data = model.get_block(calling_block);
        let calling_block_flow = calling_block_data.data_flow.as_ref().unwrap();

        assert!(
            calling_block_flow.call_site_info.as_ref().unwrap().return_values_accessed.contains_key(&1),
            "The calling block for func3 should have 1 ([R+1]) in its call_site_info.return_values_accessed"
        );
    }
    #[test]
    fn test_deref_result_in_live_in() {
        // This test verifies that pointer dereferencing operations are correctly tracked
        // in the liveness analysis. When pointers are used or dereferenced later in the
        // program, they should appear in the live_in set of preceding blocks.
        let model = setup_and_analyze(
            r#"
            R += 3              ; 0
            ptr1 = 2            ; 2  ; Define pointer 1
            ptr2 = 4            ; 6  ; Define pointer 2
            goto @below         ; 10
            below:
            [R+1] = [R-1]       ; 13 ; Stack memory operation
            *ptr1 = 7           ; 17 ; Dereference and write to ptr1
            [R+2] = *ptr2       ; 21 ; Read from dereferenced ptr2
            R -= 3              ; 25
            goto [R]
            "#,
        );

        // Get the data flow information for the "below" block at address 13
        let df = model
            .get_block(BlockId::from(13))
            .data_flow
            .as_ref()
            .unwrap();

        // Check that pointers are correctly marked as live at block entry

        // This verifies that ptr1 is live at the entry point of the block
        // PointerId 20 corresponds to ptr1 (instruction at position 2)
        assert!(
            df.live_in
                .contains_key(&MemoryReference::Pointer(PointerId::from(20))),
            "ptr1 should be in live_in as it's used for dereferencing at instruction 17"
        );

        // This verifies that dereferenced ptr2 is in the live_in set
        // The expression represents *ptr2, where ptr2 is defined at instruction position 6
        // The data flow analyzer correctly identified that we need to read through ptr2
        assert!(
            df.live_in
                .contains_key(&MemoryReference::Deref(Box::new(Expression::Addressable(
                    MemoryReference::Pointer(PointerId::from(22))
                )))),
            "Dereferenced ptr2 should be in live_in as it's read at instruction 21"
        );
    }
}
