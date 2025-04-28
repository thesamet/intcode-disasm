use std::collections::HashSet;

use itertools::Itertools;
use log::debug;

use crate::disasm::v2::control_flow::FunctionCall;
use crate::disasm::v2::data_flow::BlockDataFlow;
use crate::disasm::v2::data_flow::CallSiteInfo;
use crate::disasm::v2::events::DataFlowAnalysisPhaseComplete;
use crate::disasm::v2::events::FunctionDataFlowAnalysisComplete;
use crate::disasm::v2::instructions::{Operand, OperandKind};
use crate::disasm::v2::{
    control_flow::NextKind,
    data_flow::{DataFlowResult, Definition},
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

        // Pass 1: Initialize gen, use_before_def and function_returns_in  For each block
        Self::initialize_gen_use_func_in(model, block_ids, df_result);

        // Pass 2: compute function_returns_out and function_returns_in for all blocks (forward analysis)
        Self::run_function_returns_analysis(model, block_ids, df_result);

        // Pass 3: Reaching Definitions (Forward Analysis)
        Self::run_reaching_definitions_analysis(model, block_ids, df_result);

        // Pass 4: Liveness Analysis (Backward Analysis)
        Self::run_liveness_analysis(model, func_id, block_ids, df_result);

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

            let mut defined_in_block = HashSet::new();
            block_flow.writes_above_r = false;
            for instr in &block.instructions {
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
                        .insert(write_operand.kind, (instr.id, write_operand));
                    defined_in_block.insert(write_operand.kind);
                    if let Some(n) = write_operand.kind.get_relative_memory() {
                        if n > 0 {
                            block_flow.writes_above_r = true;
                        }
                    }
                }
            }
            block_flow.function_returns_in = block
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
                let new_func_in = Self::calculate_function_returns_in(model, block_id, df_result);
                // Update block's IN set if changed
                let block_flow = df_result.block_results.get_mut(&block_id).unwrap(); // Must exist
                if new_func_in != block_flow.function_returns_in {
                    debug!(
                        "Block {:?}: FunctionReturnsIn changed to {:?}",
                        block_id, new_func_in
                    );
                    block_flow.function_returns_in = new_func_in.clone();
                    changed = true;
                }
                if !block_flow.writes_above_r && block_flow.function_returns_out != new_func_in {
                    block_flow.function_returns_out = new_func_in;
                    changed = true;
                }
            }
        }
    }

    fn calculate_function_returns_in(
        model: &ProgramModel,
        block_id: BlockId,
        df_result: &DataFlowResult, // Read-only access for predecessor OUT sets
    ) -> HashSet<FunctionCall<Operand>> {
        let block_flow = df_result.block_results.get(&block_id).unwrap();
        let mut new_func_in = block_flow.function_returns_in.clone();
        // If this block is a return from a function call, we do not change new_func_in, as
        // defintions from further away will be overridden by the immediate one.
        if !model
            .get_block(block_id)
            .predecessors
            .iter()
            .any(|p| p.get_function_call_returns().is_some())
        {
            for pred in model.get_block(block_id).predecessors.iter() {
                // Update block's IN set if changed
                let pred_block_id = pred.source_block_id();
                let pred_function_returns_out = df_result
                    .block_results
                    .get(&pred_block_id)
                    .unwrap()
                    .function_returns_out
                    .clone();
                new_func_in.extend(pred_function_returns_out);
            }
        }
        new_func_in
    }

    /// Pass 3: Computes Reaching Definitions iteratively.
    fn run_reaching_definitions_analysis(
        model: &ProgramModel,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            for &block_id in block_ids {
                let new_defs_in = Self::calculate_defs_in(model, block_id, block_ids, df_result);

                // Update block's IN set if changed
                // Use get_mut for direct modification
                let block_flow = df_result.block_results.get_mut(&block_id).unwrap(); // Must exist
                if new_defs_in != block_flow.defs_in {
                    debug!("Block {:?}: DefsIn changed", block_id);
                    block_flow.defs_in = new_defs_in;
                    changed = true; // Continue iteration if IN changed
                }

                // Calculate OUT set: OUT = (IN - KILL) U GEN
                let killed_kinds: HashSet<&OperandKind> = block_flow.gen.keys().collect();
                let mut current_defs_out = block_flow.defs_in.clone();
                current_defs_out.retain(|def| !killed_kinds.contains(&def.location));

                // Add GEN set
                for (location, (instruction_id, _)) in &block_flow.gen {
                    current_defs_out.insert(Definition {
                        instruction_id: *instruction_id,
                        location: *location,
                        block_id,
                    });
                }
                // In we call a function at the end of the block, this block doesn't let [R+n]
                // defintions flow forward.
                if matches!(model.get_block(block_id).next, NextKind::FunctionCall(_)) {
                    current_defs_out.retain(|d| !d.location.is_positive_relative_memory());
                }

                // Update block's OUT set if changed
                if current_defs_out != block_flow.defs_out {
                    debug!("Block {:?}: DefsOut changed", block_id);
                    block_flow.defs_out = current_defs_out;
                    changed = true;
                }
            }
        }
    }

    /// Calculates the Defs-In set for a single block based on its predecessors.
    fn calculate_defs_in(
        model: &ProgramModel,
        block_id: BlockId,
        function_block_ids: &[BlockId], // IDs of blocks within the current function
        df_result: &DataFlowResult,     // Read-only access for predecessor OUT sets
    ) -> HashSet<Definition> {
        let block = model.get_block(block_id);
        let mut new_defs_in = HashSet::new();

        for pred_kind in &block.predecessors {
            let pred_block_id = pred_kind.source_block_id();

            // Ensure predecessor is within the same function
            assert!(
                function_block_ids.contains(&pred_block_id),
                "Predecessor {:?} of block {:?} is not in the same function!",
                pred_block_id,
                block_id
            );

            let pred_flow = df_result
                .block_results
                .get(&pred_block_id)
                .expect("Predecessor block data flow info should exist");

            new_defs_in.extend(&pred_flow.defs_out);
        }

        new_defs_in
    }

    /// Pass 4: Computes Liveness iteratively.
    fn run_liveness_analysis(
        model: &ProgramModel,
        function_id: FunctionId,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            // Iterate backwards - often converges faster for backward analyses like liveness
            for &block_id in block_ids.iter().rev() {
                let new_live_out =
                    Self::calculate_live_out(model, function_id, block_id, df_result);

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

                // Calculate IN set: IN = USE U (OUT - DEF)
                let defined_kinds: HashSet<OperandKind> = block_flow.gen.keys().cloned().collect();
                let mut current_live_in = block_flow.live_out.clone();
                current_live_in.retain(|kind| !defined_kinds.contains(kind));
                current_live_in.extend(block_flow.use_before_def.keys().cloned());

                // Update block's IN set if changed
                if current_live_in != block_flow.live_in {
                    debug!(
                        "Block {:?}: LiveIn changed to {:?}",
                        block_id, current_live_in
                    );
                    block_flow.live_in = current_live_in;
                    changed = true;
                }
            }
        }
    }

    /// Calculates the Live-Out set for a single block based on its successors' Live-In sets.
    fn calculate_live_out(
        model: &ProgramModel,
        function_id: FunctionId,
        block_id: BlockId,
        df_result: &DataFlowResult, // Read-only access for successor IN sets
    ) -> HashSet<OperandKind> {
        let block = model.get_block(block_id);
        let mut new_live_out = HashSet::new();

        let add_live_in_from_successor = |succ_id: BlockId, live_out: &mut HashSet<OperandKind>| {
            live_out.extend(&df_result.block_results.get(&succ_id).unwrap().live_in)
        };

        for succ_id in block.next.successors() {
            add_live_in_from_successor(succ_id, &mut new_live_out);
        }
        let function = model.get_function(function_id);

        if Some(block_id) == model.get_function(function_id).return_block {
            for block in &function.blocks {
                let dfr = df_result.block_results.get(block).unwrap();
                new_live_out.extend(dfr.gen.keys().filter(|k| k.is_negative_relative_memory()));
            }
        }
        if matches!(block.next, NextKind::FunctionCall(_)) {
            // If this is a function call, we need to add the return arguments to live out
            for block in &function.blocks {
                let dfr = df_result.block_results.get(block).unwrap();
                new_live_out.extend(dfr.gen.keys().filter(|k| k.is_positive_relative_memory()));
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
                .insert(*block_id, BlockDataFlow::new());
            if let NextKind::FunctionCall(_) = model.get_block(*block_id).next {
                df_result_for_function
                    .block_results
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
            let br = df_result_for_function.block_results.get(block_id).unwrap();
            let return_usage_in_block = br
                .use_before_def
                .iter()
                .filter_map(|(k, v)| k.get_relative_memory().map(|n| (n, *v)))
                .filter(|&(n, _)| n > 0)
                .collect_vec();
            if !return_usage_in_block.is_empty() {
                assert_eq!(br.function_returns_in.len(), 1);
                let calling_block = br.function_returns_in.iter().next().unwrap().calling_block;
                let calling_block = df_result_for_function
                    .block_results
                    .get_mut(&calling_block)
                    .unwrap();
                calling_block
                    .call_site_info
                    .as_mut()
                    .unwrap()
                    .return_values_accessed
                    .extend(return_usage_in_block);
            }
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
        v2::{
            dispatching::EventPublisher,
            events::Event,
            // Need to import OperandKind for assertions potentially
            instructions::{InstructionId, OperandKind},
            listeners::{
                control_flow_graph_builder::ControlFlowGraphBuilder, image_scanner::ImageScanner,
            },
            model::*, // Bring model types into scope
        },
    };
    use itertools::Itertools;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    // Helper to setup model, run CFG build, and then data flow analysis
    fn setup_and_analyze(assembly_code: &str) -> ProgramModel {
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
    fn def(instr_id: usize, location: OperandKind, block_id: usize) -> Definition {
        Definition {
            instruction_id: InstructionId::from(instr_id),
            location,
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

        let df_results = model
            .get_data_flow_result()
            .expect("Data flow results missing");
        let flow0 = df_results
            .block_results
            .get(&block0_id)
            .expect("Block 0 flow missing");
        let flow12 = df_results
            .block_results
            .get(&block12_id)
            .expect("Block 12 flow missing");

        // --- Block 0 ---
        // GEN/USE
        assert_eq!(flow0.gen.len(), 2, "GEN length should be 2");
        assert_eq!(
            flow0.gen[&mem_kind(100)].0,
            InstructionId::from(2),
            "GEN[100] @ B0"
        );
        assert_eq!(
            flow0.gen[&mem_kind(101)].0,
            InstructionId::from(6),
            "GEN[101] @ B0"
        );
        assert!(flow0.use_before_def.is_empty(), "USE @ B0");

        // Reaching Defs
        assert!(flow0.defs_in.is_empty(), "DefsIn @ B0");
        let expected_defs_out0: HashSet<_> = [
            def(2, mem_kind(100), 0), // Def A
            def(6, mem_kind(101), 0), // Def B
        ]
        .iter()
        .cloned()
        .collect();
        assert_eq!(flow0.defs_out, expected_defs_out0, "DefsOut @ B0");

        // Liveness (Placeholder check)
        // Needs full liveness impl. We expect [101] to be live out because it's used in output.
        // assert!(flow0.live_out.contains(&mem_kind(101)), "LiveOut @ B0");

        // --- Block 12 (Return) ---
        // GEN/USE
        assert!(flow12.gen.is_empty(), "GEN @ B12");
        assert_eq!(
            flow12.use_before_def.keys().cloned().collect_vec(),
            [rel_kind(0)].iter().cloned().collect_vec(),
            "USE @ B12"
        );

        // Reaching Defs
        assert_eq!(flow12.defs_in, expected_defs_out0, "DefsIn @ B12");
        assert_eq!(flow12.defs_out, flow12.defs_in, "DefsOut @ B12");

        // Liveness (Placeholder check)
        assert!(flow12.live_out.is_empty(), "LiveOut @ B12"); // Nothing live after return
        assert_eq!(
            flow12.live_in,
            [rel_kind(0)].iter().cloned().collect(),
            "LiveIn @ B12"
        );
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

        let df_results = model.get_data_flow_result().unwrap();
        let _flow0 = df_results.block_results.get(&block0_id).unwrap();
        let flow9 = df_results.block_results.get(&block9_id).unwrap();
        let flow16 = df_results.block_results.get(&block16_id).unwrap();
        let flow20 = df_results.block_results.get(&block20_id).unwrap();
        let flow22 = df_results.block_results.get(&block22_id).unwrap();

        // --- Check Defs reaching merge block (Block 20) ---
        let expected_defs_in20: HashSet<_> = [
            def(2, mem_kind(100), 0),   // Def A from block 0
            def(9, mem_kind(101), 9),   // Def B from false path block 9
            def(16, mem_kind(101), 16), // Def C from true path block 16
        ]
        .iter()
        .cloned()
        .collect();
        assert_eq!(flow20.defs_in, expected_defs_in20, "DefsIn @ B20");

        // --- Check USE in merge block (Block 20) ---
        assert_eq!(
            flow20.use_before_def.keys().cloned().collect_vec(),
            [mem_kind(101)].iter().cloned().collect_vec(),
            "USE @ B20"
        );
        assert!(flow20.gen.is_empty(), "GEN @ B20"); // Output doesn't generate defs

        // --- Check GEN in branches ---
        assert_eq!(
            flow9.gen.iter().map(|(k, (i, _))| (*k, *i)).collect_vec(),
            [(mem_kind(101), InstructionId::from(9))]
                .iter()
                .cloned()
                .collect_vec(),
            "GEN @ B9"
        );
        assert_eq!(
            flow16.gen.iter().map(|(k, (i, _))| (*k, *i)).collect_vec(),
            [(mem_kind(101), InstructionId::from(16))]
                .iter()
                .cloned()
                .collect_vec(),
            "GEN @ B16"
        );

        // --- Check Defs reaching branches ---
        let expected_defs_in_branches: HashSet<_> =
            [def(2, mem_kind(100), 0)].iter().cloned().collect(); // Only Def A reaches
        assert_eq!(flow9.defs_in, expected_defs_in_branches, "DefsIn @ B9");
        assert_eq!(flow16.defs_in, expected_defs_in_branches, "DefsIn @ B16");

        // --- Check Defs out of merge block (Block 20) ---
        // Defs from branches should reach, Def A also. Output generates nothing new.
        assert_eq!(flow20.defs_out, expected_defs_in20, "DefsOut @ B20");

        // --- Check Defs into return block (Block 22) ---
        assert_eq!(flow22.defs_in, expected_defs_in20, "DefsIn @ B22");
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

        let df_results = model.get_data_flow_result().unwrap();
        let _flow0 = df_results.block_results.get(&block0_id).unwrap();
        let flow6 = df_results.block_results.get(&block6_id).unwrap();
        let flow15 = df_results.block_results.get(&block15_id).unwrap();

        // --- Check Defs reaching loop header/body (Block 6) ---
        // Should receive Def A from block 0 AND Def C from loop back edge
        let expected_defs_in6: HashSet<_> = [
            def(2, mem_kind(100), 0), // Def A from block 0
            def(8, mem_kind(100), 6), // Def C from loop back edge (instr 8 in block 6)
        ]
        .iter()
        .cloned()
        .collect();
        assert_eq!(flow6.defs_in, expected_defs_in6, "DefsIn @ B6");

        // --- Check USE in loop block (Block 6) ---
        // output reads [100], addition reads [100], if reads [100]
        // All happen before the write at instr 8 within the block from the perspective of DefsIn.
        assert_eq!(
            flow6.use_before_def.keys().cloned().collect_vec(),
            [mem_kind(100)].iter().cloned().collect_vec(),
            "USE @ B6"
        );

        // --- Check GEN in loop block (Block 6) ---
        // The last write to [100] is at instruction 8
        assert_eq!(
            flow6.gen.iter().map(|(k, (i, _))| (*k, *i)).collect_vec(),
            [(mem_kind(100), InstructionId::from(8))]
                .iter()
                .cloned()
                .collect_vec(),
            "GEN @ B6"
        );

        // --- Check Defs out of loop block (Block 6) ---
        // This is DefsIn(6) - KilledDefs(6) U GenDefs(6)
        // KilledDefs = {Def A, Def C}, GenDefs = {Def C} => DefsOut = {Def C}
        let expected_defs_out6: HashSet<_> = [def(8, mem_kind(100), 6)].iter().cloned().collect();
        assert_eq!(flow6.defs_out, expected_defs_out6, "DefsOut @ B6");

        // --- Check Defs into exit block (Block 15) ---
        // Comes from the 'if' condition failing in block 6. Should receive DefsOut(6).
        assert_eq!(flow15.defs_in, expected_defs_out6, "DefsIn @ B15");
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

        let df_results = model.get_data_flow_result().unwrap();
        let _flow0 = df_results.block_results.get(&block0_id).unwrap();
        let flow21 = df_results.block_results.get(&block21_id).unwrap();
        let flow25 = df_results.block_results.get(&block25_id).unwrap();

        // --- Check USE in return block (Block 21) ---
        // This determines potential_returns for the call from block 0
        assert_eq!(
            flow21.use_before_def.keys().cloned().sorted().collect_vec(),
            [rel_kind(1), rel_kind(2)].iter().cloned().collect_vec(),
            "USE @ B21"
        );

        // --- Check Defs reaching return block (Block 21) ---
        let expected_defs_in21: HashSet<_> = [
            // Def A: [100]=50 (@0, i2) - Reaches, assuming [100] is distinct from [R+1],[R+2]
            def(2, mem_kind(100), 0),
            // Def B: [R+1]=[100] (@0, i6) - Killed by call because [R+1] is read in B21
            // Def C: [R+2]=99 (@0, i10) - Killed by call because [R+2] is read in B21
            // Abstract return def for [R+1] from call at instr 18 in block 0
            def(14, rel_kind(0), 0), // RetDef F
        ]
        .iter()
        .cloned()
        .collect();
        assert_eq!(flow21.defs_in, expected_defs_in21, "DefsIn @ B21");

        // --- Check Defs out of return block (Block 21) ---
        // Should be same as DefsIn, since output doesn't kill/gen memory defs
        assert_eq!(flow21.defs_out, expected_defs_in21, "DefsOut @ B21");

        // --- Check Defs into actual return sequence (Block 25) ---
        assert_eq!(flow25.defs_in, expected_defs_in21, "DefsIn @ B25");
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

        let df_results = model.get_data_flow_result().unwrap();
        let flow0 = df_results.block_results.get(&block0_id).unwrap();
        let flow12 = df_results.block_results.get(&block12_id).unwrap();

        // GEN should only contain the *last* write
        let gen_items: Vec<_> = flow0.gen.iter().map(|(k, (i, _))| (*k, *i)).collect();
        assert_eq!(gen_items.len(), 1);
        assert_eq!(gen_items[0].0, mem_kind(100));
        assert_eq!(gen_items[0].1, InstructionId::from(6)); // Only Def B

        // Defs Out should only contain Def B
        let expected_defs_out0: HashSet<_> = [def(6, mem_kind(100), 0)].iter().cloned().collect(); // Only Def B
        assert_eq!(flow0.defs_out, expected_defs_out0, "DefsOut @ B0");

        // Defs In for return block should only contain Def B
        assert_eq!(flow12.defs_in, expected_defs_out0, "DefsIn @ B12");
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

        let df_results = model.get_data_flow_result().unwrap();

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

        assert_eq!(
            df_results
                .block_results
                .iter()
                .filter(|(_, br)| {
                    br.function_returns_in
                        .iter()
                        .any(|fc| fc.function_addr.kind.get_immediate() == Some(124))
                })
                .map(|(id, _)| *id)
                .sorted()
                .collect_vec(),
            func3_returns_blocks,
            "Blocks that should have function returns from func3 do have them",
        );

        // Test there are no return values from calls that haven't happened yet
        let cont_block = BlockId::from(26);
        let cont_flow = df_results.block_results.get(&cont_block).unwrap();

        // Block 26 (cont:) should not have any function return definitions from func2
        let func2_addr = imm_kind(115);

        // Check that cont_flow.function_returns_in doesn't contain a function call to func2
        let cont_block_func2_returns = cont_flow
            .function_returns_in
            .iter()
            .any(|fc| fc.function_addr.kind == func2_addr);

        assert!(
            !cont_block_func2_returns,
            "Block 26 should not have function return definitions from func2"
        );

        // Block 53 should have definition for [R+1] from func3 specifically
        let block53 = BlockId::from(53);
        let block53_flow = df_results.block_results.get(&block53).unwrap();

        // Check for function return from func3 (address 124)
        let func3_returns = block53_flow
            .function_returns_in
            .iter()
            .filter(|fc| fc.function_addr.kind == imm_kind(124))
            .collect::<Vec<_>>();

        // Verify we have at least one function return from func3
        assert!(
            !func3_returns.is_empty(),
            "Block 53 should have at least one return definition from func3"
        );

        // Verify block53 has [R+1] in use_before_def, indicating it's reading a return value
        assert!(
            block53_flow.use_before_def.contains_key(&rel_kind(1)),
            "Block 53 should have [R+1] in use_before_def as a return value from func3"
        );

        // Verify the calling block has 1 ([R+1]) in its call_site_info.return_values_accessed
        let calling_block = func3_returns[0].calling_block;
        let calling_block_flow = df_results.block_results.get(&calling_block).unwrap();

        assert!(
            calling_block_flow.call_site_info.as_ref().unwrap().return_values_accessed.contains_key(&1),
            "The calling block for func3 should have 1 ([R+1]) in its call_site_info.return_values_accessed"
        );
    }
}
