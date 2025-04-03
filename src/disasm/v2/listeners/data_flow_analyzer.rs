use std::collections::HashSet;

use log::debug;

use crate::disasm::v2::{
    control_flow::{NextKind, PredecessorKind},
    data_flow::{BlockDataFlow, DataFlowResult, Definition, DefinitionKind},
    events::{self, DataFlowAnalysisComplete, FunctionCfgBuilt, ModelEventListener},
    instructions::Operand,
    model::{BlockId, FunctionId, ProgramModel},
};

pub struct DataFlowAnalyzer {}

impl DataFlowAnalyzer {
    pub fn new() -> Self {
        DataFlowAnalyzer {}
    }

    /// Performs the main data flow analysis passes for a given function.
    fn analyze_function(
        &self,
        model: &ProgramModel,
        func_id: FunctionId,
        df_result: &mut DataFlowResult,
    ) {
        let func = model.get_function(func_id);
        let block_ids = &func.blocks;

        // Pre-computation: Identify potential return operands
        let potential_returns = find_potential_return_operands(model, func_id);

        // Pass 1: Initialize GEN and USE_BEFORE_DEF for each block
        self.initialize_gen_use(model, block_ids, df_result);

        // Pass 2: Reaching Definitions (Forward Analysis)
        self.run_reaching_definitions_analysis(model, block_ids, df_result, &potential_returns);

        // Pass 3: Liveness Analysis (Backward Analysis)
        self.run_liveness_analysis(model, block_ids, df_result);

        debug!("Data Flow Analysis passes complete for {}", func_id);
    }

    /// Pass 1: Initializes GEN and USE_BEFORE_DEF sets for all blocks in the function.
    fn initialize_gen_use(
        &self,
        model: &ProgramModel,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
    ) {
        for &block_id in block_ids {
            let block = model.get_block(block_id);
            let block_flow = df_result.block_results.entry(block_id).or_default();

            let mut defined_in_block = HashSet::new();
            for instr in &block.instructions {
                // Calculate USE for this instruction
                for read_operand in instr.reads() {
                    if !defined_in_block.contains(read_operand) {
                        block_flow.use_before_def.insert(*read_operand);
                    }
                }
                // Calculate GEN for this instruction
                if let Some(write_operand) = instr.writes() {
                    block_flow.gen.insert(*write_operand, instr.id);
                    defined_in_block.insert(*write_operand);
                }
            }
            debug!(
                "Block {}: GEN={:?}, USE={:?}",
                block_id,
                block_flow.gen.keys().collect::<Vec<_>>(),
                block_flow.use_before_def
            );
        }
    }

    /// Pass 2: Computes Reaching Definitions iteratively.
    fn run_reaching_definitions_analysis(
        &self,
        model: &ProgramModel,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
        potential_returns: &HashSet<Operand>,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            for &block_id in block_ids {
                let new_defs_in = self.calculate_defs_in(
                    model,
                    block_id,
                    block_ids,
                    df_result,
                    potential_returns,
                );

                // Update block's IN set if changed
                // Use get_mut for direct modification
                let block_flow = df_result.block_results.get_mut(&block_id).unwrap(); // Must exist
                if new_defs_in != block_flow.defs_in {
                    debug!("Block {:?}: DefsIn changed", block_id);
                    block_flow.defs_in = new_defs_in;
                    changed = true; // Continue iteration if IN changed
                }

                // Calculate OUT set: OUT = (IN - KILL) U GEN
                let killed_operands: HashSet<&Operand> = block_flow.gen.keys().collect();
                let mut current_defs_out = block_flow.defs_in.clone();
                current_defs_out.retain(|def| !killed_operands.contains(&def.operand));

                // Add GEN set
                for (operand, instruction_id) in &block_flow.gen {
                    current_defs_out.insert(Definition {
                        instruction_id: *instruction_id,
                        operand: *operand,
                        block_id,
                        kind: DefinitionKind::InstructionWrite,
                    });
                }

                // Update block's OUT set if changed
                if current_defs_out != block_flow.defs_out {
                    debug!("Block {:?}: DefsOut changed", block_id);
                    block_flow.defs_out = current_defs_out;
                    // Change automatically handled by the outer loop condition
                }
            }
        }
    }

    /// Calculates the Defs-In set for a single block based on its predecessors.
    fn calculate_defs_in(
        &self,
        model: &ProgramModel,
        block_id: BlockId,
        function_block_ids: &[BlockId], // IDs of blocks within the current function
        df_result: &DataFlowResult,     // Read-only access for predecessor OUT sets
        potential_returns: &HashSet<Operand>,
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

            match pred_kind {
                PredecessorKind::FunctionCallReturns(call) => {
                    let mut defs_from_caller = pred_flow.defs_out.clone();
                    defs_from_caller.retain(|def| !potential_returns.contains(&def.operand));

                    let call_instruction_id = model
                        .get_block(call.calling_block)
                        .instructions
                        .last()
                        .expect("Calling block cannot be empty")
                        .id;

                    for ret_op in potential_returns {
                        defs_from_caller.insert(Definition {
                            instruction_id: call_instruction_id,
                            operand: *ret_op,
                            block_id: call.calling_block,
                            kind: DefinitionKind::FunctionReturn,
                        });
                    }
                    new_defs_in.extend(defs_from_caller);
                }
                _ => {
                    // Standard handling
                    new_defs_in.extend(&pred_flow.defs_out);
                }
            }
        }
        new_defs_in
    }

    /// Pass 3: Computes Liveness iteratively.
    fn run_liveness_analysis(
        &self,
        model: &ProgramModel,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            // Iterate backwards - often converges faster for backward analyses like liveness
            for &block_id in block_ids.iter().rev() {
                let new_live_out = self.calculate_live_out(model, block_id, block_ids, df_result);

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
                let defined_operands: HashSet<Operand> = block_flow.gen.keys().cloned().collect();
                let mut current_live_in = block_flow.live_out.clone();
                current_live_in.retain(|operand| !defined_operands.contains(operand));
                current_live_in.extend(block_flow.use_before_def.iter().cloned());

                // Update block's IN set if changed
                if current_live_in != block_flow.live_in {
                    debug!(
                        "Block {:?}: LiveIn changed to {:?}",
                        block_id, current_live_in
                    );
                    block_flow.live_in = current_live_in;
                    // Change automatically handled by the outer loop condition
                }
            }
        }
    }

    /// Calculates the Live-Out set for a single block based on its successors' Live-In sets.
    fn calculate_live_out(
        &self,
        model: &ProgramModel,
        block_id: BlockId,
        function_block_ids: &[BlockId], // IDs of blocks within the current function
        df_result: &DataFlowResult,     // Read-only access for successor IN sets
    ) -> HashSet<Operand> {
        let block = model.get_block(block_id);
        let mut new_live_out = HashSet::new();

        let add_live_in_from_successor = |succ_id: BlockId, live_out: &mut HashSet<Operand>| {
            // Ensure successor is within the same function
            if function_block_ids.contains(&succ_id) {
                if let Some(succ_flow) = df_result.block_results.get(&succ_id) {
                    live_out.extend(&succ_flow.live_in);
                } else {
                    // This might happen if analysis hasn't reached the successor yet
                    // in the initial iterations. It will be empty initially.
                    debug!(
                        "Successor {} of {} not yet analyzed for liveness, assuming empty live_in",
                        succ_id, block_id
                    );
                }
            } else {
                debug!(
                    "Successor {} of {} is outside the current function, ignoring for liveness",
                    succ_id, block_id
                );
            }
        };

        match &block.next {
            NextKind::Follows(succ_id) => {
                add_live_in_from_successor(*succ_id, &mut new_live_out);
            }
            NextKind::Goto(operand) => {
                // Only consider immediate jumps for intra-procedural analysis
                if let Some(target_addr) = operand.kind.get_immediate() {
                    add_live_in_from_successor(
                        BlockId::from(target_addr as usize),
                        &mut new_live_out,
                    );
                } else {
                    debug!("Non-immediate goto target {:?} from {:?}, cannot determine successor live_in", operand, block_id);
                    // Cannot determine successor statically here
                }
            }
            NextKind::Condition(cond) => {
                add_live_in_from_successor(cond.target_block, &mut new_live_out);
                add_live_in_from_successor(cond.follows_block, &mut new_live_out);
            }
            NextKind::FunctionCall(call) => {
                // Live variables after a call are those live at the start of the return block.
                add_live_in_from_successor(call.return_block, &mut new_live_out);
                // We could potentially add arguments here if they are pointers/mutable,
                // but basic liveness usually doesn't track that across calls.
            }
            NextKind::Return => {
                // Intra-procedural liveness: Nothing is live *within this function* after return.
                // Inter-procedural analysis would consider return values used by callers.
            }
            NextKind::Halt | NextKind::Unknown => {
                // Nothing is live after Halt or Unknown paths within the function.
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
    ) {
        debug!("Starting Data Flow Analysis for {:?}", event.function_id);

        // Create a temporary result container for this function's analysis
        // Note: We'll modify the global result directly later, but this structure helps organize.
        let mut df_result_for_function = DataFlowResult::new();
        // Initialize block entries for this function
        for &block_id in &model.get_function(event.function_id).blocks {
            df_result_for_function
                .block_results
                .insert(block_id, BlockDataFlow::new());
        }

        // Perform analysis directly on the global result structure within the model
        self.analyze_function(model, event.function_id, &mut df_result_for_function);

        // Get or create the global result container in the model
        if model.get_data_flow_result().is_none() {
            model.set_data_flow_result(DataFlowResult::new());
        }
        let global_results = model.get_data_flow_result_mut().unwrap(); // Now safe to unwrap
                                                                        // Ensure all block entries for this function exist in the global map
        global_results
            .block_results
            .extend(df_result_for_function.block_results);

        // Publish completion event for this function
        sender.publish(DataFlowAnalysisComplete {
            function_id: event.function_id,
        });
        debug!("Data Flow Analysis committed for {}", event.function_id);
    }
}

// Helper function (can be placed inside DataFlowAnalyzer impl or outside)
fn find_potential_return_operands(model: &ProgramModel, func_id: FunctionId) -> HashSet<Operand> {
    // Implementation as provided previously... unchanged.
    let mut return_operands = HashSet::new();
    let func = model.get_function(func_id);

    for &block_id in &func.blocks {
        let block = model.get_block(block_id);
        // Check if this block is entered via a function call return
        let is_return_target = block
            .predecessors
            .iter()
            .any(|p| matches!(p, PredecessorKind::FunctionCallReturns(_)));

        if is_return_target {
            // Look for reads of [R+n] within this block
            for instr in &block.instructions {
                for read_op in instr.reads() {
                    // Check if it's a relative memory access with positive offset
                    if let Some(offset) = read_op.kind.get_relative_memory() {
                        if offset > 0 {
                            return_operands.insert(*read_op);
                        }
                    }
                }
            }
        }
    }
    debug!(
        "Potential return operands for {:?}: {:?}",
        func_id, return_operands
    );
    return_operands
}

// TODO: Add tests
