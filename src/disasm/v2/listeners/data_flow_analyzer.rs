use std::collections::{HashMap, HashSet};

use log::debug;

use crate::disasm::v2::instructions::OperandKind;
use crate::disasm::v2::{
    control_flow::{NextKind, PredecessorKind},
    data_flow::{BlockDataFlow, DataFlowResult, Definition, DefinitionKind},
    events::{self, DataFlowAnalysisComplete, FunctionCfgBuilt, ModelEventListener},
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
        let potential_return_kinds = Self::find_potential_return_kinds(model, func_id);

        // Pass 1: Initialize GEN and USE_BEFORE_DEF for each block
        self.initialize_gen_use(model, block_ids, df_result);

        // Pass 2: Reaching Definitions (Forward Analysis)
        self.run_reaching_definitions_analysis(
            model,
            block_ids,
            df_result,
            &potential_return_kinds,
        );

        // Pass 3: Liveness Analysis (Backward Analysis)
        self.run_liveness_analysis(model, block_ids, df_result);

        debug!("Data Flow Analysis passes complete for {}", func_id);
    }

    fn find_potential_return_kinds(
        model: &ProgramModel,
        func_id: FunctionId,
    ) -> HashMap<BlockId, HashSet<OperandKind>> {
        // Implementation as provided previously... unchanged.
        let mut return_kinds: HashMap<BlockId, HashSet<OperandKind>> = HashMap::new();
        let func = model.get_function(func_id);

        for &block_id in &func.blocks {
            let block = model.get_block(block_id);
            let mut block_return_kinds = HashSet::new();
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
                                println!(
                                    "Found potential return operand: {} in block {} at {}",
                                    read_op.kind, block.span, instr.id
                                );
                                block_return_kinds.insert(read_op.kind);
                            }
                        }
                    }
                }
            }
            return_kinds.insert(block_id, block_return_kinds);
        }
        debug!(
            "Potential return kinds for {:?}: {:?}",
            func_id, return_kinds
        );
        return_kinds
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
                    if !defined_in_block.contains(&read_operand.kind) {
                        block_flow.use_before_def.insert(read_operand.kind);
                    }
                }
                // Calculate GEN for this instruction
                if let Some(write_operand) = instr.writes() {
                    block_flow.gen.insert(write_operand.kind, instr.id);
                    defined_in_block.insert(write_operand.kind);
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
        potential_return_kinds: &HashMap<BlockId, HashSet<OperandKind>>,
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
                    potential_return_kinds.get(&block_id).unwrap(),
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
                let killed_kinds: HashSet<&OperandKind> = block_flow.gen.keys().collect();
                let mut current_defs_out = block_flow.defs_in.clone();
                current_defs_out.retain(|def| !killed_kinds.contains(&def.location));

                // Add GEN set
                for (location, instruction_id) in &block_flow.gen {
                    current_defs_out.insert(Definition {
                        instruction_id: *instruction_id,
                        location: *location,
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

    /// Determines if an operand is used in a block or any of its successors without
    /// being redefined first and without crossing a function call boundary.
    fn is_used_in_execution_paths(
        &self,
        model: &ProgramModel,
        block_id: BlockId,
        operand: &OperandKind,
        function_block_ids: &[BlockId],
        df_result: &DataFlowResult,
        visited: &mut HashSet<BlockId>,
    ) -> bool {
        // Avoid infinite recursion in case of loops
        if !visited.insert(block_id) {
            return false;
        }

        // Check if directly used in this block
        if let Some(block_flow) = df_result.block_results.get(&block_id) {
            // If it's in the USE_BEFORE_DEF set, it's used before any redefinition
            if block_flow.use_before_def.contains(operand) {
                return true;
            }

            // If it's redefined in this block, the search stops here
            if block_flow.gen.contains_key(operand) {
                return false;
            }
        }

        // Check successors (if not redefined and not a function call)
        let block = model.get_block(block_id);
        match &block.next {
            NextKind::Follows(next_id) => {
                if function_block_ids.contains(next_id) {
                    return self.is_used_in_execution_paths(
                        model,
                        *next_id,
                        operand,
                        function_block_ids,
                        df_result,
                        visited,
                    );
                }
            }
            NextKind::Goto(op) => {
                // For immediate goto targets (not function calls), continue search
                if let Some(target_addr) = op.kind.get_immediate() {
                    let target_id = BlockId::from(target_addr as usize);
                    if function_block_ids.contains(&target_id) {
                        return self.is_used_in_execution_paths(
                            model,
                            target_id,
                            operand,
                            function_block_ids,
                            df_result,
                            visited,
                        );
                    }
                }
                // Indirect jumps (like goto [r]) terminate the search path since we can't determine target statically
            }
            NextKind::Condition(cond) => {
                // Check both branches
                let target_result = if function_block_ids.contains(&cond.target_block) {
                    self.is_used_in_execution_paths(
                        model,
                        cond.target_block,
                        operand,
                        function_block_ids,
                        df_result,
                        visited,
                    )
                } else {
                    false
                };

                let follows_result = if function_block_ids.contains(&cond.follows_block) {
                    self.is_used_in_execution_paths(
                        model,
                        cond.follows_block,
                        operand,
                        function_block_ids,
                        df_result,
                        visited,
                    )
                } else {
                    false
                };

                if target_result || follows_result {
                    return true;
                }
            }
            NextKind::FunctionCall(_) => {
                // Stop tracking here - any use after a function call should be
                // attributed to that function call, not to a previous one
                return false;
            }
            // Return or Halt terminates the search - we don't track across function returns
            _ => {}
        }

        false
    }

    /// Calculates the Defs-In set for a single block based on its predecessors.
    fn calculate_defs_in(
        &self,
        model: &ProgramModel,
        block_id: BlockId,
        function_block_ids: &[BlockId], // IDs of blocks within the current function
        df_result: &DataFlowResult,     // Read-only access for predecessor OUT sets
        potential_return_kinds: &HashSet<OperandKind>,
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
                    // Definitions from predecessor that are not potential return values
                    let mut defs_from_caller = pred_flow.defs_out.clone();
                    defs_from_caller.retain(|def| !potential_return_kinds.contains(&def.location));
                    new_defs_in.extend(defs_from_caller);

                    // Only add return definitions for operands that will be used
                    let call_instruction_id = model
                        .get_block(call.calling_block)
                        .instructions
                        .last()
                        .expect("Calling block cannot be empty")
                        .id;

                    // For each potential return operand, check if it's actually used
                    for ret_kind in potential_return_kinds {
                        // Check if this return operand is used in the current block or its successors
                        let mut visited = HashSet::new();
                        if self.is_used_in_execution_paths(
                            model,
                            block_id,
                            ret_kind,
                            function_block_ids,
                            df_result,
                            &mut visited,
                        ) {
                            // Only add return definition if it's actually used
                            new_defs_in.insert(Definition {
                                instruction_id: call_instruction_id,
                                location: *ret_kind,
                                block_id: call.calling_block,
                                kind: DefinitionKind::FunctionReturn {
                                    function_addr: call.function_addr.kind,
                                },
                            });
                        }
                    }
                }
                _ => {
                    // Standard handling for non-function-return predecessors
                    new_defs_in.extend(&pred_flow.defs_out);
                }
            }
        }

        if block_id == BlockId::from(1993) {
            println!("{}: new_defs_in: {:?}", block_id, new_defs_in);
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
                let defined_kinds: HashSet<OperandKind> = block_flow.gen.keys().cloned().collect();
                let mut current_live_in = block_flow.live_out.clone();
                current_live_in.retain(|kind| !defined_kinds.contains(kind));
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
    ) -> HashSet<OperandKind> {
        let block = model.get_block(block_id);
        let mut new_live_out = HashSet::new();

        let add_live_in_from_successor = |succ_id: BlockId, live_out: &mut HashSet<OperandKind>| {
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
            instructions::{InstructionId, Operand, OperandKind},
            listeners::{
                control_flow_builder::ControlFlowGraphBuilder, image_scanner::ImageScanner,
            },
            model::*, // Bring model types into scope
        },
    };
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
        publisher.process_events(&mut model);
        model // Return model with CFG and DataFlow results
    }

    // Helper to create an Operand for assertions (adjust offset as needed)
    fn mem_op(addr: i128) -> Operand {
        Operand {
            kind: OperandKind::Memory(addr),
            offset: 0, // Offset doesn't affect equality/hash if kind is Memory(v)
            debug_marker: None,
        }
    }
    fn rel_op(offset: i128) -> Operand {
        Operand {
            kind: OperandKind::RelativeMemory(offset),
            offset: 0, // Offset doesn't affect equality/hash if kind is RelativeMemory(v)
            debug_marker: None,
        }
    }
    fn imm_op(val: i128) -> Operand {
        Operand {
            kind: OperandKind::Immediate(val),
            offset: 0, // Offset doesn't affect equality/hash if kind is Immediate(v)
            debug_marker: None,
        }
    }

    // Helper to create an OperandKind for assertions
    fn mem_kind(addr: i128) -> OperandKind {
        OperandKind::Memory(addr)
    }
    fn rel_kind(offset: i128) -> OperandKind {
        OperandKind::RelativeMemory(offset)
    }
    fn imm_kind(val: i128) -> OperandKind {
        OperandKind::Immediate(val)
    }

    // Helper to create a Definition for assertions
    fn def(
        instr_id_val: usize, // Use instruction offset as ID for simplicity in tests
        location: OperandKind,
        block_id_val: usize,
        kind: DefinitionKind,
    ) -> Definition {
        Definition {
            instruction_id: InstructionId::from(instr_id_val),
            location,
            block_id: BlockId::from(block_id_val),
            kind,
        }
    }
    // Helper for InstructionWrite definitions
    fn instr_def(instr_id: usize, location: OperandKind, block_id: usize) -> Definition {
        def(
            instr_id,
            location,
            block_id,
            DefinitionKind::InstructionWrite,
        )
    }
    // Helper for FunctionReturn definitions
    fn ret_def(
        call_instr_id: usize,   // ID of the 'goto @func' instruction
        location: OperandKind,  // The [R+n] operand
        call_block_id: usize,   // Block containing the call sequence
        function_addr: Operand, // Operand representing the called function's address
    ) -> Definition {
        def(
            call_instr_id,
            location,
            call_block_id,
            DefinitionKind::FunctionReturn {
                function_addr: function_addr.kind,
            },
        )
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
        assert_eq!(flow0.gen.len(), 2);
        assert_eq!(
            flow0.gen[&mem_kind(100)],
            InstructionId::from(2),
            "GEN[100] @ B0"
        );
        assert_eq!(
            flow0.gen[&mem_kind(101)],
            InstructionId::from(6),
            "GEN[101] @ B0"
        );
        assert!(flow0.use_before_def.is_empty(), "USE @ B0");

        // Reaching Defs
        assert!(flow0.defs_in.is_empty(), "DefsIn @ B0");
        let expected_defs_out0: HashSet<_> = [
            instr_def(2, mem_kind(100), 0), // Def A
            instr_def(6, mem_kind(101), 0), // Def B
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
            flow12.use_before_def,
            [rel_kind(0)].iter().cloned().collect(),
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
        let flow0 = df_results.block_results.get(&block0_id).unwrap();
        let flow9 = df_results.block_results.get(&block9_id).unwrap();
        let flow16 = df_results.block_results.get(&block16_id).unwrap();
        let flow20 = df_results.block_results.get(&block20_id).unwrap();
        let flow22 = df_results.block_results.get(&block22_id).unwrap();

        // --- Check Defs reaching merge block (Block 20) ---
        let expected_defs_in20: HashSet<_> = [
            instr_def(2, mem_kind(100), 0),   // Def A from block 0
            instr_def(9, mem_kind(101), 9),   // Def B from false path block 9
            instr_def(16, mem_kind(101), 16), // Def C from true path block 16
        ]
        .iter()
        .cloned()
        .collect();
        assert_eq!(flow20.defs_in, expected_defs_in20, "DefsIn @ B20");

        // --- Check USE in merge block (Block 20) ---
        assert_eq!(
            flow20.use_before_def,
            [mem_kind(101)].iter().cloned().collect(),
            "USE @ B20"
        );
        assert!(flow20.gen.is_empty(), "GEN @ B20"); // Output doesn't generate defs

        // --- Check GEN in branches ---
        assert_eq!(
            flow9.gen,
            [(mem_kind(101), InstructionId::from(9))]
                .iter()
                .cloned()
                .collect(),
            "GEN @ B9"
        );
        assert_eq!(
            flow16.gen,
            [(mem_kind(101), InstructionId::from(16))]
                .iter()
                .cloned()
                .collect(),
            "GEN @ B16"
        );

        // --- Check Defs reaching branches ---
        let expected_defs_in_branches: HashSet<_> =
            [instr_def(2, mem_kind(100), 0)].iter().cloned().collect(); // Only Def A reaches
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
        let flow0 = df_results.block_results.get(&block0_id).unwrap();
        let flow6 = df_results.block_results.get(&block6_id).unwrap();
        let flow15 = df_results.block_results.get(&block15_id).unwrap();

        // --- Check Defs reaching loop header/body (Block 6) ---
        // Should receive Def A from block 0 AND Def C from loop back edge
        let expected_defs_in6: HashSet<_> = [
            instr_def(2, mem_kind(100), 0), // Def A from block 0
            instr_def(8, mem_kind(100), 6), // Def C from loop back edge (instr 8 in block 6)
        ]
        .iter()
        .cloned()
        .collect();
        assert_eq!(flow6.defs_in, expected_defs_in6, "DefsIn @ B6");

        // --- Check USE in loop block (Block 6) ---
        // output reads [100], addition reads [100], if reads [100]
        // All happen before the write at instr 8 within the block from the perspective of DefsIn.
        assert_eq!(
            flow6.use_before_def,
            [mem_kind(100)].iter().cloned().collect(),
            "USE @ B6"
        );

        // --- Check GEN in loop block (Block 6) ---
        // The last write to [100] is at instruction 8
        assert_eq!(
            flow6.gen,
            [(mem_kind(100), InstructionId::from(8))]
                .iter()
                .cloned()
                .collect(),
            "GEN @ B6"
        );

        // --- Check Defs out of loop block (Block 6) ---
        // This is DefsIn(6) - KilledDefs(6) U GenDefs(6)
        // KilledDefs = {Def A, Def C}, GenDefs = {Def C} => DefsOut = {Def C}
        let expected_defs_out6: HashSet<_> =
            [instr_def(8, mem_kind(100), 6)].iter().cloned().collect();
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

        let main_id = FunctionId::from(0);
        let block0_id = BlockId::from(0); // main entry + call setup
        let block21_id = BlockId::from(21); // main return block
        let block25_id = BlockId::from(25); // main actual return sequence

        let df_results = model.get_data_flow_result().unwrap();
        let flow0 = df_results.block_results.get(&block0_id).unwrap();
        let flow21 = df_results.block_results.get(&block21_id).unwrap();
        let flow25 = df_results.block_results.get(&block25_id).unwrap();

        // --- Check USE in return block (Block 21) ---
        // This determines potential_returns for the call from block 0
        assert_eq!(
            flow21.use_before_def,
            [rel_kind(1), rel_kind(2)].iter().cloned().collect(),
            "USE @ B21"
        );

        // --- Check Defs reaching return block (Block 21) ---
        let callee_addr_op = imm_op(30); // Address of callee for FunctionReturn kind
        let expected_defs_in21: HashSet<_> = [
            // Def A: [100]=50 (@0, i2) - Reaches, assuming [100] is distinct from [R+1],[R+2]
            instr_def(2, mem_kind(100), 0),
            // Def B: [R+1]=[100] (@0, i6) - Killed by call because [R+1] is read in B21
            // Def C: [R+2]=99 (@0, i10) - Killed by call because [R+2] is read in B21
            // Abstract return def for [R+1] from call at instr 18 in block 0
            ret_def(18, rel_kind(1), 0, callee_addr_op), // RetDef D
            // Abstract return def for [R+2] from call at instr 18 in block 0
            ret_def(18, rel_kind(2), 0, callee_addr_op), // RetDef E
            instr_def(14, rel_kind(0), 0),               // RetDef F
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
        assert_eq!(
            flow0.gen,
            [(mem_kind(100), InstructionId::from(6))] // Only Def B
                .iter()
                .cloned()
                .collect(),
            "GEN @ B0"
        );

        // Defs Out should only contain Def B
        let expected_defs_out0: HashSet<_> =
            [instr_def(6, mem_kind(100), 0)].iter().cloned().collect(); // Only Def B
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
        // that propagate to multiple blocks
        let func3_call_blocks = [
            BlockId::from(53), // Direct return target
            BlockId::from(56), // Reachable through control flow
            BlockId::from(67),
            BlockId::from(70),
            BlockId::from(30),
            BlockId::from(81),
            BlockId::from(92),
        ];

        // Check that all these blocks have function return values from func3
        for block_id in func3_call_blocks {
            let has_func3_return = df_results
                .block_results
                .get(&block_id)
                .map(|flow| {
                    flow.defs_in.iter().any(|def| {
                        matches!(def.kind, DefinitionKind::FunctionReturn { function_addr }
                             if function_addr == imm_kind(124))
                    })
                })
                .unwrap_or(false);

            assert!(
                has_func3_return,
                "Block {} should have function return definition from func3",
                block_id
            );
        }
        // Test there are no return values from calls that haven't happened yet
        let cont_block = BlockId::from(26);
        let cont_flow = df_results.block_results.get(&cont_block).unwrap();

        // Block 26 (cont:) should not have any function return definitions from func2
        let func2_addr = imm_kind(115);
        let cont_block_func2_returns: Vec<_> = cont_flow
            .defs_in
            .iter()
            .filter(|d| {
                matches!(d.kind, DefinitionKind::FunctionReturn { function_addr } if function_addr == func2_addr)
            })
            .collect();

        assert!(
            cont_block_func2_returns.is_empty(),
            "Block 26 should not have function return definitions from func2"
        );

        // Block 53 should have definition for [R+1] from func3 specifically
        let block53 = BlockId::from(53);
        let block53_flow = df_results.block_results.get(&block53).unwrap();
        let func3_return_defs: Vec<_> = block53_flow
            .defs_in
            .iter()
            .filter(|d| {
                matches!(d.kind, DefinitionKind::FunctionReturn { function_addr }
                         if function_addr == imm_kind(124))
            })
            .collect();

        // Verify we have at least one definition
        assert!(
            !func3_return_defs.is_empty(),
            "Block 53 should have at least one return definition from func3"
        );

        // Verify we have a definition for [R+1]
        let func3_r_plus_1_def = func3_return_defs.iter().any(|d| d.location == rel_kind(1));
        assert!(
            func3_r_plus_1_def,
            "Block 53 should have a return definition for [R+1] from func3"
        );
    }
}
