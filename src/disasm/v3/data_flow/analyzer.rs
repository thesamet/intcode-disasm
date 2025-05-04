use itertools::Itertools;
use log::debug;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::disasm::v3::common::{CallSiteInfo, FunctionCall}; // Keep FunctionCall from common
use crate::disasm::v3::control_flow::{BlockView, FunctionView, NextKind, PredecessorKind};
use crate::disasm::v3::id_types::{BlockId, FunctionId, InstructionId};
use crate::disasm::v3::lir::{Expression, MemoryReference, MemoryReferenceInfo}; // Use LIR types
use crate::disasm::v3::model::{ControlFlowGraphComplete, DataFlowComplete, Model};
use crate::disasm::Error;

use super::block::{DataFlowBlock, Definition, OriginationPoint};
use super::result::DataFlowResult;

type Function<'a> = FunctionView<'a, ControlFlowGraphComplete>;

/// Analyzes data flow in the control flow graph
pub struct DataFlowAnalyzer {
    model: Model<ControlFlowGraphComplete>,
}

impl DataFlowAnalyzer {
    pub fn new(model: Model<ControlFlowGraphComplete>) -> Self {
        Self { model }
    }

    pub fn run(model: Model<ControlFlowGraphComplete>) -> Result<Model<DataFlowComplete>, Error> {
        let analyzer = Self::new(model);
        analyzer.analyze()
    }

    fn analyze(&self) -> Result<Model<DataFlowComplete>, Error> {
        let mut result = DataFlowResult::new();

        // Get all functions from the control flow graph

        // Analyze each function
        for (_, f) in self.model.functions() {
            self.analyze_function(&f, &mut result); // Pass reference &f
        }

        // Return a new model with the updated state
        Ok(self.model.clone().with_data_flow_result(result))
    }

    /// Performs the main data flow analysis passes for a given function.
    fn analyze_function(&self, function: &Function, df_result: &mut DataFlowResult) {
        // Pass 1: Initialize gen, use_before_def and function_returns_in for each block
        self.initialize_gen_use_func_in(function, df_result); // Pass reference

        // Pass 2: compute function_returns_out and function_returns_in for all blocks (forward analysis)
        self.run_function_returns_analysis(function, df_result); // Pass reference

        // Pass 3: Reaching Definitions (Forward Analysis)
        self.run_reaching_definitions_analysis(function, df_result); // Pass reference

        // Pass 4: Liveness Analysis (Backward Analysis)
        self.run_liveness_analysis(function, df_result); // Pass reference

        debug!(
            "Data Flow Analysis passes complete for {}",
            function.function_id()
        );

        // Pass 5: Update Call Site Info based on return value usage
        self.update_call_site_info(function, df_result);
    }

    /// Pass 1: Initializes gen, use_before_def and function_returns_in sets for all blocks in the function.
    fn initialize_gen_use_func_in(&self, function: &Function, df_result: &mut DataFlowResult) {
        // Take &Function
        for (block_id, block) in function.blocks() {
            let block_flow = df_result
                .blocks
                .entry(block_id)
                .or_insert_with(DataFlowBlock::new);

            let mut defined_in_block = HashSet::new();
            block_flow.writes_above_r = false;

            // Initialize call_site_info if this block ends with a function call
            if matches!(block.next(), NextKind::FunctionCall(_)) {
                block_flow.call_site_info = Some(CallSiteInfo::new());
            }

            for instr in block.low_instructions() {
                // Calculate USE for this instruction
                for r in instr.kind.collect_read_addresses().into_iter() {
                    if !defined_in_block.contains(r) {
                        // Specify type for contains
                        block_flow.use_before_def.insert(r.clone(), instr.id); // Use instr.id, r.clone() is correct
                    }
                }

                // Calculate GEN for this instruction
                if let Some(write_operand) = instr.kind.get_write_address() {
                    // Use instr.kind
                    block_flow
                        .gen
                        .insert(write_operand.clone(), (instr.id, write_operand.clone())); // Use instr.id
                    defined_in_block.insert(write_operand.clone());

                    if let Some(n) = write_operand.as_stack_relative() {
                        if n > 0 {
                            block_flow.writes_above_r = true;
                        }
                    }
                }
            }

            // Function returns
            block_flow.function_returns_in = block
                .predecessors()
                .iter()
                .filter_map(|p| p.get_function_call_returns())
                .cloned()
                .collect::<HashSet<_>>(); // Added type annotation for collect

            debug!(
                "Block {:?}: GEN={:?}, USE={:?}, FuncIn={:?}", // Use block_id.0 for Debug
                block_id,
                block_flow.gen.keys().collect::<Vec<_>>(),
                block_flow.use_before_def,
                block_flow.function_returns_in // Added FuncIn to debug
            );
        }
    }

    // Pass 2: calculate function returns
    fn run_function_returns_analysis(
        &self,
        function: &Function, // Take &Function
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            for &block_id in function.all_block_ids() {
                // Function returns
                let new_func_in =
                    self.calculate_function_returns_in(function, &block_id, df_result); // Pass &block_id

                // Update block's IN set if changed
                let flow = df_result.blocks.get_mut(&block_id).unwrap();
                if new_func_in != flow.function_returns_in {
                    debug!("Block {:?}: FunctionReturnsIn changed", block_id); // Use block_id.0 for Debug
                    flow.function_returns_in = new_func_in.clone();
                    changed = true;
                }
                if !flow.writes_above_r && flow.function_returns_out != new_func_in {
                    flow.function_returns_out = new_func_in;
                    changed = true;
                }
            }
        }
    }

    fn calculate_function_returns_in(
        &self,
        function: &Function, // Take &Function
        block_id: &BlockId,
        df_result: &DataFlowResult,
    ) -> HashSet<FunctionCall<MemoryReference>> {
        let block = function.block(&block_id);
        let flow = df_result.blocks.get(&block_id).unwrap();
        let mut new_func_in = flow.function_returns_in.clone();

        // If this block is a return from a function call, we do not change new_func_in
        if !block
            .predecessors()
            .iter()
            .any(|p| p.get_function_call_returns().is_some())
        {
            for pred in block.predecessors() {
                // Update block's IN set if changed
                let pred_block_id = pred.source_block_id();
                let pred_block = df_result.blocks.get(&pred_block_id).unwrap();
                let pred_function_returns_out = pred_block.function_returns_out.clone();
                new_func_in.extend(pred_function_returns_out);
            }
        }
        new_func_in
    }

    /// Pass 3: Computes Reaching Definitions iteratively.
    fn run_reaching_definitions_analysis(
        &self,
        function: &Function, // Take &Function
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            for block_id in function.all_block_ids() {
                // Iterate over block_ids
                let block_view = function.block(block_id); // Get BlockView
                                                           // Definitions
                let new_defs_in = self.calculate_defs_in(function, &block_view, df_result); // Pass BlockView

                // Update block's IN set if changed
                let flow = df_result.blocks.get_mut(block_id).unwrap(); // Use block_id directly
                if new_defs_in != flow.defs_in {
                    debug!("Block {:?}: DefsIn changed", block_id); // Use block_id.0 for Debug
                    flow.defs_in = new_defs_in;
                    changed = true; // Continue iteration if IN changed
                }

                // Calculate OUT set: OUT = (IN - KILL) U GEN
                let killed_kinds: HashSet<&MemoryReference> = flow.gen.keys().collect();
                let mut current_defs_out = flow.defs_in.clone();
                current_defs_out.retain(|def| !killed_kinds.contains(&def.kind));

                // Add GEN set
                for (kind, (instruction_id, _)) in &flow.gen {
                    current_defs_out.insert(Definition {
                        source: OriginationPoint::Instruction(*instruction_id),
                        kind: kind.clone(),
                        block_id: *block_id, // Use dereferenced block_id
                    });
                }

                // If we call a function at the end of the block, this block doesn't let [R+n]
                // definitions flow forward.
                if matches!(block_view.next(), NextKind::FunctionCall(_)) {
                    // Use block_view
                    current_defs_out.retain(|d| !d.kind.as_stack_relative().is_some_and(|n| n > 0));
                    // Check if it's an outgoing parameter
                }

                // Update block's OUT set if changed
                if current_defs_out != flow.defs_out {
                    debug!("Block {:?}: DefsOut changed", block_id); // Use block_id.0 for Debug
                    flow.defs_out = current_defs_out;
                    changed = true;
                }
            }
        }
    }

    /// Calculates the Defs-In set for a single block based on its predecessors.
    fn calculate_defs_in(
        &self,
        function: &Function, // Take &Function
        block: &BlockView<ControlFlowGraphComplete>,
        df_result: &DataFlowResult,
    ) -> HashSet<Definition> {
        let mut new_defs_in = HashSet::new();

        for pred_kind in block.predecessors() {
            // Use block view
            let pred_block_id = pred_kind.source_block_id();
            let pred_block = df_result.blocks.get(&pred_block_id);
            let pred_flow = pred_block.as_ref().unwrap(); // TODO: Handle panic

            new_defs_in.extend(pred_flow.defs_out.iter().cloned());
        }

        if function.entry_block() == block.block_id() {
            // Use entry_block()
            // Create synthetic definitions for any potential input parameters
            // to this function. We take the union of all the use_before_def sets
            // for all blocks in the function, since it is a superset (which is still
            // smaller than all the reads).
            for (other_block_id, _) in function.blocks() {
                // Iterate view blocks
                let other_flow = df_result.blocks.get(&other_block_id).unwrap(); // TODO: Handle panic
                new_defs_in.extend(
                    other_flow
                        .use_before_def
                        .keys()
                        .filter(|k| k.as_stack_relative().is_some_and(|n| n <= 0)) // Check if it's a local or parameter
                        .map(|k| Definition {
                            source: OriginationPoint::FunctionInput,
                            kind: k.clone(),
                            block_id: block.block_id(), // Use view method
                        }),
                )
            }
        }

        new_defs_in
    }

    /// Pass 4: Computes Liveness iteratively.
    fn run_liveness_analysis(
        &self,
        function: &Function, // Take &Function
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            // Iterate backwards - often converges faster for backward analyses like liveness
            for &block_id in function.all_block_ids().collect_vec().iter().rev() {
                // Liveness
                let new_live_out = self.calculate_live_out(function, &block_id, df_result); // Pass &block_id

                // Update block's OUT set if changed
                let block_flow = df_result.blocks.get_mut(&block_id).unwrap();
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
                let defined_kinds: HashSet<MemoryReference> =
                    block_flow.gen.keys().cloned().collect();
                let mut current_live_in = block_flow.live_out.clone();

                // add potential_function_call_params.
                let block_view = function.block(&block_id); // Get BlockView
                if matches!(block_view.next(), NextKind::FunctionCall(_)) {
                    // Use block_view
                    for d in &block_flow.defs_in {
                        if d.kind.is_outgoing_parameter() {
                            // Use MemoryReferenceInfo trait directly on MemoryReference
                            current_live_in
                                .entry(d.kind.clone())
                                .or_insert_with(HashSet::new)
                                .insert(d.source);
                        }
                    }
                }

                current_live_in.retain(|kind, _| !defined_kinds.contains(kind));
                for (k, v) in &block_flow.use_before_def {
                    current_live_in
                        .entry(k.clone())
                        .or_insert_with(HashSet::new)
                        .insert(OriginationPoint::Instruction(*v)); // Use InstructionId directly
                }

                // Update block's IN set if changed
                if current_live_in != block_flow.live_in {
                    debug!(
                        "Block {:?}: LiveIn changed to {:?}", // Use block_id.0 for Debug
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
        &self,
        function: &Function, // Take &Function
        block_id: &BlockId,
        df_result: &DataFlowResult,
    ) -> HashMap<MemoryReference, HashSet<OriginationPoint>> {
        let block_view = function.block(block_id); // Get BlockView
        let mut new_live_out = HashMap::new();

        for succ_id in block_view.next().successors() {
            // Use block_view
            if let Some(succ_flow) = df_result.blocks.get(&succ_id) {
                // Handle potential missing block
                for (k, v) in &succ_flow.live_in {
                    new_live_out
                        .entry(k.clone())
                        .or_insert_with(HashSet::new)
                        .extend(v);
                }
            } else {
                debug!(
                    "Successor block {:?} not found in data flow results for block {:?}",
                    succ_id, block_id
                );
            }
        }

        if function.return_block() == Some(*block_id) {
            // Use return_block()
            // If this is a function return, we need to add all potential return arguments
            // to live out So we will have phi's automatically created for them at the right junctions.
            // We mark the live out as "FunctionOutput" to indicate that it is a return value.
            // This prevents from potential return values to appear as function inputs by propogating
            // to the entry point's live in.
            for (other_block_id, _) in function.blocks() {
                // Iterate view blocks
                let dfr = df_result.blocks.get(&other_block_id).unwrap(); // TODO: Handle panic
                for gen in dfr.gen.keys().filter(|k| k.is_local_or_parameter()) {
                    // Use MemoryReferenceInfo trait directly on MemoryReference
                    new_live_out
                        .entry(gen.clone())
                        .or_insert_with(HashSet::new)
                        .insert(OriginationPoint::FunctionOutput);
                }
            }
        }

        new_live_out
    }

    /// Pass 5: Updates CallSiteInfo based on actual usage of return values.
    /// Iterates through blocks, finds where return values ([R+n], n>0) are used before definition,
    /// identifies the unique function call that provided these values, and updates the
    /// `return_values_accessed` field in the `CallSiteInfo` of the calling block.
    fn update_call_site_info(&self, function: &Function, df_result: &mut DataFlowResult) {
        for block_id in function.all_block_ids() {
            // Find usages of positive stack offsets ([R+n]) that occur *before* any definition within this block.
            // These represent potential reads of function return values.
            let block_flow = df_result.blocks.get(&block_id).unwrap();
            let return_usages_in_block = df_result.blocks[block_id]
                .use_before_def
                .iter()
                .filter_map(|(mem_ref, instr_id)| {
                    mem_ref
                        .as_stack_relative()
                        .map(|offset| (offset, *instr_id))
                })
                .filter(|&(offset, _)| offset > 0) // Only positive offsets are return values
                .collect_vec(); // Collect as Vec<(i128, InstructionId)>

            // If we found any such usages...
            if !return_usages_in_block.is_empty() {
                // We expect these return values to come from exactly one preceding function call.
                // The `function_returns_in` set for this block should contain that single call origin.
                if block_flow.function_returns_in.len() != 1 {
                    // If this assertion fails, it means our function_returns_in propagation might be flawed,
                    // or the code structure is unexpected (e.g., merging paths after different function calls
                    // without clobbering return values).
                    panic!(
                        "Block {:?} uses return values but has {} function return sources: {:?}",
                        block_id,
                        block_flow.function_returns_in.len(),
                        block_flow.function_returns_in
                    );
                }
                let func_call_origin = block_flow.function_returns_in.iter().next().unwrap();
                let calling_block_id = func_call_origin.calling_block;

                // Now, get the DataFlowBlock for the *calling* block and update its CallSiteInfo.
                if let Some(calling_block_flow) = df_result.blocks.get_mut(&calling_block_id) {
                    if let Some(call_site_info) = calling_block_flow.call_site_info.as_mut() {
                        // Add the identified return value usages to the `return_values_accessed` map.
                        call_site_info
                            .return_values_accessed
                            .extend(return_usages_in_block.clone()); // Clone the vec to extend
                        debug!(
                            "Updated call site info for block {:?}: added return usages {:?}",
                            calling_block_id, return_usages_in_block
                        );
                    } else {
                        // This should not happen if initialization was correct.
                        panic!(
                            "Block {:?} identified as caller for {:?}, but has no CallSiteInfo",
                            calling_block_id, block_id
                        );
                    }
                } else {
                    // This indicates an inconsistency, maybe the calling block is not in the current function?
                    panic!(
                        "Calling block {:?} for return usages in {:?} not found in df_result",
                        calling_block_id, block_id
                    );
                }
            }
        }
    }
}
