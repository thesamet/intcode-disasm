use std::collections::{HashMap, HashSet, VecDeque};
use itertools::Itertools;
use log::debug;

use crate::disasm::v3::model::{Model, ControlFlowGraphComplete, DataFlowComplete, FunctionView, BlockView};
use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v3::control_flow::{NextKind, Block};
use crate::disasm::v3::common::{MemoryReference, Expression};
use crate::disasm::Error;

use super::result::DataFlowResult;
use super::block::{DataFlowBlock, Definition, OriginationPoint};

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
        let function_ids: Vec<FunctionId> = self.model.control_flow_graph_result()
            .functions.keys().cloned().collect();
        
        // Analyze each function
        for function_id in function_ids {
            self.analyze_function(function_id, &mut result);
        }
        
        // Return a new model with the updated state
        Ok(Model {
            image_scanner_result: self.model.image_scanner_result.clone(),
            control_flow_graph_result: self.model.control_flow_graph_result.clone(),
            data_flow_result: Some(result),
            ssa_result: None,
            function_call_analysis_result: None,
            marker: std::marker::PhantomData,
        })
    }
    
    /// Performs the main data flow analysis passes for a given function.
    fn analyze_function(&self, func_id: FunctionId, df_result: &mut DataFlowResult) {
        let function = self.model.function(&func_id);
        let block_ids = function.all_block_ids();

        // Pass 1: Initialize gen, use_before_def and function_returns_in for each block
        self.initialize_gen_use_func_in(&function, &block_ids, df_result);

        // Pass 2: compute function_returns_out and function_returns_in for all blocks (forward analysis)
        self.run_function_returns_analysis(&function, &block_ids, df_result);

        // Pass 3: Reaching Definitions (Forward Analysis)
        self.run_reaching_definitions_analysis(&function, df_result);

        // Pass 4: Liveness Analysis (Backward Analysis)
        self.run_liveness_analysis(&function, &block_ids, df_result);

        debug!("Data Flow Analysis passes complete for {}", func_id);
    }
    
    /// Pass 1: Initializes gen, use_before_def and function_returns_in sets for all blocks in the function.
    fn initialize_gen_use_func_in(
        &self,
        function: &FunctionView,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
    ) {
        for &block_id in block_ids {
            let block = function.block(&block_id);
            let block_flow = df_result.blocks.entry(block_id).or_insert_with(DataFlowBlock::new);

            let mut defined_in_block = HashSet::new();
            block_flow.writes_above_r = false;

            for instr in block.instructions() {
                // Calculate USE for this instruction
                for r in instr.collect_read_addresses().into_iter() {
                    if !defined_in_block.contains(r) {
                        block_flow.use_before_def.insert(r.clone(), instr.id());
                    }
                }

                // Calculate GEN for this instruction
                if let Some(write_operand) = instr.get_write_address() {
                    block_flow
                        .gen
                        .insert(write_operand.clone(), (instr.id(), write_operand.clone()));
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
        &self,
        function: &FunctionView,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            for &block_id in block_ids {
                // Function returns
                let new_func_in = self.calculate_function_returns_in(function, block_id, df_result);

                // Update block's IN set if changed
                let flow = df_result.blocks.get_mut(&block_id).unwrap();
                if new_func_in != flow.function_returns_in {
                    debug!("Block {:?}: FunctionReturnsIn changed", block_id);
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
        function: &FunctionView,
        block_id: BlockId,
        df_result: &DataFlowResult,
    ) -> HashSet<crate::disasm::v3::control_flow::FunctionCall<MemoryReference>> {
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
        function: &FunctionView,
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            for block_id in function.all_block_ids() {
                let block = function.block(&block_id);
                // Definitions
                let new_defs_in = self.calculate_defs_in(function, &block, df_result);

                // Update block's IN set if changed
                let flow = df_result.blocks.get_mut(&block_id).unwrap();
                if new_defs_in != flow.defs_in {
                    debug!("Block {:?}: DefsIn changed", block_id);
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
                        block_id: block_id,
                    });
                }

                // In we call a function at the end of the block, this block doesn't let [R+n]
                // defintions flow forward.
                if matches!(block.next(), NextKind::FunctionCall(_)) {
                    current_defs_out.retain(|d| !d.kind.is_outgoing_parameter());
                }

                // Update block's OUT set if changed
                if current_defs_out != flow.defs_out {
                    debug!("Block {:?}: DefsOut changed", block_id);
                    flow.defs_out = current_defs_out;
                    changed = true;
                }
            }
        }
    }

    /// Calculates the Defs-In set for a single block based on its predecessors.
    fn calculate_defs_in(
        &self,
        function: &FunctionView,
        block: &BlockView,
        df_result: &DataFlowResult,
    ) -> HashSet<Definition> {
        let mut new_defs_in = HashSet::new();

        for pred_kind in block.predecessors() {
            let pred_block_id = pred_kind.source_block_id();
            let pred_block = df_result.blocks.get(&pred_block_id);
            let pred_flow = pred_block.as_ref().unwrap();

            new_defs_in.extend(pred_flow.defs_out.iter().cloned());
        }

        if function.entry_block() == block.id() {
            // Create synthetic definitions for any potential input parameters
            // to this function. We take the union of all the use_before_def sets
            // for all blocks in the function, since it is a superset (which is still
            // smaller than all the reads).
            for &other_block_id in function.all_block_ids() {
                let other_flow = df_result.blocks.get(&other_block_id).unwrap();
                new_defs_in.extend(
                    other_flow
                        .use_before_def
                        .keys()
                        .filter(|k| (*k).is_local_or_parameter())
                        .map(|k| Definition {
                            source: OriginationPoint::FunctionInput,
                            kind: k.clone(),
                            block_id: block.id(),
                        }),
                )
            }
        }

        new_defs_in
    }
    
    /// Pass 4: Computes Liveness iteratively.
    fn run_liveness_analysis(
        &self,
        function: &FunctionView,
        block_ids: &[BlockId],
        df_result: &mut DataFlowResult,
    ) {
        let mut changed = true;
        while changed {
            changed = false;
            // Iterate backwards - often converges faster for backward analyses like liveness
            for &block_id in block_ids.iter().rev() {
                // Liveness
                let new_live_out = self.calculate_live_out(function, block_id, df_result);

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
                let defined_kinds: HashSet<MemoryReference> = block_flow.gen.keys().cloned().collect();
                let mut current_live_in = block_flow.live_out.clone();
                
                // add potential_function_call_params.
                if function.block(&block_id).next().as_function_call().is_some() {
                    for d in &block_flow.defs_in {
                        if d.kind.is_outgoing_parameter() {
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
                        .insert(OriginationPoint::Instruction(*v));
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
            }
        }
    }

    /// Calculates the Live-Out set for a single block based on its successors' Live-In sets.
    fn calculate_live_out(
        &self,
        function: &FunctionView,
        block_id: BlockId,
        df_result: &DataFlowResult, // Read-only access for successor IN sets
    ) -> HashMap<MemoryReference, HashSet<OriginationPoint>> {
        let block = function.block(&block_id);
        let mut new_live_out = HashMap::new();

        for succ_id in block.next().successors() {
            for (k, v) in &df_result.blocks.get(&succ_id).unwrap().live_in {
                new_live_out
                    .entry(k.clone())
                    .or_insert_with(HashSet::new)
                    .extend(v);
            }
        }

        if Some(block_id) == function.return_block() {
            // If this is a function return, we need to add all potential return arguments
            // to live out So we will have phi's automatically created for them at the right junctions.
            // We mark the live out as "FunctionOutput" to indicate that it is a return value.
            // This prevents from potential return values to appear as function inputs by propogating
            // to the entry point's live in.
            for block_id in function.all_block_ids() {
                let dfr = df_result.blocks.get(&block_id).unwrap();
                for gen in dfr.gen.keys().filter(|k| k.is_local_or_parameter()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::test_utils::init_logging;
    use crate::disasm::v3::model::Model;
    use crate::disasm::v3::control_flow::ControlFlowGraphBuilder;
    use crate::disasm::v3::image_scanner::ImageScanner;
    use pretty_assertions::assert_eq;

    // Helper to setup model, run CFG build, and then data flow analysis
    fn setup_and_analyze(binary: Vec<i128>) -> Model<DataFlowComplete> {
        init_logging();
        
        // Create model and run image scanner
        let model = Model::new();
        let model = model.with_image(binary);
        let model = ImageScanner::run(model).unwrap();
        
        // Build control flow graph
        let model = ControlFlowGraphBuilder::run(model).unwrap();
        
        // Run data flow analysis
        let model = DataFlowAnalyzer::run(model).unwrap();
        
        model
    }

    // TODO: Add more tests
    #[test]
    fn test_simple_sequence() {
        // This is a placeholder test - we'll need to implement proper tests
        // once we have the parser and other components migrated
        let binary = vec![
            // R += 2
            9, 2, 0,
            // [100] = 5
            1, 100, 5, 0,
            // [101] = [100]
            1, 101, 0, 100,
            // output [101]
            4, 101, 0,
            // R -= 2
            9, -2, 0,
            // goto [R]
            5, 1, 0, 0
        ];
        
        let model = setup_and_analyze(binary);
        
        // Basic verification that we have data flow results
        assert!(model.data_flow_result.is_some());
        
        // In a real test, we would check specific data flow properties
        // but for now we just verify the analysis runs without errors
    }
}
