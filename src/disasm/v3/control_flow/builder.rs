use itertools::Itertools;
use log::{debug, info, trace};
use std::collections::{HashMap, HashSet};

// Use v3 types consistently
use crate::disasm::v3::common::{FunctionCall, Span}; // Keep common types
use crate::disasm::v3::control_flow::block::{Condition, NextKind, PredecessorKind}; // v3 NextKind, PredecessorKind
use crate::disasm::v3::lir::{
    Expression,
    Instruction,
    InstructionNode,
    MemoryReference, // Use LIR types
};
use crate::disasm::Error;

use super::block::Block;
use super::function::Function;
use super::result::ControlFlowGraphResult;
// Removed duplicate: use crate::disasm::v3::common::Span;
use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v3::image_scanner::RecognizedFunction;
use crate::disasm::v3::model::{ControlFlowGraphComplete, ImageScannerComplete, Model};

/// Builds the control flow graph from the image scanner results
#[derive(Debug, Clone)]
pub struct ControlFlowGraphBuilder {
    blocks: HashMap<BlockId, Block>,
    functions: HashMap<FunctionId, Function>,
}

impl ControlFlowGraphBuilder {
    pub fn new() -> Self {
        Self {
            blocks: HashMap::new(),
            functions: HashMap::new(),
        }
    }

    pub fn run(
        model: Model<ImageScannerComplete>,
    ) -> Result<Model<ControlFlowGraphComplete>, Error> {
        let mut builder = Self::new();
        builder.build(model)
    }

    fn build(
        &mut self,
        model: Model<ImageScannerComplete>,
    ) -> Result<Model<ControlFlowGraphComplete>, Error> {
        debug!("Building control flow graph...");

        // Process each function from the image scanner result
        let scanner_result = model.image_scanner_result().clone();

        for function_id in &scanner_result.recognized_functions {
            let function_details = &scanner_result.function_details[function_id];
            self.process_function(*function_id, function_details, &scanner_result)?;
        }

        info!(
            "Control flow graph built with {} functions and {} blocks",
            self.functions.len(),
            self.blocks.len()
        );

        // Create the control flow graph result
        let result = ControlFlowGraphResult::new(self.functions.clone());

        // Return a new model with the updated state
        let final_model = model.with_control_flow_graph_result(result);
        Ok(final_model)
    }

    fn process_function(
        &mut self,
        function_id: FunctionId,
        function_details: &RecognizedFunction,
        scanner_result: &crate::disasm::v3::image_scanner::result::ImageScannerResult,
    ) -> Result<(), Error> {
        debug!("Processing function {}", function_id);

        // --- Pre-calculate all block boundaries ---
        let mut block_boundaries: HashSet<usize> = function_details.jump_targets.clone();
        block_boundaries.insert(function_details.span.start); // Function entry is a boundary

        let instruction_offsets: HashSet<usize> = function_details
            .instructions
            .iter()
            .map(|instr| instr.span.start)
            .collect();

        block_boundaries.extend(function_details.halts.iter().map(|h| h.end));
        block_boundaries.extend(function_details.jump_targets.iter());
        block_boundaries.extend(
            function_details
                .jump_instructions
                .iter()
                .map(|j| j.span.end),
        );
        block_boundaries.extend(
            function_details
                .function_calls
                .iter()
                .map(|j| j.return_address),
        );

        // Add boundaries for the return sequence block
        if let Some(return_span) = function_details.return_span {
            block_boundaries.insert(return_span.start); // Start of R-=N is a boundary
                                                        // End of goto [R] is also a boundary (start of the next block)
            if return_span.end < function_details.span.end {
                block_boundaries.insert(return_span.end);
            }
        }

        // Ensure boundaries are within the function's span
        block_boundaries.retain(|addr| {
            *addr >= function_details.span.start && *addr < function_details.span.end
        });

        // --- Pass 1: Create Blocks based on pre-calculated boundaries ---
        let mut instructions_iter = function_details.instructions.iter().peekable();
        let mut current_block_start = function_details.span.start;
        let mut function_block_ids = Vec::new();

        while instructions_iter.peek().is_some() {
            // Handle potential gaps (though unlikely with contiguous code)
            while !instruction_offsets.contains(&current_block_start)
                && current_block_start < function_details.span.end
            {
                current_block_start += 1;
            }
            if current_block_start >= function_details.span.end {
                break;
            }

            let start_addr = current_block_start;
            let mut current_block_instructions = Vec::new();
            let mut current_block_end = start_addr;

            // Consume instructions until the next boundary or end of function
            while let Some(current_instr_peek) = instructions_iter.peek() {
                // Boundary check: Stop *before* consuming if the current instruction starts a new block (and it's not the first of *this* block)
                if current_instr_peek.span.start != start_addr
                    && block_boundaries.contains(&current_instr_peek.span.start)
                {
                    break;
                }

                // Consume the instruction
                let consumed_instr = instructions_iter.next().unwrap(); // Safe due to peek
                current_block_end = consumed_instr.span.end;
                current_block_instructions.push(consumed_instr.clone());

                // Stop *after* consuming the instruction if it was the last one before a boundary start
                // This ensures jumps/halts/returns are the last instruction in their block
                if block_boundaries.contains(&current_block_end) {
                    break;
                }

                // Also stop if it's the last instruction overall
                if instructions_iter.peek().is_none() {
                    break;
                }
            }

            // Create and store the block
            let block_id = BlockId::from(start_addr);
            function_block_ids.push(block_id);
            let block = Block {
                id: block_id,
                containing_function_id: function_id,
                span: Span::new(start_addr, current_block_end),
                // native_instructions: current_block_instructions.clone(), // Removed - unresolved
                // Assuming convert_block now returns Vec<InstructionNode<v3::lir::MemoryReference>>
                low_instructions: InstructionNode::convert_block(
                    current_block_instructions.clone(),
                ), // Clone to satisfy IntoIterator
                next: NextKind::Unknown,  // Specify type
                predecessors: Vec::new(), // Will use v3 MemoryReference
            };
            self.blocks.insert(block_id, block);

            // Prepare for the next block start address
            current_block_start = current_block_end; // Start next block right after the current one ends
            if current_block_start >= function_details.span.end {
                break; // Reached end
            }
        }

        // --- Pass 2: Determine NextKind and Predecessors ---
        let mut predecessors_map: HashMap<BlockId, Vec<PredecessorKind<MemoryReference>>> =
            HashMap::new();

        for block_id in &function_block_ids {
            let block = self.blocks.get(block_id).unwrap(); // immutable borrow
            let next_kind = if block.low_instructions.is_empty() {
                assert_eq!(
                    BlockId::from(function_details.span.start),
                    *block_id,
                    "Only the entry block can be empty"
                );
                // It only had the SET R+=<Stack> command, so follower is block start+2.
                let next_block = BlockId::from(function_details.span.start + 2);
                assert!(
                    self.blocks.contains_key(&next_block),
                    "Block {} not found",
                    next_block
                );
                NextKind::Follows(BlockId::from(next_block))
            } else if let Some(last_instr) = block.low_instructions.last() {
                self.determine_next_kind(*block_id, last_instr, block.span.end)
            } else {
                NextKind::Unknown
            };

            // Store predecessors temporarily, checking if target blocks exist
            match &next_kind {
                NextKind::Follows(target_id) => {
                    assert!(
                        self.blocks.contains_key(target_id), // Pass &BlockId
                        "Block {} not found",
                        target_id
                    );
                    predecessors_map
                        .entry(*target_id) // Keep as value for entry
                        .or_default()
                        .push(PredecessorKind::FollowsFrom(*block_id));
                }
                NextKind::Goto(target_block_id) => {
                    assert!(
                        self.blocks.contains_key(target_block_id), // Pass &BlockId
                        "Block {} not found",
                        target_block_id
                    );
                    predecessors_map
                        .entry(*target_block_id) // Keep as value for entry
                        .or_default()
                        .push(PredecessorKind::GotoFrom(*block_id));
                }
                NextKind::FunctionCall(call) => {
                    assert!(
                        self.blocks.contains_key(&call.return_block),
                        "Return block {:?} does not exist",
                        call.return_block
                    );
                    predecessors_map
                        .entry(call.return_block)
                        .or_default()
                        .push(PredecessorKind::FunctionCallReturns(call.clone()));
                }
                NextKind::Condition(condition) => {
                    let true_branch = condition.target_block;
                    let false_branch = condition.follows_block;
                    assert!(
                        self.blocks.contains_key(&true_branch), // Pass &BlockId
                        "Block {} not found",
                        true_branch
                    );
                    assert!(
                        self.blocks.contains_key(&false_branch), // Pass &BlockId
                        "Block {} not found",
                        false_branch
                    );
                    predecessors_map.entry(true_branch).or_default().push(
                        // Keep as value for entry
                        PredecessorKind::ConditionalJump(Condition {
                            from_block: *block_id,
                            condition_operand: condition.condition_operand.clone(),
                            jump_if_true: true,
                            target_block: true_branch,
                            follows_block: false_branch,
                        }),
                    );
                    predecessors_map.entry(false_branch).or_default().push(
                        // Keep as value for entry
                        PredecessorKind::ConditionalFollow(Condition {
                            from_block: *block_id,
                            condition_operand: condition.condition_operand.clone(),
                            jump_if_true: true,
                            target_block: true_branch,
                            follows_block: false_branch,
                        }),
                    );
                }
                NextKind::Return | NextKind::Halt | NextKind::Unknown => { /* No successors */ }
            };

            // Update the block's next kind
            let block = self.blocks.get_mut(block_id).unwrap();
            block.next = next_kind;
        }

        // Apply predecessors
        for (block_id, preds) in predecessors_map {
            if let Some(block) = self.blocks.get_mut(&block_id) {
                block.predecessors = preds;
            }
        }

        // Update the Function object
        let return_block = if let Some(return_span) = function_details.return_span {
            // Find the block containing the return sequence start
            let block_id = BlockId::from(return_span.start);
            assert!(
                self.blocks.contains_key(&block_id),
                "Return block {} not found",
                block_id
            );
            Some(block_id)
        } else {
            None
        };

        // Create the function
        let function = Function::new(
            function_id,
            BlockId::from(function_details.span.start),
            function_details.stack_size,
            return_block,
            function_block_ids
                .iter()
                .map(|id| (*id, self.blocks[id].clone()))
                .collect(),
        );

        // Add the function to our collection
        self.functions.insert(function_id, function);

        Ok(())
    }

    fn determine_next_kind(
        &self,
        block_id: BlockId,
        last_instr: &InstructionNode<MemoryReference>,
        block_end_addr: usize,
    ) -> NextKind<MemoryReference> {
        match &last_instr.kind {
            Instruction::Halt => NextKind::Halt,
            Instruction::Goto(target_addr) => NextKind::Goto(BlockId::from(*target_addr)),
            Instruction::Call { addr, return_to } => NextKind::FunctionCall(FunctionCall::new(
                block_id,
                addr.clone(),
                BlockId::from(*return_to),
            )),
            Instruction::Return => NextKind::Return,
            Instruction::If {
                cond,
                then_addr,
                else_addr,
            } => NextKind::Condition(Condition {
                from_block: BlockId::from(block_id),
                condition_operand: cond.clone(),
                jump_if_true: true,
                target_block: BlockId::from(*then_addr),
                follows_block: BlockId::from(*else_addr),
            }),
            _ => {
                // Find the next block by address
                let next_block_id = BlockId::from(block_end_addr);
                if self.blocks.contains_key(&next_block_id) {
                    NextKind::Follows(BlockId::from(block_end_addr))
                } else {
                    // If there's no block at the exact end address, this might be the end of the function
                    NextKind::Halt
                }
            }
        }
    }
}
