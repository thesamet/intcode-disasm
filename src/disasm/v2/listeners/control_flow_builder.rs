// disasm/src/disasm/v2/listeners/control_flow_builder.rs
use std::collections::{HashMap, HashSet};

use crate::disasm::{
    low_ir::Span,
    v2::{
        control_flow::{Block, Condition, FunctionCall, NextKind, PredecessorKind},
        events::{self, FunctionCfgBuilt, ImageScannerComplete, ModelEventListener}, // + FunctionCfgBuilt
        instructions::Instruction,
        model::{BlockId, FunctionId, ProgramModel},
    },
};

use super::image_scanner::RecognizedFunction;

pub struct ControlFlowGraphBuilder {}

impl ControlFlowGraphBuilder {
    pub fn new() -> Self {
        ControlFlowGraphBuilder {}
    }

    fn build_cfg_for_function(
        &self,
        model: &mut ProgramModel,
        func_id: FunctionId,
        recognized_func: &super::image_scanner::RecognizedFunction,
        sender: &mut events::Sender,
    ) {
        // --- Pre-calculate all block boundaries ---
        let mut block_boundaries: HashSet<usize> = recognized_func.jump_targets.clone();
        block_boundaries.insert(recognized_func.span.start); // Function entry is a boundary

        let instruction_offsets: HashSet<usize> = recognized_func
            .instructions
            .iter()
            .map(|instr| instr.span.start)
            .collect();

        // Add boundaries *after* jump/halt instructions
        for instr in &recognized_func.instructions {
            if instr.is_jump() || instr.is_halt() {
                // Boundary is the start of the *next* instruction, if it exists within the function span
                if instr.span.end < recognized_func.span.end {
                    block_boundaries.insert(instr.span.end);
                }
            }
        }

        // Add boundaries for the return sequence block
        if let Some(return_span) = recognized_func.return_span {
            block_boundaries.insert(return_span.start); // Start of R-=N is a boundary
                                                        // End of goto [R] is also a boundary (start of the next block)
            if return_span.end < recognized_func.span.end {
                block_boundaries.insert(return_span.end);
            }
        }

        // Ensure boundaries are within the function's span
        block_boundaries
            .retain(|addr| *addr >= recognized_func.span.start && *addr < recognized_func.span.end);

        // --- Pass 1: Create Blocks based on pre-calculated boundaries ---
        let mut instructions_iter = recognized_func.instructions.iter().peekable();
        let mut current_block_start = recognized_func.span.start;
        let mut function_block_ids = Vec::new();

        while instructions_iter.peek().is_some() {
            // Handle potential gaps (though unlikely with contiguous code)
            while !instruction_offsets.contains(&current_block_start)
                && current_block_start < recognized_func.span.end
            {
                current_block_start += 1;
            }
            if current_block_start >= recognized_func.span.end {
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
                containing_function_id: func_id,
                span: Span::new(start_addr, current_block_end),
                instructions: current_block_instructions,
                predecessors: Vec::new(), // To be filled later
                next: NextKind::Unknown,  // To be filled now
            };
            model.add_block(block);

            // Prepare for the next block start address
            current_block_start = current_block_end; // Start next block right after the current one ends
            if current_block_start >= recognized_func.span.end {
                break; // Reached end
            }
        }

        // --- Pass 2: Determine NextKind and Predecessors ---
        let mut predecessors_map: HashMap<BlockId, Vec<PredecessorKind>> = HashMap::new();

        for block_id in &function_block_ids {
            let block = model.get_block(*block_id); // immutable borrow
            let last_instr = block
                .instructions
                .last()
                .expect("Created blocks cannot be empty");

            // Determine next kind, passing the block_id for context
            let next_kind =
                determine_next_kind(*block_id, last_instr, block.span.end, &recognized_func);

            // Store predecessors temporarily, checking if target blocks exist
            match &next_kind {
                NextKind::Follows(target_id) => {
                    assert!(model.has_block(*target_id));
                    predecessors_map
                        .entry(*target_id)
                        .or_default()
                        .push(PredecessorKind::FollowsFrom(*block_id));
                }
                NextKind::Goto(operand) => {
                    if let Some(target_addr) = operand.kind.get_immediate() {
                        let target_id = BlockId::from(target_addr as usize);
                        assert!(model.has_block(target_id));
                        predecessors_map
                            .entry(target_id)
                            .or_default()
                            .push(PredecessorKind::GotoFrom(*block_id));
                    } // Else: Unknown target, no predecessor added yet
                }
                NextKind::FunctionCall(call) => {
                    assert!(model.has_block(call.return_block));
                    predecessors_map
                        .entry(call.return_block)
                        .or_default()
                        .push(PredecessorKind::FunctionCallReturns(call.clone()));
                }
                NextKind::Condition(cond) => {
                    assert!(model.has_block(cond.target_block));
                    assert!(model.has_block(cond.follows_block));
                    predecessors_map
                        .entry(cond.target_block)
                        .or_default()
                        .push(PredecessorKind::ConditionalJump(*cond));
                    predecessors_map
                        .entry(cond.follows_block)
                        .or_default()
                        .push(PredecessorKind::ConditionalFollow(*cond));
                }
                NextKind::Return | NextKind::Halt | NextKind::Unknown => { /* No successors */ }
            }

            // Update the block in the model (mutable borrow needed here)
            model.get_block_mut(*block_id).next = next_kind;
        }

        // Apply predecessors
        for (block_id, preds) in predecessors_map {
            // block_id must exist since we created it and added it to function_block_ids
            model.get_block_mut(block_id).predecessors = preds;
        }

        // Update the Function object
        let return_block = if let Some(return_span) = recognized_func.return_span {
            // Find the block containing the return sequence start by iterating the collected block IDs
            let block_id = return_span.start.into();
            assert!(model.has_block(block_id));
            Some(block_id)
        } else {
            None
        };
        let function = model.get_function_mut(func_id); // Pass func_id directly
        function.return_block = return_block;
        function.blocks = function_block_ids; // Store the list of block IDs for this function

        sender.publish(FunctionCfgBuilt {
            function_id: func_id,
        });
    }
}

impl ModelEventListener for ControlFlowGraphBuilder {
    fn on_image_scanner_complete(
        &mut self,
        model: &mut ProgramModel,
        _event: ImageScannerComplete,
        sender: &mut events::Sender,
    ) {
        let image_scan_result = model.get_image_scanner_result().clone(); // Clone to avoid borrow issues

        for rec_func in &image_scan_result.recognized_functions {
            let func_id = FunctionId::from(rec_func.span.start);

            // Add basic function info first
            model.add_function(crate::disasm::v2::model::Function {
                function_id: func_id,
                entry_block: BlockId::from(rec_func.span.start),
                stack_size: rec_func.stack_size,
                blocks: Vec::new(), // Will be filled
                return_block: None, // Will be filled
            });

            self.build_cfg_for_function(model, func_id, rec_func, sender);
        }
    }
}

// Helper to determine NextKind based on the last instruction and context
fn determine_next_kind(
    bock_id: BlockId,
    last_instr: &Instruction,
    block_end_addr: usize,
    func: &RecognizedFunction,
) -> NextKind {
    if func.return_span.map(|r| r.end) == Some(block_end_addr) {
        NextKind::Return
    } else if let Some(call) = func
        .function_calls
        .iter()
        .find(|c| c.span.end == last_instr.span.end)
    {
        let Some(goto_addr) = last_instr.goto_address() else {
            panic!("Expected goto address");
        };
        NextKind::FunctionCall(FunctionCall {
            calling_block: BlockId::from(last_instr.span.start), // Placeholder, will be updated
            function_addr: call.target,
            return_block: BlockId::from(call.return_address),
        })
    } else if let Some(target_addr) = last_instr.goto_address() {
        NextKind::Goto(target_addr)
    } else if let Some(target_addr) = last_instr.conditional_jump_immediate_address() {
        let jump_if_true = last_instr.opcode == crate::disasm::v2::instructions::Opcode::JumpIfTrue;
        let condition_operand = last_instr.conditional_jump_condition().unwrap();
        NextKind::Condition(Condition {
            from_block: bock_id,
            condition_operand,
            jump_if_true,
            target_block: BlockId::from(target_addr as usize),
            follows_block: BlockId::from(block_end_addr), // Fallthrough address
        })
    } else if last_instr.is_conditional_jump() {
        panic!("Expected conditional jump to have an immediate target");
    } else if last_instr.is_halt() {
        NextKind::Halt
    } else {
        NextKind::Follows(BlockId::from(block_end_addr))
    }
}
