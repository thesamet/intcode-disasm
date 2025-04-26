use std::collections::{HashMap, HashSet};

use crate::disasm::v2::{
    control_flow::{Block, Condition, FunctionCall, NextKind, PredecessorKind},
    events::{
        self, ControlFlowAnalysisPhaseComplete, FunctionCfgBuilt, ImageScannerComplete,
        ModelEventListener,
    }, // + FunctionCfgBuilt
    instructions::{Instruction, Operand},
    model::{BlockId, FunctionId, ProgramModel},
    Span,
};

use super::image_scanner::RecognizedFunction;

pub struct ControlFlowGraphBuilder {}
/**
 * Builds the Control Flow Graph (CFG) for each function identified by the `ImageScanner`.
 *
 * This listener reacts to the `ImageScannerComplete` event. For each `RecognizedFunction`
 * provided by the scanner, it performs the following steps:
 *
 * 1.  **Identifies Block Boundaries:** It determines all addresses within the function's
 *     instruction stream that mark the beginning of a new basic block. A basic block
 *     is a sequence of instructions with exactly one entry point (the first instruction)
 *     and one exit point (the last instruction). Control flow only enters at the beginning
 *     and only leaves at the end (except for conditional jumps which have two possible exits).
 *
 *     Block boundaries are established at the following locations:
 *     *   **Function Entry:** The very first instruction of the function (`recognized_func.span.start`).
 *     *   **Jump Targets:** Any instruction that is the destination of a conditional or
 *         unconditional jump (`recognized_func.jump_targets`).
 *     *   **Instruction After Control Transfer:** The instruction immediately following:
 *         *   A conditional jump (`if [...] goto @target`).
 *         *   An unconditional jump (`goto @target`).
 *         *   A function call sequence (`[R]=@ret; goto @func`). The instruction at `@ret` starts a new block.
 *         *   The function return sequence (`R-=N; goto [R]`). The instruction *after* `goto [R]` (if any within the function span) would start a new block, although typically the return sequence is the end.
 *         *   A `halt` instruction. Code after `halt` starts a new block *only if* it's a jump target.
 *     *   **Return Sequence Start:** The `R -= N` instruction that begins the function's canonical return sequence, if present (`recognized_func.return_span.start`).
 *
 * 2.  **Creates Blocks:** It iterates through the function's instructions (`recognized_func.instructions`),
 *     grouping them into `Block` objects based on the identified boundaries. Each block stores
 *     its instruction list, its span, and its containing function ID. These blocks are added
 *     to the `ProgramModel.blocks` map.
 *
 * 3.  **Determines Control Flow Links:** For each created block, it analyzes the *last* instruction
 *     to determine how control flow exits:
 *     *   **Conditional Jump:** Sets `NextKind::Condition`, linking to both the target block (if jump taken) and the fallthrough block (if jump not taken).
 *     *   **Unconditional Jump:** Sets `NextKind::Goto`, linking only to the target block. There is *no* fallthrough from an unconditional jump.
 *     *   **Function Call:** Sets `NextKind::FunctionCall`, storing call details and linking to the return block.
 *     *   **Return Sequence:** Sets `NextKind::Return` if the block ends with the canonical `goto [R]`.
 *     *   **Halt:** Sets `NextKind::Halt`.
 *     *   **Other Instructions:** Sets `NextKind::Follows`, linking to the block starting at the next instruction's address.
 *
 * 4.  **Calculates Predecessors:** Based on the `NextKind` links established in the previous step, it
 *     populates the `predecessors` list for each block, indicating how control flow can arrive at that block.
 *
 * 5.  **Updates Function Metadata:** Updates the corresponding `Function` object in `ProgramModel.functions`
 *     with the list of `BlockId`s it contains and the ID of its specific `return_block`, if found.
 *
 * 6.  **Emits Events:** Publishes a `FunctionCfgBuilt` event for each function once its CFG is constructed.
 */

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

        block_boundaries.extend(recognized_func.halts.iter().map(|h| h.end));
        block_boundaries.extend(recognized_func.jump_targets.iter());
        block_boundaries.extend(recognized_func.jump_instructions.iter().map(|j| j.span.end));
        block_boundaries.extend(
            recognized_func
                .function_calls
                .iter()
                .map(|j| j.return_address),
        );

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
        let mut predecessors_map: HashMap<BlockId, Vec<PredecessorKind<Operand>>> = HashMap::new();

        for block_id in &function_block_ids {
            let block = model.get_block(*block_id); // immutable borrow
            let last_instr = block
                .instructions
                .last()
                .expect("Created blocks cannot be empty");

            // Determine next kind, passing the block_id for context
            let next_kind =
                determine_next_kind(*block_id, last_instr, block.span.end, recognized_func);

            // Store predecessors temporarily, checking if target blocks exist
            match &next_kind {
                NextKind::Follows(target_id) => {
                    assert!(model.has_block(*target_id));
                    predecessors_map
                        .entry(*target_id)
                        .or_default()
                        .push(PredecessorKind::FollowsFrom(*block_id));
                }
                NextKind::Goto(target_block_id) => {
                    assert!(model.has_block(*target_block_id));
                    predecessors_map
                        .entry(*target_block_id)
                        .or_default()
                        .push(PredecessorKind::GotoFrom(*block_id));
                }
                NextKind::FunctionCall(call) => {
                    assert!(
                        model.has_block(call.return_block),
                        "Return block {:?} does not exist",
                        call.return_block
                    );
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
                        .push(PredecessorKind::ConditionalJump(cond.clone()));
                    predecessors_map
                        .entry(cond.follows_block)
                        .or_default()
                        .push(PredecessorKind::ConditionalFollow(cond.clone()));
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
    ) -> Result<(), crate::disasm::Error> {
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
        sender.publish(ControlFlowAnalysisPhaseComplete {});
        Ok(())
    }
}

// Helper to determine NextKind based on the last instruction and context
fn determine_next_kind(
    block_id: BlockId,
    last_instr: &Instruction,
    block_end_addr: usize,
    func: &RecognizedFunction,
) -> NextKind<Operand> {
    if func.return_span.map(|r| r.end) == Some(block_end_addr) {
        NextKind::Return
    } else if let Some(call) = func
        .function_calls
        .iter()
        .find(|c| c.span.end == last_instr.span.end)
    {
        let Some(_) = last_instr.goto_address() else {
            panic!("Expected goto address");
        };
        NextKind::FunctionCall(FunctionCall::new(
            block_id,
            call.target,
            BlockId::from(call.return_address),
        ))
    } else if let Some(target_addr) = last_instr.immediate_goto() {
        NextKind::Goto(BlockId::from(target_addr))
    } else if last_instr.goto_address().is_some() {
        panic!(
            "Unexpected non-immediate goto at {}: {}",
            last_instr.span.start, last_instr
        );
    } else if let Some(target_addr) = last_instr.conditional_jump_immediate_address() {
        let jump_if_true =
            last_instr.opcode() == crate::disasm::v2::instructions::Opcode::JumpIfTrue;
        let condition_operand = last_instr.conditional_jump_condition().unwrap();
        NextKind::Condition(Condition {
            from_block: block_id,
            condition_operand,
            jump_if_true,
            target_block: BlockId::from(target_addr),
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

#[cfg(test)]
mod tests {
    use crate::disasm::parser;
    use crate::disasm::v2::{
        dispatching::EventPublisher,
        events::Event,
        listeners::{
            control_flow_graph_builder::ControlFlowGraphBuilder, image_scanner::ImageScanner,
        },
    };
    use itertools::Itertools;

    use super::*;

    // Helper function to run the pipeline up to CFG building
    fn setup_and_build_cfg(assembly_code: &str) -> ProgramModel {
        let binary = parser::compile(assembly_code);
        let mut model = ProgramModel::new();
        let mut publisher = EventPublisher::<Event, ProgramModel>::new();

        // Register listeners
        publisher.add_listener(Box::new(ImageScanner {}));
        publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));

        // Run the pipeline
        model.load_image(&binary, &mut publisher);
        publisher.process_events(&mut model).unwrap(); // ImageScanner runs

        model
    }

    #[test]
    fn test_simple_return_function() {
        let model = setup_and_build_cfg(
            r#"
            ; Offset 0
            R += 5
            ; Offset 2
            R -= 5
            ; Offset 4
            goto [R]
            "#,
        );

        let func_id = FunctionId::from(0);
        let func = model.get_function(func_id);
        assert_eq!(func.stack_size, 5);
        assert_eq!(func.entry_block, BlockId::from(0));
        assert_eq!(func.blocks.len(), 2);
        assert_eq!(func.return_block, Some(BlockId::from(2))); // The whole function is the return block

        let block0 = model.get_block(BlockId::from(0));
        assert_eq!(block0.id, BlockId::from(0));
        assert_eq!(block0.containing_function_id, func_id);
        assert_eq!(block0.instructions.len(), 1);
        assert_eq!(block0.span, Span::new(0, 2));
        assert_eq!(block0.next, NextKind::Follows(BlockId::from(2)));

        let block1 = model.get_block(BlockId::from(2));
        assert_eq!(block1.id, BlockId::from(2));
        assert_eq!(block1.containing_function_id, func_id);
        assert_eq!(block1.instructions.len(), 2);
        assert_eq!(block1.span, Span::new(2, 7));
        assert_eq!(block1.next, NextKind::Return);
        assert_eq!(
            *block1.predecessors.iter().exactly_one().unwrap(),
            PredecessorKind::FollowsFrom(BlockId::from(0))
        );
    }

    #[test]
    fn test_fallthrough_function() {
        let model = setup_and_build_cfg(
            r#"
            ; Offset 0
            R += 5
            ; Offset 2
            [R+1] = 10 ; Block 1
            ; Offset 6
            [R+2] = 20
            ; Offset 10
            R -= 5;   ; Block 2 (starts here)
            ; Offset 12
            goto [R]
            "#,
        );

        let func_id = FunctionId::from(0);
        let func = model.get_function(func_id);
        assert_eq!(func.stack_size, 5);
        assert_eq!(func.entry_block, BlockId::from(0));
        assert_eq!(func.blocks.len(), 2);
        assert_eq!(func.blocks, vec![BlockId::from(0), BlockId::from(10)]);
        assert_eq!(func.return_block, Some(BlockId::from(10)));

        let block0 = model.get_block(BlockId::from(0));
        assert_eq!(block0.instructions.len(), 3); // R+=5, [R+1]=10, [R+2]=20
        assert_eq!(block0.span, Span::new(0, 10));
        assert_eq!(block0.next, NextKind::Follows(BlockId::from(10)));
        assert!(block0.predecessors.is_empty());

        let block6 = model.get_block(BlockId::from(10));
        assert_eq!(block6.instructions.len(), 2); // R-=5, goto [R]
        assert_eq!(block6.span, Span::new(10, 15));
        assert_eq!(block6.next, NextKind::Return);
        assert_eq!(block6.predecessors.len(), 1);
        assert_eq!(
            block6.predecessors[0],
            PredecessorKind::FollowsFrom(BlockId::from(0))
        );
    }

    #[test]
    fn test_unconditional_jump_function() {
        let model = setup_and_build_cfg(
            r#"
            ; Offset 0   ; Block 0
            R += 5
            ; Offset 2
            goto @target
            ; Offset 5: Unreachable code (should not be part of function/blocks)
            halt;        ; Unnumbered.
            ; Offset 6: Target block
            target:
            [R+1] = 30 ; Block 2 (starts here)
            ; Offset 10
            R -= 5     ; Block 3 (starts here)
            ; Offset 12
            goto [R]
            "#,
        );

        let func_id = FunctionId::from(0);
        let func = model.get_function(func_id);
        assert_eq!(func.stack_size, 5);
        assert_eq!(func.entry_block, BlockId::from(0));
        assert_eq!(func.blocks.len(), 3);
        assert_eq!(
            func.blocks,
            vec![BlockId::from(0), BlockId::from(6), BlockId::from(10)]
        );
        assert_eq!(func.return_block, Some(BlockId::from(10)));

        let block0 = model.get_block(BlockId::from(0));
        assert_eq!(block0.instructions.len(), 2);
        assert_eq!(block0.span, Span::new(0, 5));
        assert!(matches!(block0.next, NextKind::Goto(address) if address == BlockId::from(6)));
        assert!(block0.predecessors.is_empty());

        let block6 = model.get_block(BlockId::from(6));
        assert_eq!(block6.instructions.len(), 1); // [R+1]=30
        assert_eq!(block6.span, Span::new(6, 10));
        assert_eq!(block6.next, NextKind::Follows(BlockId::from(10)));
        assert_eq!(block6.predecessors.len(), 1);
        assert_eq!(
            block6.predecessors[0],
            PredecessorKind::GotoFrom(BlockId::from(0))
        );

        let block10 = model.get_block(BlockId::from(10));
        assert_eq!(block10.instructions.len(), 2); // R-=5, goto [R]
        assert_eq!(block10.span, Span::new(10, 15));
        assert_eq!(block10.next, NextKind::Return);
        assert_eq!(block10.predecessors.len(), 1);
        assert_eq!(
            block10.predecessors[0],
            PredecessorKind::FollowsFrom(BlockId::from(6))
        );
    }

    #[test]
    fn test_conditional_jump_function() {
        let model = setup_and_build_cfg(
            r#"
            ; Offset 0
            R += 5
            ; Offset 2
            if [R+1] goto @true_branch ; Block 0 (entry)
            ; Offset 5
            ; False branch (Block 5)
            [R+2] = 100
            ; Offset 9
            goto @merge
            ; Offset 12
            ; True branch (Block 12)
            true_branch:
            [R+3] = 200
            ; Offset 16
            ; Merge point (Block 16)
            merge:
            R -= 5
            ; Offset 18
            goto [R]
            "#,
        );

        let func_id = FunctionId::from(0);
        let func = model.get_function(func_id);
        assert_eq!(func.stack_size, 5);
        assert_eq!(func.blocks.len(), 4);
        assert_eq!(
            func.blocks,
            vec![
                BlockId::from(0),
                BlockId::from(5),
                BlockId::from(12),
                BlockId::from(16)
            ]
        );
        assert_eq!(func.return_block, Some(BlockId::from(16)));

        // Block 0 (Entry)
        let block0 = model.get_block(BlockId::from(0));
        assert_eq!(block0.instructions.len(), 2); // R+=5, if [R+1] goto @true_branch
        assert_eq!(block0.span, Span::new(0, 5));
        if let NextKind::Condition(ref cond) = block0.next {
            assert_eq!(cond.target_block, BlockId::from(12));
            assert_eq!(cond.follows_block, BlockId::from(5));
            assert!(cond.jump_if_true);
        } else {
            panic!("Expected NextKind::Condition");
        }
        assert!(block0.predecessors.is_empty());

        // Block 5 (False branch)
        let block5 = model.get_block(BlockId::from(5));
        assert_eq!(block5.instructions.len(), 2); // [R+2]=100, goto @merge
        assert_eq!(block5.span, Span::new(5, 12));
        assert!(matches!(block5.next, NextKind::Goto(b) if b == BlockId::from(16)));
        assert_eq!(block5.predecessors.len(), 1);
        if let PredecessorKind::ConditionalFollow(ref cond) = block5.predecessors[0] {
            assert_eq!(cond.from_block, BlockId::from(0));
        } else {
            panic!("Expected PredecessorKind::ConditionalFollow");
        }

        // Block 12 (True branch)
        let block12 = model.get_block(BlockId::from(12));
        assert_eq!(block12.instructions.len(), 1); // [R+3]=200
        assert_eq!(block12.span, Span::new(12, 16));
        assert_eq!(block12.next, NextKind::Follows(BlockId::from(16))); // Falls through to merge
        assert_eq!(block12.predecessors.len(), 1);
        if let PredecessorKind::ConditionalJump(ref cond) = block12.predecessors[0] {
            assert_eq!(cond.from_block, BlockId::from(0));
        } else {
            panic!("Expected PredecessorKind::ConditionalJump");
        }

        // Block 16 (Merge & Return)
        let block16 = model.get_block(BlockId::from(16));
        assert_eq!(block16.instructions.len(), 2); // R-=5, goto [R]
        assert_eq!(block16.span, Span::new(16, 21));
        assert_eq!(block16.next, NextKind::Return);
        assert_eq!(block16.predecessors.len(), 2);
        assert!(block16
            .predecessors
            .contains(&PredecessorKind::GotoFrom(BlockId::from(5))));
        assert!(block16
            .predecessors
            .contains(&PredecessorKind::FollowsFrom(BlockId::from(12))));
    }

    #[test]
    fn test_loop_function() {
        let model = setup_and_build_cfg(
            r#"
            ; Offset 0
            R += 5
            ; Offset 2
            loop_start:
            [R+1] = [R+1] + -1 ; Block 2 (Loop body)
            ; Offset 6
            if [R+1] goto @loop_start ; Block 6 (Loop condition)
            ; Offset 9
            R -= 5 ;          ; Block 9 (Exit)
            ; Offset 11
            goto [R]
            "#,
        );

        let func_id = FunctionId::from(0);
        let func = model.get_function(func_id);
        assert_eq!(func.blocks.len(), 3);
        assert_eq!(
            func.blocks,
            vec![BlockId::from(0), BlockId::from(2), BlockId::from(9)]
        );
        assert_eq!(func.return_block, Some(BlockId::from(9)));

        // Block 0 (Setup)
        let block0 = model.get_block(BlockId::from(0));
        assert_eq!(block0.instructions.len(), 1); // R+=5
        assert_eq!(block0.span, Span::new(0, 2));
        assert_eq!(block0.next, NextKind::Follows(BlockId::from(2)));
        assert!(block0.predecessors.is_empty());

        // Block 2 (Loop Body)
        let block2 = model.get_block(BlockId::from(2));
        assert_eq!(block2.instructions.len(), 2); // [R+1] = [R+1] - 1
        assert_eq!(block2.span, Span::new(2, 9));
        let NextKind::Condition(Condition {
            target_block,
            follows_block,
            ..
        }) = block2.next
        else {
            panic!("Expected condition");
        };
        assert_eq!(target_block, BlockId::from(2));
        assert_eq!(follows_block, BlockId::from(9));
        assert!(block2
            .predecessors
            .contains(&PredecessorKind::FollowsFrom(BlockId::from(0))));
        // Block 6 is just the jump, so the loop jump goes FROM 6 TO 2.
        // Block 2 predecessor should also include the loop back edge from Block 6.
        assert!(block2
            .predecessors
            .contains(&PredecessorKind::ConditionalJump(Condition {
                from_block: BlockId::from(2),
                condition_operand: block2
                    .instructions
                    .last()
                    .unwrap()
                    .conditional_jump_condition()
                    .unwrap(), // Check this assumption
                jump_if_true: true,
                target_block: BlockId::from(2),
                follows_block: BlockId::from(9)
            }))); // TODO: Need to get condition operand correctly

        // Block 9 (Exit & Return)
        let block9 = model.get_block(BlockId::from(9));
        assert_eq!(block9.instructions.len(), 2); // The if, R-=5, goto [R]
        assert_eq!(block9.span, Span::new(9, 14));
        assert_eq!(
            func.blocks,
            vec![BlockId::from(0), BlockId::from(2), BlockId::from(9)]
        ); // Block 0, Block 2 (body), Block 6 (if), Block 9 (return)
    }

    #[test]
    fn test_function_call() {
        let model = setup_and_build_cfg(
            r#"
            ; Main Function (Offset 0)
            main:
            R += 5
            ; Offset 2
            [R+1] = 111 ; Arg 1
            ; Offset 6
            [R+2] = 222 ; Arg 2
            ; Offset 10
            [R] = @main_ret ; Set return address
            ; Offset 14
            goto @callee ; Call
            ; Offset 17
            main_ret:
            output [R+1] ; Use return value
            ; Offset 19
            R -= 5
            ; Offset 21
            goto [R]

            ; Callee Function (Offset 24)
            callee:
            R += 4 ; Stack frame for locals + args
            ; Offset 26
            [R-1] = [R-5] ; Access arg 1 ([R+1] from caller -> [R-5] in callee)
            ; Offset 30
            [R-2] = [R-6] ; Access arg 2 ([R+2] from caller -> [R-6] in callee)
            ; Offset 34
            [R-3] = [R-1] + [R-2] ; Local calc
            ; Offset 38
            [R-5] = [R-3] ; Put result in return slot 1 ([R-5] in callee -> [R+1] in caller)
            ; Offset 42
            R -= 4
            ; Offset 44
            goto [R]
            "#,
        );

        let main_id = FunctionId::from(0);
        let callee_id = FunctionId::from(24);

        // Check Main Function
        let main_func = model.get_function(main_id);
        assert_eq!(main_func.stack_size, 5);
        assert_eq!(main_func.blocks.len(), 3); // Entry+Args+Call, Output, Return
        assert_eq!(
            main_func.blocks,
            vec![BlockId::from(0), BlockId::from(17), BlockId::from(19)]
        );
        assert_eq!(main_func.return_block, Some(BlockId::from(19)));

        let block0 = model.get_block(BlockId::from(0)); // The call block
        assert_eq!(block0.instructions.len(), 5);
        assert_eq!(block0.span, Span::new(0, 17));
        let NextKind::FunctionCall(call) = &block0.next else {
            panic!("block0.next mismatch: {:?}", block0.next);
        };

        assert_eq!(call.return_block, BlockId::from(17));
        assert_eq!(call.function_addr.kind.get_immediate().unwrap(), 24);
        assert_eq!(call.calling_block, BlockId::from(0));

        // Check Callee Function (Block 24)
        let callee_func = model.get_function(callee_id);
        assert_eq!(callee_func.stack_size, 4);
        assert_eq!(callee_func.blocks.len(), 2);
        assert_eq!(callee_func.return_block, Some(BlockId::from(42)));

        // Check Return Block Predecessor in Main
        let block17 = model.get_block(BlockId::from(17)); // The return block in main
        assert_eq!(block17.predecessors.len(), 1);
        assert_eq!(
            block17.predecessors[0],
            PredecessorKind::FunctionCallReturns(call.clone())
        );

        // Check Call Block Predecessor in Callee
        let block24 = model.get_block(BlockId::from(24)); // The call block in callee
        assert_eq!(block24.predecessors.len(), 0);
    }

    #[test]
    fn test_halt_function() {
        let model = setup_and_build_cfg(
            r#"
            R += 2
            halt
            "#,
        );
        let func_id = FunctionId::from(0);
        let func = model.get_function(func_id);
        assert_eq!(func.stack_size, 2);
        assert_eq!(func.blocks.len(), 1);
        assert!(func.return_block.is_none());

        let block0 = model.get_block(BlockId::from(0));
        assert_eq!(block0.instructions.len(), 2);
        assert_eq!(block0.next, NextKind::Halt);
    }
}
