#[cfg(test)]
mod tests {
    use super::super::{ControlFlowGraphBuilder, Function};
    use crate::disasm::test_utils::init_logging;
    use crate::disasm::v2::control_flow::{NextKind, PredecessorKind};
    use crate::disasm::v3::common::Span;
    use crate::disasm::v3::control_flow::ControlFlowGraphResult;
    use crate::disasm::v3::id_types::{BlockId, FunctionId};
    use crate::disasm::v3::image_scanner::ImageScanner;
    use crate::disasm::v3::model::{ControlFlowGraphComplete, InitialState, Model};
    use crate::disasm::{parser, v3};
    use itertools::Itertools;

    fn parse_and_build_cfg(code: &str) -> v3::model::Model<ControlFlowGraphComplete> {
        let binary = parser::compile(code);
        let model = Model::from_binary(binary);
        let model = ImageScanner::run(model).expect("Image scanner failed");
        let model = ControlFlowGraphBuilder::run(model).expect("CFG builder failed");
        model
    }
    #[test]
    fn test_simple_return_function() {
        init_logging();

        let model = parse_and_build_cfg(
            r#"
            ; Offset 0
            R += 5
            ; Offset 2
            R -= 5
            ; Offset 4
            goto [R]
            "#,
        );

        let func_id = model.functions().map(|(id, _)| id).next().unwrap();
        let func = model.function(&func_id);
        assert_eq!(func.stack_size(), 5);
        assert_eq!(func.entry_block(), BlockId::from(0));
        assert_eq!(func.blocks().count(), 2);
        assert_eq!(func.return_block(), Some(BlockId::from(2))); // The return block starts at offset 2

        let block0 = func.block(&BlockId::from(0));
        assert_eq!(block0.block_id(), BlockId::from(0));
        assert_eq!(block0.containing_function_id(), func_id);
        assert_eq!(block0.low_instructions().len(), 0); // Entry block has no low instructions (just R+=5)
        assert_eq!(block0.span(), &Span::new(0, 2));
        assert_eq!(block0.next(), &NextKind::Follows(BlockId::from(2)));

        let block1 = func.block(&BlockId::from(2));
        assert_eq!(block1.block_id(), BlockId::from(2));
        assert_eq!(block1.containing_function_id(), func_id);
        assert_eq!(block1.low_instructions().len(), 1); // Just the Return instruction
        assert_eq!(block1.span(), &Span::new(2, 7));
        assert_eq!(block1.next(), &NextKind::Return);
        assert_eq!(
            block1.predecessors().len(),
            1,
            "Return block should have exactly one predecessor"
        );
        assert!(matches!(
            block1.predecessors()[0],
            PredecessorKind::FollowsFrom(id) if id == BlockId::from(0)
        ));
    }

    #[test]
    fn test_fallthrough_function() {
        init_logging();

        let model = parse_and_build_cfg(
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

        let func_id = model.functions().map(|(id, _)| id).next().unwrap();
        let func = model.function(&func_id);
        assert_eq!(func.stack_size(), 5);
        assert_eq!(func.entry_block(), BlockId::from(0));
        assert_eq!(func.blocks().count(), 2);
        assert_eq!(func.return_block(), Some(BlockId::from(10)));

        let block0 = func.block(&BlockId::from(0));
        assert_eq!(block0.low_instructions().len(), 2); // [R+1]=10, [R+2]=20 (excluding R+=5)
        assert_eq!(block0.span(), &Span::new(0, 10));
        assert_eq!(block0.next(), &NextKind::Follows(BlockId::from(10)));
        assert!(block0.predecessors().is_empty());

        let block10 = func.block(&BlockId::from(10));
        assert_eq!(block10.low_instructions().len(), 1); // Only Return instruction
        assert_eq!(block10.span(), &Span::new(10, 15));
        assert_eq!(block10.next(), &NextKind::Return);
        assert_eq!(block10.predecessors().len(), 1);
        assert_eq!(
            block10.predecessors()[0],
            PredecessorKind::FollowsFrom(BlockId::from(0))
        );
    }

    #[test]
    fn test_unconditional_jump_function() {
        init_logging();

        let model = parse_and_build_cfg(
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

        let func_id = model.functions().map(|(id, _)| id).next().unwrap();
        let func = model.function(&func_id);
        assert_eq!(func.stack_size(), 5);
        assert_eq!(func.entry_block(), BlockId::from(0));
        assert_eq!(func.blocks().count(), 3);
        assert_eq!(func.return_block(), Some(BlockId::from(10)));

        let block0 = func.block(&BlockId::from(0));
        assert_eq!(block0.low_instructions().len(), 1); // goto @target
        assert_eq!(block0.span(), &Span::new(0, 5));
        assert!(matches!(block0.next(), NextKind::Goto(address) if *address == BlockId::from(6)));
        assert!(block0.predecessors().is_empty());

        let block6 = func.block(&BlockId::from(6));
        assert_eq!(block6.low_instructions().len(), 1); // [R+1]=30
        assert_eq!(block6.span(), &Span::new(6, 10));
        assert_eq!(block6.next(), &NextKind::Follows(BlockId::from(10)));
        assert_eq!(block6.predecessors().len(), 1);
        assert_eq!(
            block6.predecessors()[0],
            PredecessorKind::GotoFrom(BlockId::from(0))
        );

        let block10 = func.block(&BlockId::from(10));
        assert_eq!(block10.low_instructions().len(), 1); // Just Return
        assert_eq!(block10.span(), &Span::new(10, 15));
        assert_eq!(block10.next(), &NextKind::Return);
        assert_eq!(block10.predecessors().len(), 1);
        assert_eq!(
            block10.predecessors()[0],
            PredecessorKind::FollowsFrom(BlockId::from(6))
        );
    }

    #[test]
    fn test_conditional_jump_function() {
        init_logging();

        let model = parse_and_build_cfg(
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

        let func_id = model.functions().map(|(id, _)| id).next().unwrap();
        let func = model.function(&func_id);
        assert_eq!(func.stack_size(), 5);
        assert_eq!(func.blocks().count(), 4);
        assert_eq!(func.return_block(), Some(BlockId::from(16)));

        // Block 0 (Entry)
        let block0 = func.block(&BlockId::from(0));
        assert_eq!(block0.low_instructions().len(), 1); // if [R+1] goto @true_branch
        assert_eq!(block0.span(), &Span::new(0, 5));
        if let NextKind::Condition(ref cond) = block0.next() {
            assert_eq!(cond.target_block, BlockId::from(12));
            assert_eq!(cond.follows_block, BlockId::from(5));
            assert!(cond.jump_if_true);
        } else {
            panic!("Expected NextKind::Condition");
        }
        assert!(block0.predecessors().is_empty());

        // Block 5 (False branch)
        let block5 = func.block(&BlockId::from(5));
        assert_eq!(block5.low_instructions().len(), 2); // [R+2]=100, goto @merge
        assert_eq!(block5.span(), &Span::new(5, 12));
        assert!(matches!(block5.next(), NextKind::Goto(b) if *b == BlockId::from(16)));
        assert_eq!(block5.predecessors().len(), 1);
        if let PredecessorKind::ConditionalFollow(ref cond) = block5.predecessors()[0] {
            assert_eq!(cond.from_block, BlockId::from(0));
        } else {
            panic!("Expected PredecessorKind::ConditionalFollow");
        }

        // Block 12 (True branch)
        let block12 = func.block(&BlockId::from(12));
        assert_eq!(block12.low_instructions().len(), 1); // [R+3]=200
        assert_eq!(block12.span(), &Span::new(12, 16));
        assert_eq!(block12.next(), &NextKind::Follows(BlockId::from(16))); // Falls through to merge
        assert_eq!(block12.predecessors().len(), 1);
        if let PredecessorKind::ConditionalJump(ref cond) = block12.predecessors()[0] {
            assert_eq!(cond.from_block, BlockId::from(0));
        } else {
            panic!("Expected PredecessorKind::ConditionalJump");
        }

        // Block 16 (Merge & Return)
        let block16 = func.block(&BlockId::from(16));
        assert_eq!(block16.low_instructions().len(), 1); // Just Return
        assert_eq!(block16.span(), &Span::new(16, 21));
        assert_eq!(block16.next(), &NextKind::Return);
        assert_eq!(block16.predecessors().len(), 2);
        assert!(block16
            .predecessors()
            .contains(&PredecessorKind::GotoFrom(BlockId::from(5))));
        assert!(block16
            .predecessors()
            .contains(&PredecessorKind::FollowsFrom(BlockId::from(12))));
    }

    #[test]
    fn test_loop_function() {
        init_logging();

        let model = parse_and_build_cfg(
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

        let func_id = model.functions().map(|(id, _)| id).next().unwrap();
        let func = model.function(&func_id);
        assert_eq!(func.blocks().count(), 3);
        assert_eq!(func.return_block(), Some(BlockId::from(9)));

        // Block 0 (Setup)
        let block0 = func.block(&BlockId::from(0));
        assert_eq!(block0.low_instructions().len(), 0); // No low-level instructions (just R+=5)
        assert_eq!(block0.span(), &Span::new(0, 2));
        assert_eq!(block0.next(), &NextKind::Follows(BlockId::from(2)));
        assert!(block0.predecessors().is_empty());

        // Block 2 (Loop Body)
        let block2 = func.block(&BlockId::from(2));
        assert_eq!(block2.low_instructions().len(), 2); // [R+1] = [R+1] - 1, if [R+1] goto @loop_start
        assert_eq!(block2.span(), &Span::new(2, 9));

        // Check the conditional loop structure
        if let NextKind::Condition(cond) = block2.next() {
            assert_eq!(
                cond.target_block,
                BlockId::from(2),
                "Loop should target itself"
            );
            assert_eq!(
                cond.follows_block,
                BlockId::from(9),
                "Loop exit should go to block 9"
            );
        } else {
            panic!("Expected block2.next() to be a Condition");
        }

        assert!(block2
            .predecessors()
            .contains(&PredecessorKind::FollowsFrom(BlockId::from(0))));

        // Block 9 (Exit & Return)
        let block9 = func.block(&BlockId::from(9));
        assert_eq!(block9.low_instructions().len(), 1); // Just Return instruction
        assert_eq!(block9.span(), &Span::new(9, 14));
        assert_eq!(block9.next(), &NextKind::Return);

        // Check that Block 9 has a predecessor - should be a ConditionalFollow from Block 2
        assert_eq!(
            block9.predecessors().len(),
            1,
            "Block 9 should have exactly one predecessor"
        );
        if let PredecessorKind::ConditionalFollow(cond) = &block9.predecessors()[0] {
            assert_eq!(
                cond.from_block,
                BlockId::from(2),
                "Block 9 should be entered from Block 2"
            );
        } else {
            panic!("Expected Block 9 to have a ConditionalFollow predecessor from Block 2");
        }
    }

    #[test]
    fn test_function_call() {
        init_logging();

        let model = parse_and_build_cfg(
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

        // Find the main and callee functions
        let (main_id, callee_id) = model
            .functions()
            .map(|(id, _)| id)
            .sorted()
            .collect_tuple()
            .unwrap();
        let main = model.function(&main_id);
        let callee = model.function(&callee_id);

        // Check function properties
        assert_eq!(main.stack_size(), 5);
        assert_eq!(callee.stack_size(), 4);

        // Find the call block in main
        let call_block = main
            .blocks()
            .find(|(_, block)| matches!(block.next(), &NextKind::FunctionCall(_)))
            .map(|(_, block)| block)
            .unwrap();

        // Check the function call
        if let NextKind::FunctionCall(call) = call_block.next() {
            assert_eq!(call.return_block, BlockId::from(17));
            assert_eq!(call.calling_block, call_block.block_id());
            // For low-level, check that there's a constant expression with value 24
            if let crate::disasm::v2::instructions::Expression::Constant(addr) = &call.function_addr
            {
                assert_eq!(*addr, 24);
            } else {
                panic!("Expected function address to be a constant");
            }
        } else {
            panic!("Expected FunctionCall");
        }

        // Check the return block in main
        let return_block = main.block(&BlockId::from(17));
        assert_eq!(return_block.predecessors().len(), 1);
        assert!(matches!(
            return_block.predecessors()[0],
            PredecessorKind::FunctionCallReturns(_)
        ));

        // Check Call Block Predecessor in Callee
        let block24 = callee.block(&BlockId::from(24)); // The call block in callee
        assert_eq!(block24.predecessors().len(), 0);
    }

    #[test]
    fn test_halt_function() {
        init_logging();

        let model = parse_and_build_cfg(
            r#"
            R += 2
            halt
            "#,
        );
        let func_id = model.functions().map(|(id, _)| id).next().unwrap();
        let func = model.function(&func_id);
        assert_eq!(func.stack_size(), 2);
        assert_eq!(func.blocks().count(), 1);
        assert!(func.return_block().is_none());

        let block0 = func.block(&BlockId::from(0));
        assert_eq!(block0.low_instructions().len(), 1); // Just the Halt instruction
        assert_eq!(block0.next(), &NextKind::Halt);
    }
}
