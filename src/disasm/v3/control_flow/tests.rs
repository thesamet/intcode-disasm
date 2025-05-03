#[cfg(test)]
mod tests {
    use super::super::{ControlFlowGraphBuilder, Function};
    use crate::disasm::parser;
    use crate::disasm::test_utils::init_logging;
    use crate::disasm::v2::control_flow::{NextKind, PredecessorKind};
    use crate::disasm::v3::id_types::{BlockId, FunctionId};
    use crate::disasm::v3::image_scanner::ImageScanner;
    use crate::disasm::v3::model::{InitialState, Model};

    fn parse_and_build_cfg(code: &str) -> super::super::ControlFlowGraphResult {
        let binary = parser::compile(code);
        let model = Model::<InitialState>::new().with_image(binary.clone());
        let model = ImageScanner::run(binary, model).expect("Image scanner failed");
        let result = ControlFlowGraphBuilder::run(model).expect("CFG builder failed");
        result.control_flow_graph_result.unwrap()
    }

    #[test]
    fn test_simple_function_cfg() {
        init_logging();
        
        let result = parse_and_build_cfg(
            r#"
            R += 5
            [R+2] = [R+3] + [R+4]
            [R+2] = [R+3] + [R+4]
            R -= 5
            goto [R]
            "#,
        );
        
        assert_eq!(result.functions.len(), 1);
        
        // Get the function
        let function_id = *result.functions.keys().next().unwrap();
        let function = &result.functions[&function_id];
        
        // Check function properties
        assert_eq!(function.stack_size, 5);
        assert!(function.return_block.is_some());
        
        // Check blocks
        assert!(!function.blocks.is_empty());
        
        // Check entry block
        let entry_block = &function.blocks[&function.entry_block];
        assert_eq!(entry_block.containing_function_id, function_id);
        assert!(!entry_block.native_instructions.is_empty());
    }

    #[test]
    fn test_function_with_call() {
        init_logging();
        
        let result = parse_and_build_cfg(
            r#"
            R += 5      ;0
            [R+1] = 42  ;2
            [R] = @ret  ;6
            goto @other_func   ; 10
            ret:
            R -= 5             ; 13
            goto [R]
            other_func:
            R += 3
            [R-1] = [R-2] + 1
            R -= 3
            goto [R]
            "#,
        );
        
        assert_eq!(result.functions.len(), 2);
        
        // Find the main function (first one)
        let main_id = *result.functions.keys().next().unwrap();
        let main = &result.functions[&main_id];
        
        // Find the other function (second one)
        let other_id = *result.functions.keys().skip(1).next().unwrap();
        let other = &result.functions[&other_id];
        
        // Check function properties
        assert_eq!(main.stack_size, 5);
        assert_eq!(other.stack_size, 3);
        
        // Check that the main function has a function call
        let call_block = main.blocks.values().find(|block| {
            matches!(block.next, NextKind::FunctionCall { .. })
        });
        assert!(call_block.is_some());
    }

    #[test]
    fn test_function_with_jumps() {
        init_logging();
        
        let result = parse_and_build_cfg(
            r#"
            R += 5                   ; 0
            if [R+1] goto @branch    ; 2
            [R+2] = 42               ; 5
            goto @merge              ; 9
            branch:
            [R+2] = 100              ; 12
            merge:
            R -= 5                   ; 16
            goto [R]                 ; 18
            "#,
        );
        
        assert_eq!(result.functions.len(), 1);
        
        // Get the function
        let function_id = *result.functions.keys().next().unwrap();
        let function = &result.functions[&function_id];
        
        // Check that we have at least 3 blocks (entry, branch, merge)
        assert!(function.blocks.len() >= 3);
        
        // Find the conditional jump block
        let cond_block = function.blocks.values().find(|block| {
            matches!(block.next, NextKind::ConditionalJump { .. })
        });
        assert!(cond_block.is_some());
    }

    #[test]
    fn test_simple_return_function() {
        init_logging();
        
        let result = parse_and_build_cfg(
            r#"
            ; Offset 0
            R += 5
            ; Offset 2
            R -= 5
            ; Offset 4
            goto [R]
            "#,
        );

        let func_id = *result.functions.keys().next().unwrap();
        let func = &result.functions[&func_id];
        assert_eq!(func.stack_size, 5);
        assert_eq!(func.entry_block, BlockId::from(0));
        assert_eq!(func.blocks.len(), 2);
        assert_eq!(func.return_block, Some(BlockId::from(2))); // The return block starts at offset 2

        let block0 = &func.blocks[&BlockId::from(0)];
        assert_eq!(block0.id, BlockId::from(0));
        assert_eq!(block0.containing_function_id, func_id);
        assert_eq!(block0.low_instructions.len(), 0); // Entry block has no low instructions (just R+=5)
        assert_eq!(block0.span, Span::new(0, 2));
        assert_eq!(block0.next, NextKind::Follows(BlockId::from(2)));

        let block1 = &func.blocks[&BlockId::from(2)];
        assert_eq!(block1.id, BlockId::from(2));
        assert_eq!(block1.containing_function_id, func_id);
        assert_eq!(block1.low_instructions.len(), 1); // Just the Return instruction
        assert_eq!(block1.span, Span::new(2, 7));
        assert_eq!(block1.next, NextKind::Return);
        assert_eq!(
            block1.predecessors.len(), 1,
            "Return block should have exactly one predecessor"
        );
        assert!(matches!(
            block1.predecessors[0],
            PredecessorKind::FollowsFrom(id) if id == BlockId::from(0)
        ));
    }

    #[test]
    fn test_loop_function() {
        init_logging();
        
        let result = parse_and_build_cfg(
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

        let func_id = *result.functions.keys().next().unwrap();
        let func = &result.functions[&func_id];
        assert_eq!(func.blocks.len(), 3);
        assert_eq!(func.return_block, Some(BlockId::from(9)));

        // Block 0 (Setup)
        let block0 = &func.blocks[&BlockId::from(0)];
        assert_eq!(block0.low_instructions.len(), 0); // No low-level instructions (just R+=5)
        assert_eq!(block0.span, Span::new(0, 2));
        assert_eq!(block0.next, NextKind::Follows(BlockId::from(2)));
        assert!(block0.predecessors.is_empty());

        // Block 2 (Loop Body)
        let block2 = &func.blocks[&BlockId::from(2)];
        assert_eq!(block2.span, Span::new(2, 9));
        
        // Check that the loop body has a conditional jump back to itself
        if let NextKind::ConditionalJump { true_branch, false_branch, .. } = &block2.next {
            assert_eq!(*true_branch, BlockId::from(2), "Loop should target itself");
            assert_eq!(*false_branch, BlockId::from(9), "Loop exit should go to block 9");
        } else {
            panic!("Expected block2.next to be a ConditionalJump");
        }

        // Block 9 (Exit & Return)
        let block9 = &func.blocks[&BlockId::from(9)];
        assert_eq!(block9.low_instructions.len(), 1); // Just Return instruction
        assert_eq!(block9.span, Span::new(9, 14));
        assert_eq!(block9.next, NextKind::Return);
        
        // Check that Block 9 has a predecessor from the loop condition
        assert_eq!(
            block9.predecessors.len(),
            1,
            "Block 9 should have exactly one predecessor"
        );
        assert!(matches!(
            block9.predecessors[0],
            PredecessorKind::ConditionalFollow(ref cond) if cond.from_block == BlockId::from(2)
        ));
    }

    #[test]
    fn test_function_call() {
        init_logging();
        
        let result = parse_and_build_cfg(
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
        let (main_id, callee_id) = result.functions.keys().collect_tuple().unwrap();
        let main = &result.functions[main_id];
        let callee = &result.functions[callee_id];

        // Check function properties
        assert_eq!(main.stack_size, 5);
        assert_eq!(callee.stack_size, 4);
        
        // Find the call block in main
        let call_block = main.blocks.values().find(|block| {
            matches!(block.next, NextKind::FunctionCall { .. })
        }).unwrap();
        
        // Check the function call
        if let NextKind::FunctionCall(call) = &call_block.next {
            assert_eq!(call.return_block, BlockId::from(17));
            assert_eq!(call.calling_block, call_block.id);
        } else {
            panic!("Expected FunctionCall");
        }
        
        // Check the return block in main
        let return_block = &main.blocks[&BlockId::from(17)];
        assert_eq!(return_block.predecessors.len(), 1);
        assert!(matches!(
            return_block.predecessors[0],
            PredecessorKind::FunctionCallReturns(_)
        ));
    }
}
