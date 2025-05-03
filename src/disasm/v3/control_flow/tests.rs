#[cfg(test)]
mod tests {
    use super::super::{ControlFlowGraphBuilder, Function};
    use crate::disasm::parser;
    use crate::disasm::test_utils::init_logging;
    use crate::disasm::v2::control_flow::NextKind;
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
}
