#[cfg(test)]
mod tests {
    use super::super::{DataSegment, DataType, ImageScanner};
    use crate::disasm::parser;
    use crate::disasm::test_utils::init_logging;
    use crate::disasm::v3::id_types::FunctionId;
    use crate::disasm::v3::model::{InitialState, Model};
    use std::collections::HashMap;

    fn parse_and_scan(code: &str) -> super::super::ImageScannerResult {
        let binary = parser::compile(code);
        let model = Model::<InitialState>::new().with_image(binary.clone());
        let result = ImageScanner::run(binary, model).expect("Image scanner failed");
        result.image_scanner_result.unwrap()
    }

    #[test]
    fn test_image_scanner_basic() {
        init_logging();

        // Create a simple test image
        let image = vec![1, 2, 3, 4, 5];

        // Create initial model
        let model = Model::<InitialState>::new().with_image(image.clone());

        // Run the image scanner
        let result = ImageScanner::run(image, model).expect("Image scanner failed");

        // Verify the result
        let scanner_result = result.image_scanner_result.unwrap();
        assert_eq!(scanner_result.image, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_disassemble() {
        init_logging();

        // Create a simple test image
        let image = vec![1, 2, 3, 4, 5];

        // Run the disassemble function
        let result =
            crate::disasm::v3::analysis::disassemble(image.clone()).expect("Disassembly failed");

        // Verify the result
        assert_eq!(result.image, image);
    }

    #[test]
    fn test_empty_image() {
        init_logging();

        // Create an empty image
        let image = vec![];

        // Create initial model
        let model = Model::<InitialState>::new().with_image(image.clone());

        // Run the image scanner
        let result = ImageScanner::run(image, model).expect("Image scanner failed");

        // Verify the result
        let scanner_result = result.image_scanner_result.unwrap();
        assert_eq!(scanner_result.image, vec![]);
        assert_eq!(scanner_result.recognized_functions.len(), 0);
        assert_eq!(scanner_result.data_segments.len(), 0);
    }

    #[test]
    fn test_function_mapping() {
        init_logging();

        // Create a test image with multiple potential functions
        let image = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Create initial model
        let model = Model::<InitialState>::new().with_image(image.clone());

        // Run the image scanner
        let result = ImageScanner::run(image, model).expect("Image scanner failed");

        // Verify the result
        let scanner_result = result.image_scanner_result.unwrap();

        // Check that function ID 0 maps to address 0
        if !scanner_result.recognized_functions.is_empty() {
            let function_id = scanner_result.recognized_functions[0];
            assert_eq!(
                scanner_result.function_to_address.get(&function_id),
                Some(&0)
            );
            assert_eq!(
                scanner_result.address_to_function.get(&0),
                Some(&function_id)
            );
        }
    }
    
    #[test]
    fn test_simple_function() {
        let result = parse_and_scan(
            r#"
            R += 5
            [R+2] = [R+3] + [R+4]
            [R+2] = [R+3] + [R+4]
            R -= 5
            goto [R]
            "#,
        );
        assert_eq!(result.recognized_functions.len(), 1);
        let function_id = result.recognized_functions[0];
        let function = &result.function_details[&function_id];
        assert_eq!(function.stack_size, 5);
        assert!(function.return_span.is_some());
        assert_eq!(function.instructions.len(), 5);
    }

    #[test]
    fn test_function_with_call() {
        let result = parse_and_scan(
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
        assert_eq!(result.recognized_functions.len(), 2);
        
        // Get the main function (first one)
        let main_id = result.recognized_functions[0];
        let main = &result.function_details[&main_id];
        
        // Get the other function (second one)
        let other_id = result.recognized_functions[1];
        let other = &result.function_details[&other_id];

        assert_eq!(main.stack_size, 5);
        assert_eq!(other.stack_size, 3);

        assert_eq!(main.function_calls.len(), 1);
        assert_eq!(main.function_calls[0].return_address, 13);
    }

    #[test]
    fn test_function_with_jumps() {
        let result = parse_and_scan(
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
        assert_eq!(result.recognized_functions.len(), 1);
        let function_id = result.recognized_functions[0];
        let function = &result.function_details[&function_id];

        assert_eq!(function.jump_targets.len(), 2);
        assert!(function.jump_targets.contains(&12)); // branch
        assert!(function.jump_targets.contains(&16)); // merge
    }

    #[test]
    fn test_data_segments() {
        let result = parse_and_scan(
            r#"
            DATA 99
            DATA 1, 2, 3, 4
            R += 5         ; 5
            [R+1] = 42     ; 7
            R -= 5         ; 11
            goto [R]       ; 13
            DATA 99        ; 16
            DATA 5, 6, 7, 8
            "#,
        );

        assert_eq!(result.recognized_functions.len(), 1);
        assert!(result.data_segments.len() >= 1);
    }

    #[test]
    fn test_another_function_call() {
        let result = parse_and_scan(
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
        assert_eq!(result.recognized_functions.len(), 2);
        
        // Get the main function (first one)
        let main_id = result.recognized_functions[0];
        let main = &result.function_details[&main_id];
        
        // Get the callee function (second one)
        let callee_id = result.recognized_functions[1];
        let callee = &result.function_details[&callee_id];

        assert_eq!(main.stack_size, 5);
        assert_eq!(callee.stack_size, 4);

        assert_eq!(main.function_calls.len(), 1);
        assert_eq!(main.function_calls[0].return_address, 17);
    }
}
