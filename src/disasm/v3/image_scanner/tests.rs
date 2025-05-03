#[cfg(test)]
mod tests {
    use super::super::{ImageScanner, ImageScannerResult, DataSegment, DataType};
    use crate::disasm::v3::model::{Model, InitialState};
    use crate::disasm::test_utils::init_logging;
    use crate::disasm::v3::id_types::FunctionId;
    use std::collections::HashMap;

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
        assert_eq!(scanner_result.recognized_functions.len(), 1);
        assert_eq!(scanner_result.data_segments.len(), 1);
    }
    
    #[test]
    fn test_disassemble() {
        init_logging();
        
        // Create a simple test image
        let image = vec![1, 2, 3, 4, 5];
        
        // Run the disassemble function
        let result = crate::disasm::v3::analysis::disassemble(image.clone()).expect("Disassembly failed");
        
        // Verify the result
        assert_eq!(result.image, image);
        assert_eq!(result.recognized_functions.len(), 1);
        assert_eq!(result.data_segments.len(), 1);
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
        
        // Create a scanner with a custom implementation for testing
        let mut scanner = ImageScanner::new(image.clone());
        
        // Create initial model
        let model = Model::<InitialState>::new().with_image(image.clone());
        
        // Run the image scanner
        let result = ImageScanner::run(image, model).expect("Image scanner failed");
        
        // Verify the result
        let scanner_result = result.image_scanner_result.unwrap();
        
        // Check that function ID 0 maps to address 0
        if !scanner_result.recognized_functions.is_empty() {
            let function_id = scanner_result.recognized_functions[0];
            assert_eq!(scanner_result.function_to_address.get(&function_id), Some(&0));
            assert_eq!(scanner_result.address_to_function.get(&0), Some(&function_id));
        }
    }
}
