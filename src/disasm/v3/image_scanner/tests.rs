#[cfg(test)]
mod tests {
    use super::super::{ImageScanner, ImageScannerResult};
    use crate::disasm::v3::model::{Model, InitialState};
    use crate::disasm::test_utils::init_logging;

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
}
