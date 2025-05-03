mod result;
mod scanner;

pub use result::ImageScannerResult;
pub use scanner::ImageScanner;

use crate::disasm::v3::model::{Model, InitialState, ImageScannerComplete};

impl ImageScanner {
    pub fn analyze(image: Vec<i128>, model: Model<InitialState>) -> Model<ImageScannerComplete> {
        // Create the image scanner result
        let result = ImageScannerResult {
            recognized_functions: Vec::new(),
            data_segments: Vec::new(),
            image,
        };
        
        // Return a new model with the updated state
        Model {
            image_scanner_result: Some(result),
            control_flow_graph_result: None,
            data_flow_result: None,
            ssa_result: None,
            function_call_analysis_result: None,
            marker: std::marker::PhantomData,
        }
    }
}
