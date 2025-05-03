mod result;
mod scanner;

pub use result::ImageScannerResult;
pub use scanner::ImageScanner;

use crate::disasm::v3::model::{HasImageScannerResult, Model, ModelState};
use std::collections::HashMap;

impl<S: ModelState> Model<S>
where
    S: HasImageScannerResult,
{
    pub fn image_scanner_result(&self) -> &ImageScannerResult {
        // This would access the actual result stored in the model
        // For now it's a placeholder
        unimplemented!("Access to image scanner result not yet implemented")
    }
}
