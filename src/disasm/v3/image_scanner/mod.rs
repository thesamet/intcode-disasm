pub mod result;
mod scanner;
#[cfg(test)]
mod tests;

pub use result::{ImageScannerResult, DataSegment, DataType, RecognizedFunction, BaseFunctionCall};
pub use scanner::ImageScanner;
