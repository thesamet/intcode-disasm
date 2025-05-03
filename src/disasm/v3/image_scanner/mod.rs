mod result;
mod scanner;
#[cfg(test)]
mod tests;

pub use result::{ImageScannerResult, DataSegment, DataType};
pub use scanner::ImageScanner;
