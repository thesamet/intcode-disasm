use crate::disasm::v3::id_types::FunctionId;
use std::collections::HashMap;

/// Result of the image scanning phase
#[derive(Debug, Clone)]
pub struct ImageScannerResult {
    pub recognized_functions: Vec<FunctionId>,
    pub data_segments: Vec<DataSegment>,
    pub image: Vec<i128>,
}

#[derive(Debug, Clone)]
pub struct DataSegment {
    pub start: usize,
    pub end: usize,
    pub data_type: DataType,
}

#[derive(Debug, Clone)]
pub enum DataType {
    Code,
    Data,
    Unknown,
}
