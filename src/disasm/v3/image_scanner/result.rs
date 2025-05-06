use crate::disasm::v2::native::{NativeInstruction, Operand};
use crate::disasm::v3::common::Span;
use crate::disasm::v3::id_types::FunctionId;
use std::collections::{HashMap, HashSet};

/// Result of the image scanning phase
#[derive(Debug, Clone, Default)]
pub struct ImageScannerResult {
    pub recognized_functions: Vec<FunctionId>,
    pub data_segments: Vec<DataSegment>,

    // Maps addresses to function IDs
    pub address_to_function: HashMap<usize, FunctionId>,

    // Maps function IDs to their entry point addresses
    pub function_to_address: HashMap<FunctionId, usize>,

    // Detailed function information
    pub function_details: HashMap<FunctionId, RecognizedFunction>,
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

#[derive(Debug, Clone)]
pub struct RecognizedFunction {
    pub span: Span,
    pub stack_size: usize,
    pub instructions: Vec<NativeInstruction>,
    // The span of the return starts at the R adjustment, and ends after the goto.
    pub return_span: Option<Span>,
    pub jump_targets: HashSet<usize>,
    // Locations from which a jump (conditional or unconditional) is taken.
    pub jump_instructions: Vec<NativeInstruction>,
    pub function_calls: Vec<BaseFunctionCall>,
    pub halts: Vec<Span>,
}

#[derive(Debug, Clone)]
pub struct BaseFunctionCall {
    pub span: Span,
    pub target: Operand,
    pub return_address: usize,
}
