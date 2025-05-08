use itertools::Itertools;

use crate::disasm::v3::id_types::FunctionId;
use crate::disasm::v3::native::Operand;
use crate::disasm::v3::{common::Span, native::NativeInstruction};
use std::collections::{HashMap, HashSet};

/// Result of the image scanning phase
#[derive(Debug, Clone, Default)]
pub struct ImageScannerResult {
    pub data_segments: Vec<DataSegment>,

    // Maps addresses to function IDs
    pub(crate) address_to_function: HashMap<usize, FunctionId>,

    // Detailed function information
    pub recognized_functions: HashMap<FunctionId, RecognizedFunction>,
}

impl ImageScannerResult {
    pub fn function_ids(&self) -> Vec<FunctionId> {
        self.recognized_functions.keys().sorted().cloned().collect()
    }
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
