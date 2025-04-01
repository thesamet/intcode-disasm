use std::collections::HashMap;

use crate::disasm::low_ir::{Arg, Span};

use super::{id_types::define_id_type, instructions::Instruction};

define_id_type!(FunctionId);

#[derive(Debug, Clone)]
pub struct ProgramModel {
    pub image: Vec<i128>,

    functions: HashMap<FunctionId, Function>,
    blocks: HashMap<BlockId, Block>,
    // Define fields here
}

impl ProgramModel {
    pub fn new() -> Self {
        Self {
            image: Vec::new(),
            functions: HashMap::new(),
            blocks: HashMap::new(),
            // Initialize fields here
        }
    }
}

define_id_type!(BlockId);

#[derive(Debug, Clone)]
struct Block {
    // Basic structural info (always available)
    pub id: BlockId,

    // To which function does this block belong?
    pub containing_function: FunctionId,
    pub span: Span,
    pub instructions: Vec<Instruction>,
}

define_id_type!(ParameterId);
#[derive(Debug, Clone)]
struct Parameter {
    id: ParameterId,
}

define_id_type!(ReturnValueId);
#[derive(Debug, Clone)]
struct ReturnValue {
    id: ReturnValueId,
}

#[derive(Debug, Clone)]
struct Function {
    // Basic structural info (always available)
    pub function_id: FunctionId,
    pub entry_block: BlockId,

    // Discovered by control flow analysis
    pub stack_size: Option<usize>,
    pub return_block: Option<BlockId>,

    // Parameters and return values (enriched over time)
    pub parameters: Option<Vec<Parameter>>,
    pub return_values: Option<Vec<ReturnValue>>,
}
