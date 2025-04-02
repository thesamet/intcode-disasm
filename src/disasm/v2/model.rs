use std::collections::HashMap;

use crate::disasm::low_ir::{Arg, Span};

use super::{
    dispatching::EventPublisher,
    events::{self, Event, ImageAddedEvent, ImageScannerComplete},
    id_types::define_id_type,
    instructions::Instruction,
    listeners::image_scanner::ImageScannerResult,
};

define_id_type!(FunctionId);

#[derive(Debug, Clone)]
pub struct ProgramModel {
    image: Vec<i128>,

    image_scanner_result: Option<ImageScannerResult>,

    functions: HashMap<FunctionId, Function>,
    blocks: HashMap<BlockId, Block>,
    // Define fields here
}

impl ProgramModel {
    pub fn new() -> Self {
        Self {
            image: Vec::new(),
            image_scanner_result: None,
            functions: HashMap::new(),
            blocks: HashMap::new(),
        }
    }

    pub fn load_image(&mut self, image: &[i128], sender: &mut EventPublisher<Event, Self>) {
        self.image = image.to_vec();
        sender.publish(ImageAddedEvent {});
    }

    pub fn get_image(&self) -> &Vec<i128> {
        &self.image
    }

    pub fn set_image_scanner_result(
        &mut self,
        result: ImageScannerResult,
        sender: &mut events::Sender,
    ) {
        self.image_scanner_result = Some(result);
        sender.publish(ImageScannerComplete {});
    }

    pub fn get_image_scanner_result(&self) -> &ImageScannerResult {
        self.image_scanner_result.as_ref().unwrap()
    }

    pub fn get_function(&self, function_id: FunctionId) -> &Function {
        self.functions.get(&function_id).unwrap()
    }

    pub fn get_block(&self, block_id: BlockId) -> &Block {
        self.blocks.get(&block_id).unwrap()
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
