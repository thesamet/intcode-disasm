use std::collections::HashMap;

use super::{
    control_flow::Block,
    data_flow::DataFlowResult, // + Import DataFlowResult
    dispatching::EventPublisher,
    events::{self, Event, ImageAddedEvent, ImageScannerComplete},
    id_types::define_id_type,
    listeners::image_scanner::ImageScannerResult,
};

define_id_type!(FunctionId);

#[derive(Debug, Clone)]
pub struct ProgramModel {
    image: Vec<i128>,

    image_scanner_result: Option<ImageScannerResult>,
    data_flow_result: Option<DataFlowResult>, // + Add field for data flow results

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
            data_flow_result: None, // + Initialize field
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

    /// Sets the computed data flow analysis results.
    /// Typically called by the DataFlowAnalyzer listener.
    pub fn set_data_flow_result(&mut self, result: DataFlowResult) {
        self.data_flow_result = Some(result);
        // Potentially emit a DataFlowAnalysisComplete event here if needed by subsequent stages
    }

    /// Gets an immutable reference to the data flow analysis results, if computed.
    pub fn get_data_flow_result(&self) -> Option<&DataFlowResult> {
        self.data_flow_result.as_ref()
    }

    pub fn get_data_flow_result_mut(&mut self) -> Option<&mut DataFlowResult> {
        self.data_flow_result.as_mut()
    }

    pub fn add_function(&mut self, function: Function) {
        self.functions.insert(function.function_id, function);
    }

    pub fn has_function(&self, function_id: FunctionId) -> bool {
        self.functions.contains_key(&function_id)
    }
    pub fn get_function(&self, function_id: FunctionId) -> &Function {
        self.functions.get(&function_id).unwrap()
    }

    pub fn get_function_mut(&mut self, function_id: FunctionId) -> &mut Function {
        self.functions.get_mut(&function_id).unwrap()
    }

    pub fn add_block(&mut self, block: Block) {
        self.blocks.insert(block.id, block);
    }

    pub fn has_block(&self, block_id: BlockId) -> bool {
        self.blocks.contains_key(&block_id)
    }

    pub fn get_block(&self, block_id: BlockId) -> &Block {
        self.blocks.get(&block_id).unwrap()
    }

    pub fn get_block_mut(&mut self, block_id: BlockId) -> &mut Block {
        self.blocks.get_mut(&block_id).unwrap()
    }
}

define_id_type!(BlockId);

#[derive(Debug, Clone)]
pub struct Condition {}

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
pub struct Function {
    // Basic structural info (always available)
    pub function_id: FunctionId,
    pub entry_block: BlockId,

    // Discovered by control flow analysis
    pub stack_size: usize,
    pub blocks: Vec<BlockId>, // list of blocks in this function

    // The block containing the R -= N; goto [R] sequence.
    // Function may not have a return block. For example, if it reaches the end of the image, is a loop, or it halts.
    pub return_block: Option<BlockId>,
}
