mod block;
mod function;
mod result;
mod builder;

pub use block::Block;
pub use function::Function;
pub use result::ControlFlowGraphResult;
pub use builder::ControlFlowGraphBuilder;

use crate::disasm::v3::model::{Model, ImageScannerComplete, ControlFlowGraphComplete};
use std::collections::HashMap;

impl ControlFlowGraphBuilder {
    pub fn analyze(model: Model<ImageScannerComplete>) -> Model<ControlFlowGraphComplete> {
        // Create the control flow graph result
        let result = ControlFlowGraphResult {
            functions: HashMap::new(),
        };
        
        // Return a new model with the updated state
        Model {
            image_scanner_result: model.image_scanner_result,
            control_flow_graph_result: Some(result),
            data_flow_result: None,
            ssa_result: None,
            function_call_analysis_result: None,
            marker: std::marker::PhantomData,
        }
    }
}
