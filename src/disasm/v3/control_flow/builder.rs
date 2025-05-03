use crate::disasm::v3::model::{Model, ImageScannerComplete, ControlFlowGraphComplete};
use crate::disasm::Error;
use super::result::ControlFlowGraphResult;
use std::collections::HashMap;

/// Builds the control flow graph from the image scanner results
pub struct ControlFlowGraphBuilder;

impl ControlFlowGraphBuilder {
    pub fn new() -> Self {
        Self {}
    }
    
    pub fn run(&self, model: Model<ImageScannerComplete>) -> Result<Model<ControlFlowGraphComplete>, Error> {
        let model = self.build(model)?;
        Ok(model)
    }
    
    fn build(&self, model: Model<ImageScannerComplete>) -> Result<Model<ControlFlowGraphComplete>, Error> {
        // Create the control flow graph result
        let result = ControlFlowGraphResult {
            functions: HashMap::new(),
        };
        
        // Return a new model with the updated state
        Ok(Model {
            image_scanner_result: model.image_scanner_result,
            control_flow_graph_result: Some(result),
            data_flow_result: None,
            ssa_result: None,
            function_call_analysis_result: None,
            marker: std::marker::PhantomData,
        })
    }
}
