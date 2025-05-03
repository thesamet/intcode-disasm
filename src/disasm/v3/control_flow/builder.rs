use crate::disasm::v3::model::{Model, ImageScannerComplete, ControlFlowGraphComplete};
use crate::disasm::Error;
use super::result::ControlFlowGraphResult;
use std::collections::HashMap;

/// Builds the control flow graph from the image scanner results
pub struct ControlFlowGraphBuilder {
    model: Model<ImageScannerComplete>,
}

impl ControlFlowGraphBuilder {
    pub fn new(model: Model<ImageScannerComplete>) -> Self {
        Self { model }
    }
    
    pub fn run(model: Model<ImageScannerComplete>) -> Result<Model<ControlFlowGraphComplete>, Error> {
        let builder = Self::new(model);
        builder.build()
    }
    
    fn build(&self) -> Result<Model<ControlFlowGraphComplete>, Error> {
        // Create the control flow graph result
        let result = ControlFlowGraphResult {
            functions: HashMap::new(),
        };
        
        // Return a new model with the updated state
        Ok(Model {
            image_scanner_result: self.model.image_scanner_result.clone(),
            control_flow_graph_result: Some(result),
            data_flow_result: None,
            ssa_result: None,
            function_call_analysis_result: None,
            marker: std::marker::PhantomData,
        })
    }
}
