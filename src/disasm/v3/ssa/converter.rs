use crate::disasm::v3::model::{Model, DataFlowComplete, SsaComplete};
use crate::disasm::Error;
use super::result::SsaResult;
use std::collections::HashMap;

/// Converts the control flow graph to SSA form
pub struct SsaConverter;

impl SsaConverter {
    pub fn new() -> Self {
        Self {}
    }
    
    pub fn run(&self, model: Model<DataFlowComplete>) -> Result<Model<SsaComplete>, Error> {
        let model = self.convert(model)?;
        Ok(model)
    }
    
    fn convert(&self, model: Model<DataFlowComplete>) -> Result<Model<SsaComplete>, Error> {
        // Create the SSA result
        let result = SsaResult {
            blocks: HashMap::new(),
        };
        
        // Return a new model with the updated state
        Ok(Model {
            image_scanner_result: model.image_scanner_result,
            control_flow_graph_result: model.control_flow_graph_result,
            data_flow_result: model.data_flow_result,
            ssa_result: Some(result),
            function_call_analysis_result: None,
            marker: std::marker::PhantomData,
        })
    }
}
