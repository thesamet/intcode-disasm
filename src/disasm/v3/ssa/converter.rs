use super::result::SsaResult;
use crate::disasm::v2::ssa_form;
use crate::disasm::v3::model::{DataFlowComplete, Model, SsaComplete};
use crate::disasm::Error;
use std::collections::HashMap;

/// Converts the control flow graph to SSA form
pub struct SsaConverter {
    model: Model<DataFlowComplete>,
}

impl SsaConverter {
    pub fn new(model: Model<DataFlowComplete>) -> Self {
        Self { model }
    }

    pub fn run(model: Model<DataFlowComplete>) -> Result<Model<SsaComplete>, Error> {
        let converter = Self::new(model);
        converter.convert()
    }

    fn convert(self) -> Result<Model<SsaComplete>, Error> {
        // Create the SSA result
        Ok(ssa_form::SsaResult::from_program_model(self.model))
    }
}
