use crate::disasm::Error;

use super::{
    control_flow::ControlFlowGraphBuilder,
    data_flow::DataFlowAnalyzer,
    function_call::FunctionCallAnalyzer,
    image_scanner::ImageScanner,
    model::{
        ControlFlowGraphComplete, DataFlowComplete, FunctionCallAnalysisComplete,
        HasDataFlowResult, HasSsaResult, ImageScannerComplete, InitialState, Model, ModelState,
        SsaComplete,
    },
    ssa::SsaConverter,
};

use log::info;

pub fn binary_to_scanned_image(binary: Vec<i128>) -> Result<Model<ImageScannerComplete>, Error> {
    let model = Model::from_binary(binary);
    ImageScanner::run(model)
}

pub fn binary_to_cfg(binary: Vec<i128>) -> Result<Model<ControlFlowGraphComplete>, Error> {
    let model = binary_to_scanned_image(binary)?;
    ControlFlowGraphBuilder::run(model)
}

pub fn binary_to_data_flow(binary: Vec<i128>) -> Result<Model<DataFlowComplete>, Error> {
    let model = binary_to_cfg(binary)?;
    DataFlowAnalyzer::run(model)
}

pub fn binary_to_ssa(binary: Vec<i128>) -> Result<Model<SsaComplete>, Error> {
    let model = binary_to_data_flow(binary)?;
    SsaConverter::run(model)
}

pub fn binary_to_function_calls(
    binary: Vec<i128>,
) -> Result<Model<FunctionCallAnalysisComplete>, Error> {
    let model = binary_to_ssa(binary)?;
    FunctionCallAnalyzer::run(model)
}
