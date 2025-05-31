use crate::disasm::Error;

use super::{
    control_flow::ControlFlowGraphBuilder,
    data_flow::DataFlowAnalyzer,
    folded_ssa::FoldedSsaBuilder,
    function_call::FunctionCallAnalyzer,
    image_scanner::ImageScanner,
    model::{
        ControlFlowGraphComplete, DataFlowComplete, FoldedSsaComplete,
        FunctionCallAnalysisComplete, ImageScannerComplete, Model, SsaComplete,
        TypeInferenceComplete, VariableMergerComplete,
    },
    ssa::SsaConverter,
    type_inference::Solver,
    variable_analyzer::VariableMerger,
};

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

pub fn binary_to_folded_ssa(binary: Vec<i128>) -> Result<Model<FoldedSsaComplete>, Error> {
    let model = binary_to_function_calls(binary)?;
    FoldedSsaBuilder::run(model)
}

pub fn binary_to_type_inference(binary: Vec<i128>) -> Result<Model<TypeInferenceComplete>, Error> {
    let model = binary_to_folded_ssa(binary)?;
    Solver::run(model)
}

pub fn binary_to_variable_merger(
    binary: Vec<i128>,
) -> Result<Model<VariableMergerComplete>, Error> {
    let model = binary_to_type_inference(binary)?;
    VariableMerger::run(model)
}
