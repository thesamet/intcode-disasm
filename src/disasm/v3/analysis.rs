use super::{
    control_flow::ControlFlowGraphBuilder,
    data_flow::DataFlowAnalyzer,
    function_call::FunctionCallAnalyzer,
    image_scanner::ImageScanner,
    model::{FunctionCallComplete, InitialState, Model, SsaComplete},
    ssa::SsaConverter,
};

use crate::disasm::Error;
use log::info;

/// Run the complete analysis pipeline
pub fn run_analysis(image: Vec<i128>) -> Result<Model<FunctionCallComplete>, Error> {
    info!("Starting complete analysis pipeline");

    // Create initial model
    let model = Model::from_binary(image);

    // Run each analysis phase in sequence
    let model = ImageScanner::run(model)?;
    let model = ControlFlowGraphBuilder::run(model)?;
    let model = DataFlowAnalyzer::run(model)?;
    let model = SsaConverter::run(model)?;
    let model = FunctionCallAnalyzer::run(model)?;

    info!("Analysis pipeline complete");

    // Return the final model
    Ok(model)
}

/// Run the analysis pipeline up to SSA conversion
pub fn run_analysis_ssa(image: Vec<i128>) -> Result<Model<SsaComplete>, Error> {
    info!("Starting analysis pipeline up to SSA conversion");

    // Create initial model
    let model = Model::from_binary(image);

    // Run each analysis phase in sequence up to SSA
    let model = ImageScanner::run(model)?;
    let model = ControlFlowGraphBuilder::run(model)?;
    let model = DataFlowAnalyzer::run(model)?;
    let model = SsaConverter::run(model)?;

    info!("SSA analysis pipeline complete");

    // Return the model with SSA complete
    Ok(model)
}

/// Disassemble the image and return just the image scanner result
pub fn disassemble(image: Vec<i128>) -> Result<super::image_scanner::ImageScannerResult, Error> {
    info!("Starting disassembly");

    // Create initial model
    let model = Model::from_binary(image);

    // Run only the image scanner phase
    let model = ImageScanner::run(model)?;

    info!("Disassembly complete");

    // Return just the image scanner result
    Ok(model.image_scanner_result().clone())
}
