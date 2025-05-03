use super::{
    model::{Model, InitialState, FunctionCallComplete},
    image_scanner::ImageScanner,
    control_flow::ControlFlowGraphBuilder,
    data_flow::DataFlowAnalyzer,
    ssa::SsaConverter,
    function_call::FunctionCallAnalyzer,
};

use crate::disasm::Error;

/// Run the complete analysis pipeline
pub fn run_analysis(image: Vec<i128>) -> Result<Model<FunctionCallComplete>, Error> {
    // Create initial model
    let model = Model::<InitialState>::new().with_image(image.clone());
    
    // Run each analysis phase in sequence
    let model = ImageScanner::analyze(image, model);
    let model = ControlFlowGraphBuilder::analyze(model);
    let model = DataFlowAnalyzer::analyze(model);
    let model = SsaConverter::analyze(model);
    let model = FunctionCallAnalyzer::analyze(model);
    
    // Return the final model
    Ok(model)
}

/// Run the analysis pipeline up to SSA conversion
pub fn run_analysis_ssa(image: Vec<i128>) -> Result<Model<super::model::SsaComplete>, Error> {
    // Create initial model
    let model = Model::<InitialState>::new().with_image(image.clone());
    
    // Run each analysis phase in sequence up to SSA
    let model = ImageScanner::analyze(image, model);
    let model = ControlFlowGraphBuilder::analyze(model);
    let model = DataFlowAnalyzer::analyze(model);
    let model = SsaConverter::analyze(model);
    
    // Return the model with SSA complete
    Ok(model)
}
