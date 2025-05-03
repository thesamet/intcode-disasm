use super::{
    model::{Model, InitialState, FunctionCallComplete, SsaComplete},
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
    let model = ImageScanner::run(image, model)?;
    let model = ControlFlowGraphBuilder::run(model)?;
    let model = DataFlowAnalyzer::run(model)?;
    let model = SsaConverter::run(model)?;
    let model = FunctionCallAnalyzer::run(model)?;
    
    // Return the final model
    Ok(model)
}

/// Run the analysis pipeline up to SSA conversion
pub fn run_analysis_ssa(image: Vec<i128>) -> Result<Model<SsaComplete>, Error> {
    // Create initial model
    let model = Model::<InitialState>::new().with_image(image.clone());
    
    // Run each analysis phase in sequence up to SSA
    let model = ImageScanner::run(image, model)?;
    let model = ControlFlowGraphBuilder::run(model)?;
    let model = DataFlowAnalyzer::run(model)?;
    let model = SsaConverter::run(model)?;
    
    // Return the model with SSA complete
    Ok(model)
}
