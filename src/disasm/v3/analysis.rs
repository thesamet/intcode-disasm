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
    let scanner = ImageScanner::new();
    let model = scanner.run(image, model)?;
    
    let builder = ControlFlowGraphBuilder::new();
    let model = builder.run(model)?;
    
    let analyzer = DataFlowAnalyzer::new();
    let model = analyzer.run(model)?;
    
    let converter = SsaConverter::new();
    let model = converter.run(model)?;
    
    let analyzer = FunctionCallAnalyzer::new();
    let model = analyzer.run(model)?;
    
    // Return the final model
    Ok(model)
}

/// Run the analysis pipeline up to SSA conversion
pub fn run_analysis_ssa(image: Vec<i128>) -> Result<Model<SsaComplete>, Error> {
    // Create initial model
    let model = Model::<InitialState>::new().with_image(image.clone());
    
    // Run each analysis phase in sequence up to SSA
    let scanner = ImageScanner::new();
    let model = scanner.run(image, model)?;
    
    let builder = ControlFlowGraphBuilder::new();
    let model = builder.run(model)?;
    
    let analyzer = DataFlowAnalyzer::new();
    let model = analyzer.run(model)?;
    
    let converter = SsaConverter::new();
    let model = converter.run(model)?;
    
    // Return the model with SSA complete
    Ok(model)
}
