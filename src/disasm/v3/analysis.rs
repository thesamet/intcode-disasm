use super::{
    model::{Model, InitialState},
    image_scanner::ImageScanner,
    control_flow::ControlFlowGraphBuilder,
    data_flow::DataFlowAnalyzer,
    ssa::SsaConverter,
    function_call::FunctionCallAnalyzer,
};

use crate::disasm::{
    dispatching::EventPublisher,
    events::Event,
    Error,
};

/// Run the complete analysis pipeline
pub fn run_analysis(image: Vec<i128>) -> Result<(), Error> {
    let mut model = Model::<InitialState>::new();
    let mut publisher = EventPublisher::<Event, Model<InitialState>>::new();
    
    // Register all listeners in the pipeline order
    publisher.add_listener(Box::new(ImageScanner::new()));
    publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
    publisher.add_listener(Box::new(DataFlowAnalyzer::new()));
    publisher.add_listener(Box::new(SsaConverter::new()));
    publisher.add_listener(Box::new(FunctionCallAnalyzer::new()));
    
    // Future listeners can be added here:
    // publisher.add_listener(Box::new(TypeInferenceAnalyzer::new()));
    // publisher.add_listener(Box::new(VariableAnalyzer::new()));
    
    // Start the analysis by loading the image
    // This would trigger the first event
    
    // Process all events
    publisher.process_events(&mut model)
}

/// Run the analysis pipeline up to SSA conversion
pub fn run_analysis_ssa(image: Vec<i128>) -> Result<(), Error> {
    let mut model = Model::<InitialState>::new();
    let mut publisher = EventPublisher::<Event, Model<InitialState>>::new();
    
    publisher.add_listener(Box::new(ImageScanner::new()));
    publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
    publisher.add_listener(Box::new(DataFlowAnalyzer::new()));
    publisher.add_listener(Box::new(SsaConverter::new()));
    
    // Process all events
    publisher.process_events(&mut model)
}
