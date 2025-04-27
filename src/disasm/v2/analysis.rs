use crate::disasm::{
    v2::{listeners::image_scanner::ImageScanner, model::ProgramModel},
    Error,
};
use colored::Colorize;

use super::{
    dispatching::EventPublisher,
    events::Event,
    listeners::{
        control_flow_analyzer::ControlFlowStructureRecoveryListener,
        control_flow_graph_builder::ControlFlowGraphBuilder, data_flow_analyzer::DataFlowAnalyzer,
        function_call_analyzer::FunctionCallAnalyzer, hlr_optimization::HlrOptimizationListener,
        image_scanner::ImageScannerResult, ssa_converter::SsaConverter,
        variable_analyzer::VariableAnalyzer,
    },
    pretty_print::{pretty_print_ssa, pretty_print_with_types},
    type_inference::TypeInferenceAnalyzer,
};
use crate::disasm::hlr::ast::pretty_print_program;

/// Run the analysis pipeline and print data flow information
pub fn run_analysis(image: Vec<i128>) {
    let mut model = ProgramModel::new();
    let mut publisher = EventPublisher::<Event, ProgramModel>::new();
    publisher.add_listener(Box::new(ImageScanner::new()));
    publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
    publisher.add_listener(Box::new(DataFlowAnalyzer::new()));
    publisher.add_listener(Box::new(SsaConverter::new()));
    publisher.add_listener(Box::new(FunctionCallAnalyzer::new()));
    publisher.add_listener(Box::new(TypeInferenceAnalyzer::new()));
    publisher.add_listener(Box::new(VariableAnalyzer::new()));
    publisher.add_listener(Box::new(ControlFlowStructureRecoveryListener::new()));
    publisher.add_listener(Box::new(HlrOptimizationListener::new()));
    model.load_image(&image, &mut publisher);
    let res = publisher.process_events(&mut model);
    match res {
        Ok(_) => {
            // pretty_print_with_vars(&model);
        }
        Err(e) => {
            eprintln!("\nError: {}", e.to_string().red().bold());
            if let Error::TypeConflict {
                key,
                partial_result,
                ..
            } = e
            {
                eprintln!("\n{}", partial_result.format_traces_for_var(key));
            }
        }
    }
}

pub fn run_types(image: Vec<i128>) {
    let mut model = ProgramModel::new();
    let mut publisher = EventPublisher::<Event, ProgramModel>::new();
    publisher.add_listener(Box::new(ImageScanner::new()));
    publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
    publisher.add_listener(Box::new(DataFlowAnalyzer::new()));
    publisher.add_listener(Box::new(SsaConverter::new()));
    publisher.add_listener(Box::new(FunctionCallAnalyzer::new()));
    publisher.add_listener(Box::new(TypeInferenceAnalyzer::new()));
    model.load_image(&image, &mut publisher);
    let res = publisher.process_events(&mut model);
    match res {
        Ok(_) => {
            pretty_print_with_types(&model);
        }
        Err(e) => {
            eprintln!("\nError: {}", e.to_string().red().bold());
            if let Error::TypeConflict {
                key,
                partial_result,
                ..
            } = e
            {
                eprintln!("\n{}", partial_result.format_traces_for_var(key));
            }
        }
    }
}

/// Run the analysis pipeline up to and including control flow structure recovery
pub fn run_flow_recovery(image: Vec<i128>) {
    let mut model = ProgramModel::new();
    let mut publisher = EventPublisher::<Event, ProgramModel>::new();
    publisher.add_listener(Box::new(ImageScanner::new()));
    publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
    publisher.add_listener(Box::new(DataFlowAnalyzer::new()));
    publisher.add_listener(Box::new(SsaConverter::new()));
    publisher.add_listener(Box::new(FunctionCallAnalyzer::new()));
    publisher.add_listener(Box::new(TypeInferenceAnalyzer::new()));
    publisher.add_listener(Box::new(VariableAnalyzer::new()));
    publisher.add_listener(Box::new(ControlFlowStructureRecoveryListener::new()));
    model.load_image(&image, &mut publisher);
    let res = publisher.process_events(&mut model);
    match res {
        Ok(_) => {
            if let Some(hlr_program) = model.get_hlr_program() {
                println!("{}", pretty_print_program(hlr_program));
            } else {
                println!("No HLR program was generated.");
            }
        }
        Err(e) => {
            eprintln!("\nError: {}", e.to_string().red().bold());
            if let Error::TypeConflict {
                key,
                partial_result,
                ..
            } = e
            {
                eprintln!("\n{}", partial_result.format_traces_for_var(key));
            }
        }
    }
}

pub fn disassemble(image: Vec<i128>) -> ImageScannerResult {
    let mut model = ProgramModel::new();
    let mut publisher = EventPublisher::<Event, ProgramModel>::new();
    publisher.add_listener(Box::new(ImageScanner::new()));
    model.load_image(&image, &mut publisher);
    publisher
        .process_events(&mut model)
        .expect("Failed to process events");
    model.get_image_scanner_result().clone()
}

/// Run the analysis pipeline and print the program in SSA form
pub fn run_analysis_ssa(image: Vec<i128>) {
    let mut model = ProgramModel::new();
    let mut publisher = EventPublisher::<Event, ProgramModel>::new();

    publisher.add_listener(Box::new(ImageScanner::new()));
    publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
    publisher.add_listener(Box::new(DataFlowAnalyzer::new()));
    publisher.add_listener(Box::new(SsaConverter::new()));
    publisher.add_listener(Box::new(FunctionCallAnalyzer::new()));

    // Process the image
    model.load_image(&image, &mut publisher);
    publisher
        .process_events(&mut model)
        .expect("Failed to process events");

    // Check if data flow analysis was completed
    if model.get_data_flow_result().is_none() {
        println!("No SSA form available due to missing data flow analysis");
    }

    // Pretty-print the SSA form
    pretty_print_ssa(&model);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_analysis_executes_without_panic() {
        // Define a minimal valid Intcode program (e.g., addition then halt)
        let sample_image = vec![109, 1, 21101, 3, 2, -3, 99];

        // Call the function. Since it doesn't return anything or have observable
        // side effects in its current state (doesn't call process_events),
        // the primary test is that it completes without panicking.
        run_analysis(sample_image);
    }

    // Add more specific tests here as the functionality evolves.
    // For example, testing the behavior of ImageScanner would require:
    // 1. Modifying `run_analysis` to call `publisher.process_events()`.
    // 2. Modifying `run_analysis` to return the `ProgramModel` after processing.
    // 3. Adding assertions based on the expected state of the model after
    //    ImageScanner processes the ImageAddedEvent.
    /*
    #[test]
    fn test_image_scanner_effect() {
        // Setup: Create an image that ImageScanner should react to
        let specific_image = vec![/* ... */];

        // Action: Run the analysis (assuming it processes events and returns model)
        // let final_model = run_analysis(specific_image); // Hypothetical return

        // Assert: Check the model for expected changes made by ImageScanner
        // assert_eq!(final_model.some_field, expected_value);
    }
    */
}
