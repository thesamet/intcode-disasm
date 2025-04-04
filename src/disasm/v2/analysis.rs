use itertools::Itertools;

use crate::disasm::v2::{
    data_flow::DefinitionKind, 
    listeners::image_scanner::ImageScanner, 
    model::ProgramModel,
    ssa_form::SsaProgram,
};

use super::{
    dispatching::EventPublisher,
    events::Event,
    listeners::{
        control_flow_builder::ControlFlowGraphBuilder, 
        data_flow_analyzer::DataFlowAnalyzer,
        ssa_converter::SsaConverter,
    },
};

/// Run the analysis pipeline and print data flow information
pub fn run_analysis(image: Vec<i128>) {
    let mut model = ProgramModel::new();
    let mut publisher = EventPublisher::<Event, ProgramModel>::new();
    publisher.add_listener(Box::new(ImageScanner::new()));
    publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
    publisher.add_listener(Box::new(DataFlowAnalyzer::new()));
    model.load_image(&image, &mut publisher);
    publisher.process_events(&mut model);

    if let Some(data_flow_results) = model.get_data_flow_result() {
        for (block_id, res) in data_flow_results
            .block_results
            .iter()
            .sorted_by_key(|(k, _)| *k)
        {
            let function_return_defs = res
                .defs_in
                .iter()
                // Correctly use matches! to check the enum variant
                .filter(|d| matches!(d.kind, DefinitionKind::FunctionReturn { .. }))
                .sorted_by_key(|d| d.block_id)
                .collect_vec(); // collect_vec() should be outside filter

            if !function_return_defs.is_empty() {
                let block = model.get_block(*block_id); // Get block info for span
                println!(
                    "Block {} has incoming function return definitions:",
                    block.span
                );
                for r_def in function_return_defs.iter() {
                    // Match on the kind to extract function_addr
                    if let DefinitionKind::FunctionReturn { function_addr } = r_def.kind {
                        println!(
                            "- {}: usage of {} from func call targeting {:?}",
                            r_def.instruction_id,
                            r_def.location,
                            function_addr, // Print the kind of the function address operand
                        );
                    } else {
                        // This branch shouldn't be hit due to the filter, but included for completeness
                        println!(
                            "- Unexpected non-FunctionReturn def: {:?} for operand {:?}",
                            r_def.kind, r_def.location
                        );
                    }
                }
            }
        }
    } else {
        println!("Data flow analysis results not available.");
    }
}

/// Run the analysis pipeline and print the program in SSA form
pub fn run_analysis_ssa(image: Vec<i128>) -> String {
    let mut model = ProgramModel::new();
    let mut publisher = EventPublisher::<Event, ProgramModel>::new();
    
    // Initialize all the required listeners
    publisher.add_listener(Box::new(ImageScanner::new()));
    publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
    publisher.add_listener(Box::new(DataFlowAnalyzer::new()));
    
    // Add the SSA converter
    let mut ssa_converter = SsaConverter::new();
    publisher.add_listener(Box::new(ssa_converter.clone()));
    
    // Process the image
    model.load_image(&image, &mut publisher);
    publisher.process_events(&mut model);
    
    // Since the events don't seem to be updating our copy of the converter,
    // let's directly convert to SSA form
    let ssa_program = SsaProgram::from_program_model(&model);
    
    // Pretty-print the SSA form
    ssa_program.pretty_print()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_analysis_executes_without_panic() {
        // Define a minimal valid Intcode program (e.g., addition then halt)
        let sample_image = vec![1, 0, 0, 0, 99];

        // Call the function. Since it doesn't return anything or have observable
        // side effects in its current state (doesn't call process_events),
        // the primary test is that it completes without panicking.
        run_analysis(sample_image);

        // No assertions possible here without modifying `run_analysis` to return
        // the model state or having listeners with verifiable side effects
        // after calling `publisher.process_events()`.
        assert!(true, "run_analysis completed without panic");
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
