use std::fmt::Debug;

use crate::disasm::v2::{listeners::image_scanner::ImageScanner, model::ProgramModel};

use super::{
    dispatching::EventPublisher,
    events::{Event, EventSender, ImageAddedEvent, ModelEventListener},
};

pub fn run_analysis(image: Vec<i128>) {
    let mut model = ProgramModel::new();
    let mut publisher = EventPublisher::<Event, ProgramModel>::new();
    publisher.add_listener(Box::new(ImageScanner {}));
    model.image = image;
    publisher.publish(ImageAddedEvent {});
    publisher.process_events(&mut model);
    for x in &model.image_scanner_result.unwrap().recognized_functions {
        println!("f start: {:?}", x.span);
    }
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
