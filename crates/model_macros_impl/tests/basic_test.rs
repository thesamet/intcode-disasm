#[cfg(test)]
mod tests {
    use model_macros_impl::{model, states};

    pub struct InitialData {
        pub vec: Vec<u32>,
    }

    // Define test state data
    pub struct FirstPassResult {
        pub x: u32,
        pub y: u32,
    }

    pub struct SecondPassResult {
        pub z: u32,
    }

    pub struct AggregationResult {
        pub w: u32,
    }

    pub struct FinalSummary {
        pub s: String,
    }

    // Define states
    #[states]
    enum ModelState {
        InitialState(InitialData),
        FirstPassComplete(FirstPassResult),
        SecondPassComplete(SecondPassResult),
        AggregationComplete(AggregationResult),
        Done(FinalSummary),
    }

    // Test Model
    // The `#[model]` macro will now automatically add `_state: PhantomData<S>`
    #[model]
    pub struct Model<S: ModelState> {}

    fn test_handle_model<S: ModelState + HasAggregationResult>(model: &Model<S>) -> u32 {
        model.aggregation_result().w + model.first_pass_result().x
    }

    #[test]
    fn test_state_transitions() {
        // Create a model in the initial state
        let model = Model::new(InitialData { vec: vec![1, 2, 3] });

        // Transition to FirstPassComplete
        let model = model.with_first_pass_result(FirstPassResult { x: 42, y: 24 });

        // Verify we can access first pass results
        assert_eq!(model.first_pass_result().x, 42);
        assert_eq!(model.initial_data().vec.len(), 3); // Still access initial data

        // Transition to SecondPassComplete
        let model = model.with_second_pass_result(SecondPassResult { z: 99 });

        // Verify we can still access first pass results
        assert_eq!(model.first_pass_result().x, 42);
        assert_eq!(model.first_pass_result().y, 24);
        assert_eq!(model.initial_data().vec.len(), 3); // Still access initial data

        // Transition to AggregationComplete
        let model = model.with_aggregation_result(AggregationResult { w: 100 });

        // Verify we can access all previous results
        assert_eq!(model.first_pass_result().x, 42);
        assert_eq!(model.first_pass_result().y, 24);
        assert_eq!(model.aggregation_result().w, 100);
        assert_eq!(model.initial_data().vec.len(), 3); // Still access initial data

        // Transition to Done
        let model = model.with_final_summary(FinalSummary {
            s: "Done".to_string(),
        });

        // Verify we can access all results
        assert_eq!(model.first_pass_result().x, 42);
        assert_eq!(model.first_pass_result().y, 24);
        assert_eq!(model.aggregation_result().w, 100);
        assert_eq!(model.final_summary().s, "Done");
        assert_eq!(model.initial_data().vec.len(), 3); // Still access initial data
        assert_eq!(model.second_pass_result().z, 99);
        assert_eq!(test_handle_model(&model), 142);
    }

    #[test]
    fn test_has_trait() {
        let model = Model::new(InitialData { vec: vec![1, 2, 3] });

        // Verify we can access the initial data
        assert_eq!(model.initial_data().vec.len(), 3);
    }
}
