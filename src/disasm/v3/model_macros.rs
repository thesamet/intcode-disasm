// our goal is to build an abstraction for defining models that
// track data as analysis progresses.
// Each phase in the pipelien takes a model at a certain state
// Model<S1> and returns the model in a new state <S2> where
// S2 contains all the data of S1 (unmodified) and has additional
// data. One goal is to provide compile time dependency of what
// can each phase access and what data they provide.
//
// Models are immutable.
//
// The definition would work like this:
// User defines marker type for their model
trait ModelState {}

// User defines data types that are available in each state.
// There is always an implicit InitialState.

pub struct FirstPassResults {
    pub x: u32,
    pub y: u32,
}

struct SecondPassResults {
    pub z: u32,
}

struct AggregationResults {
    pub w: u32,
}

struct FinalResult {
    pub s: String,
}

// Then a user defines a model has follows:

create_model!(Model, ModelState, {
    InitialState(()),
    FirstPassComplete(FirstPassResult),
    SecondPassComplete(SecondPassResult),
    AggregationComplete(AggregationResult),
    FinalResult(FinalResult),
});

// This will enable the following usages:

// Create a model in ititial state. From the users point
// of view only models at Initial state can be created. Internally
// we should be able to create a model at any state since they are
// immutable and we need to allow transitions.
fn create_model() -> Model<InitialState> {
    let new_model: Model<InitialState> = Model::new(());
}

fn run_first_pass(model: Model<InitialState>) -> Model<FirstPassComplete> {
    let new_model: Model<FirstPassComplete> =
        // transitions the model to FirstPassComplete.
        // consumes the model, so data can be moved to the new model
        // without cloning.
        model.with_first_pass_results(FirstPassResults { x: 1, y: 2 });
}

fn run_second_pass(model: Model<FirstPassComplete>) -> Model<SecondPassComplete> {
    // Note that this returns an immutable reference to a value inside the model.
    // We never return immutable references to the model or anything
    // within the model.
    let first_pass_results: &FinalResult = model.first_pass_result();
    let second_pass_results = SecondPassResults {
        z: inputs.x + inputs.y,
    };
    let new_model: Model<SecondPassComplete> = model.with_second_pass_results(second_pass_results);
}

fn run_aggregation_pass(model: Model<SecondPassComplete>) -> Model<AggregationComplete> {
    // Note that we can can get references for all the previous results, not just the last one:
    let first_pass_results: &FirstPassResults = model.first_pass_result();
    let second_pass_results: &SecondPassResults = model.second_pass_result();
    let aggregation_results = AggregationResults {
        w: first_pass_results.x + first_pass_results.y + second_pass_results.z,
    };
    let new_model: Model<AggregationComplete> = model.with_aggregation_results(aggregation_results);
}

// Automated hazzers generation
// Sometimes we want to implement methods that can run at all phases from one
// phase forward. For example, if I want to implement a method that can be called
// from all states after the including SecondPassComplete, I can do this:

fn method<S: ModelState>(model: Model<K>) -> u32
where
    S: Has<SecondPassResults>,
{
    let second_pass_results: &SecondPassResults = model.second_pass_result();
    // The following line because we have not requested AggregationResults
    // code:
    // let aggregation_results: &AggregationResults = model.aggregation_result();
    //
    // The following line also does not compile, even though the first phase comes
    // before the second phase. It doesn't compile because we haven't included the Has
    //
    // let first_pass_results: &FirstPassResults = model.first_pass_result();
}

// How would you implement this AI?
