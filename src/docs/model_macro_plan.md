# Goal

our goal is to build an abstraction for defining models that
track data as analysis progresses.
Each phase in the pipeline takes a model at a certain state
Model<S1> and returns the model in a new state <S2> where
S2 contains all the data of S1 (unmodified) and has additional
data. One goal is to provide compile time dependency of what
can each phase access and what data they provide.

Models are immutable.

Let's first present the requirements in the form of a user story.

User wants an immutable compile-time safe model to represent
the state of a model as it progresses through the pipeline.
She starts by listing all the possible states that the model can be.

```rust
pub struct InitialState {}
pub struct FirstPassResult {
    pub x: u32,
    pub y: u32,
}

struct SecondPassResult {
    pub z: u32,
}

struct AggregationResult {
    pub w: u32,
}

struct FinalSummary {
    pub s: String,
}
```

The user then summarizes the set of states available and **their order** in the following enum:

```rust
#[states]
enum ModelState {
    InitialState(()),
    FirstPassComplete(FirstPassResult),
    SecondPassComplete(SecondPassResult),
    AggregationComplete(AggregationResult),
    Done(FinalSummary),
}
```

The intent here is that the model always instantiated into the first state (called here `InitialState`). Then transformations would take it
from one state to the next in the order in the enum. In each state
the model will have access to the state's data **and all previous states data**. For example, when we have `Model<SecondPassComplete>` it will have access to `SecondPassResults`, `FirstPassResults` and `()` - where the latter comes from `InitialState..

This will result in the macro generating a marker trait named `ModelState` - exactly the enum's name. There's no name mangling, no prefixes and no suffixes involved. The macro will inhibit the generation of the original enum since it's not necessary and will just conflict with the trait name.

The macro will generate marker structs for each state:

```rust
pub struct SecondPassComplete {}
impl ModelState for SecondPassCompete

// Trait that says a given a given state provides a data struct.
pub trait HasSecondPassResult {
    fn get_second_pass_result(&self) -> &SecondPassResult
}

impl HasSecondPassResult for SecondPassComplete
impl HasFirstPassResult for SecondPassComplete
```

Note that the name of the `Has` structs match the type of the data, not the name of the corresponding state.

Note that each state has `Has`ers also for the previous stastes leading to it.

Note that since InitialState takes a unit, so we do not generate a hasser for it.
Each variant in the given enum (`ModelState` in the example) will have a unique type - no need to validate it.

Note that if the initial state does take a type we need to create a has'er for it. Also, the generated constuctor
should take this type as a parameter to create the model in its initial state.

The user then defines the model struct:

```rust
#[model]
pub struct Model<S: ModelState> {}
```

There's always some type parameter. The key is the `: ModelState` type boundary which links this struct to the generated `ModelState` that must
be annotated with `#[states]`.

We can then use the model as follows:

# Create a model in ititial state. From the users point

// The user can only create models in their initial state. Internally
// we should be able to create a model at any state since they are
// immutable and we need to allow transitions.

```rust
fn create_model() -> Model<InitialState> {
    let new_model: Model<InitialState> = Model::new();
}
```

State transitions will be functions from one state to the next:

```rust
fn run_first_pass(model: Model<InitialState>) -> Model<FirstPassComplete> {
    let new_model: Model<FirstPassComplete> =
        // transitions the model to FirstPassComplete.
        // consumes the model, so data can be moved to the new model
        // without cloning.
        model.with_first_pass_results(FirstPassResults { x: 1, y: 2 });
}

fn run_second_pass(model: Model<FirstPassComplete>) -> Result<Model<SecondPassComplete>, SomeErrorType> {
    // Note that this returns an immutable reference to a value inside the model.
    // We never return immutable references to the model or anything
    // within the model.
    let first_pass_results: &FinalResult = model.first_pass_result();
    let second_pass_results = SecondPassResults {
        z: inputs.x + inputs.y,
    };
    Ok(model.with_second_pass_results(second_pass_results))
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
```

Note how getters return a reference and how they are named as snake_case of the type of the single unnamed argument of each variant in the input enum. Againt, the input enum is suppressed, it is replaced by a trait with the same name.

Using of the `Has`ers:

```rust
fn method<S: ModelState>(model: Model<K>) -> u32
where
    S: HasSecondPassResults,
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
```

# Internal representation

The internal representation of the state in the model struct will be nested tuples.
We will sketch the design.
