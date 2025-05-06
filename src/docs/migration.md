We are migration the various analyzers from v2 into v3. Principles:

- We want to move the code as closely as possible to the original form, but only
- adjust to the new Model format (in `v3/models.rs`)
- Only minor local modifications, cleanups or slight improvements should be done at this point.
- You must move all the existing tests on the analyzer being requested to move into v3.
- IMPRTANT: The tests should be identical. Same test names, same programs inside, and the same coverage of assertions. If a way to test the assertion is missing in v3, do not add a lot of logic within the test and do not give up on testing the same assertions. Instead, assume we follow the lines of v2, add a similar call that will fail, and in the next phase we will add what's missing for v3 design.
- In case there are errors when using v2 entities mixed up with v3 entities, which are probably identical (such as BlockId, Span), we will delete the v2 entity, and add the correct "pub use" in the respective mod.rs to forward it to the v3 instance.
- Building on the previous comment, v3 should be standalone and not use v2.
- Again, please keep the logic and flow identical to the original.
- Testing is done using:
  - The `cargo test` command
  - Building:
  - The `cargo build`
  - Ignore the warnings we have in the code, but fix the tests. Focus on the migration, the code does not need to have any other changes to migrate.
- In v3 blocks are not directly on the model, but provided through FunctionView. To access graph build
  blocks do `model.function(&function_id).block(&block_id)`. Prefer having a reference of the Function
  we are processing as a local variable.
- In v3, function.block(&block_id) gives a BlockView, which has ssa(), data_flow() to access the analyzer outputs
  of earlier phasees. Previously, in v2, those things were accessed directly on the model. Now it's supposed
  to be more convenient since we usually have a reference to the block or function around.
- In v3, we get a function view by id through the model (model.function(&function_id) and model.functions() to iterate over ids and function views. Similarly with func.block(&block_id) to get a block view, and func.blocks() for the corresponding iterator. Note that with FunctionView and BlockView the base-accessors from the original code are functions and not fields, so it is block.block_id(), function.stack_size(), etc)
- On id_types: to create a new instance of an id type: PointerId::new(usize) or FunctionId::new(usize). The usize inside is meant to be opaque and rarly is pulled out using the index() method.
- Do not add new assertions based on the logic of the algorithm as the algorithms are intricate and hard to analyze without proper debugging. Add new assertions only when the expectation is obvious and the assertion is useful for coverage.
- v2 Ids and V3 Ids are the same types. There's no such thing as a "v2 id".
- Specifically, "let v2_function_id = FunctionId::new(self.function.function_id().index());" doesn't make sense as the ids are the same. This is the same as self.function.function_id()`
- If a function pre-migration took a FunctionId or BlockId only to look up in the model, it's preferred to change the function to take a FunctionView<S> or BlockView<S>.
- NextKind is only in v3. There's no V2 nextkind. Same from PredecessorKind and FunctionCall. They are all in v3/common
