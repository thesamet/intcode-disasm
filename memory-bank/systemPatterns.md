# System Patterns *Optional*

This file documents recurring patterns and standards used in the project.
It is optional, but recommended to be updated as the project evolves.
2025-05-19 09:25:10 - Log of updates made.

*

## Coding Patterns

* Following the conventions outlined in src/docs/conventions.md:
  - Using snake_case for functions, variables, and module names
  - Following standard Rust error handling with Result types and thiserror
  - Using descriptive variable names that reflect their purpose
  - Preferring strong typing with custom types/enums over primitive types
  - Keeping functions focused on a single responsibility
  - Organizing imports with std first, then external crates, then internal modules
  - Using the log crate for structured logging with appropriate log levels
  - Preferring itertools:Itertools for more concise code (e.g., collect_vec())
  - Avoiding trivial comments where code is self-explanatory
  - Avoiding repetition through helper functions and abstractions
  - Using early returns from functions when requirements are not met
  - Taking references in APIs whenever possible
  - Passing id types (BlockId, FunctionId, etc.) by reference

## Architectural Patterns

* Pipeline architecture with distinct analysis stages
* Each analysis stage builds on the results of previous stages
* Clear separation between different representations (native, LIR, SSA)
* Hierarchical access to functions and blocks through the model (model.function(&function_id).block(&block_id).ssa())
* Result structures that contain the analysis output separate from the model
* Use of Rust's type system to enforce analysis pipeline stages (e.g., Model<FunctionCallAnalysisComplete>)

## Testing Patterns

* Creating unit tests in a tests module with #[test] attribute
* Using test with logs via cargo test -- --nocapture or the test-log feature
* End-to-end tests with sample programs

2025-05-19 09:25:10 - Initial creation of systemPatterns.md based on conventions.md and observed patterns in the codebase.