# Project conventions

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build/Lint/Test Commands

- Build: `cargo build`
- Run: `cargo run`
- Test all: `cargo test`
- Test single test: `cargo test test_name`
- Test with logs: `cargo test -- --nocapture` or use `test-log` feature
- Lint: `cargo clippy`
- Format: `cargo fmt`

- The current name of the project is disasm.

## Code Style Guidelines

- Use snake_case for functions, variables, and module names
- Follow standard Rust error handling with Result types and thiserror
- Create unit tests in a `tests` module with `#[test]` attribute
- Use descriptive variable names that reflect their purpose
- Prefer strong typing with custom types/enums over primitive types
- Keep functions focused on a single responsibility
- Organize imports with std first, then external crates, then internal modules
- Use the log crate for structured logging with appropriate log levels
- Prefer using itertools:Itertools if it makes the code more concise. For example use `collect_vec()` instead of `collect::<T>()`
- Don't add trivial comments where it's obvious what the code does
- Avoid long fully-qualified names, unless they help disambiguate (mod1::Entity, mod2::Entity). Prefer a "use statement" at the top.
- We do not like repetition. Find ways to avoid code duplication by creating helper functions or abstractions. However, not at the expense of readability and maintainability of the code.
- Leverage external crates if they provide functionality we need.
- Prefer early exits from functions when a requirement is not meant rather than creating nesting levels. For example, instead of

Early returns:

```rust
fn bad_example(&self, v: Value) -> Option<Finding> {
  if self.is_valid(v) {
    if v > 0 {
      // do something
    } else {
      panic!("v must be positive")
    }
  } else {
    None
  }
}

Do this:

fn good_example(&self, v: Value) -> Option<Finding> {
  if !self.is_valid(v) {
    return None;
  }
  if v <= 0 {
    panic!("v must be positive")
  }
  // do something
}

```

- APIs should prefer taking references whenever possible to prevent the caller from calling.
- All id types (BlockId, FunctionId, and so on) are passed by reference.

```rust

## Intcode

- Basic information about the virtual machine is in src/docs/machine_arch.md and must be understood.
```

## Model, BlockView and FunctionView

- Access functions and blocks hierarchically through the model, not through model.ssa_result(), model.data_flow(). Instead model.function(&function_id).block(&block_id).ssa(). Those helper functions return a reference (with the lifetime of the model they are within) and panic if the id is not found.

## Changes and refactoring

- When refactoring, do not leave comments about what was there before the refactoring, or what you just added. For example, do not add command such as "// added XYZ field.", or "// We previously constrained X to be Y, but this is not correct".
- If you encounter a private function that can be used in the change, suggest making it public. There is a high chance that this change will be welcome.
- When working in a conversational mode as an assistance in a text editor, when asked to modify a function or a part of a file, provide only the diffs, not the whole file.
