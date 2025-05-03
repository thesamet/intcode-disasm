pub mod model;
pub mod id_types;
pub mod common;
pub mod image_scanner;
pub mod control_flow;
pub mod data_flow;
pub mod ssa;
pub mod function_call;
pub mod listeners;

// Re-export common types
pub use common::Span;
pub use id_types::{BlockId, FunctionId, InstructionId};
