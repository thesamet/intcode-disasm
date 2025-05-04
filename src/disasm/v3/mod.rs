pub mod analysis;
pub mod common;
pub mod control_flow;
pub mod data_flow;
pub mod function_call;
pub mod id_types;
pub mod image_scanner;
pub mod listeners;
pub mod model;
pub mod native; // Added native module
pub mod ssa;

// Re-export common types
pub use common::{FunctionCall, Span};
pub use control_flow::Function;
pub use control_flow::{Block, NextKind, PredecessorKind};
pub use id_types::*;
