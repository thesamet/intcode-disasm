pub mod analysis;
pub mod common;
pub mod control_flow;
pub mod data_flow;
pub mod function_call;
pub mod id_types;
pub mod image_scanner;
pub mod lir; // Added LIR module
pub mod listeners;
pub mod model;
pub mod native;
pub mod ssa;

// Re-export common types (Removed LIR types)
pub use common::Span; // Keep Span if it's truly common
pub use control_flow::Function;
pub use control_flow::{Block, NextKind, PredecessorKind};
pub use id_types::*;
// Note: FunctionCall might belong in LIR or HLR depending on usage
pub use common::FunctionCall;
