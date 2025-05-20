//! Type inference system for the V3 decompiler.

mod analyzer;
mod result;
mod solver;
mod types;
pub mod type_bounds_map;
pub mod constraints;

pub use analyzer::TypeInferenceAnalyzer;
pub use result::TypeInferenceResult;
pub use solver::Solver;
pub use types::Type;
pub use type_bounds_map::{InferenceAlgorithmState, TypeVarState};
pub use constraints::{Constraint, ConstraintReason};
pub use constraints::ConstraintStore;
