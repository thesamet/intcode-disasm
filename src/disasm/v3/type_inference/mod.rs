//! Type inference system for the V3 decompiler.

mod analyzer;
pub mod constraints;
mod result;
mod solver;
pub mod type_bounds_map;
mod types;

pub use analyzer::TypeInferenceAnalyzer;
pub use constraints::ConstraintStore;
pub use constraints::{Constraint, ConstraintReason};
pub use result::TypeInferenceResult;
pub use solver::Solver;
pub use type_bounds_map::{InferenceAlgorithmState, TypeVarState};
pub use types::Type;

mod type_inference_tests;
