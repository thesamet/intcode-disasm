//! Type inference system for the V3 decompiler.

pub mod constraints;
mod constraints_generator;
mod result;
mod solver;
pub mod type_bounds_map;
mod types;

pub use constraints::ConstraintStore;
pub use constraints::{Constraint, ConstraintReason};
pub use result::TypeInferenceResult;
pub use solver::Solver;
pub use type_bounds_map::{InferenceAlgorithmState, TypeVarState};
pub use types::ExpressionPathElement;
pub use types::Type;
pub use types::{TypeVarId, TypeVarPath};

#[cfg(test)]
mod type_inference_tests;
