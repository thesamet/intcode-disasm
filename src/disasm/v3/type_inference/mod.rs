//! Type inference system for the V3 decompiler.

pub mod constraints;
mod constraints_generator;
pub mod query_engine;
mod result;
mod solver;
pub mod type_bounds_map;
mod type_interval;
mod types;

pub use constraints::ConstraintStore;
pub use constraints::{Constraint, ConstraintReason};
pub use constraints_generator::generate_constraints;
pub use query_engine::TypeInferenceQueryEngine;
pub use result::TypeInferenceResult;
pub use solver::Solver;
pub use type_bounds_map::{InferenceAlgorithmState, TypeVarState};
pub use types::Type;

mod type_inference_tests;
