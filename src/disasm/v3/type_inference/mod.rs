//! Type inference system for the V3 decompiler.

mod result;
mod solver;

pub use result::TypeInferenceResult;
pub use solver::Solver;
