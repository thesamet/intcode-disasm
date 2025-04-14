// Declare the submodules
pub mod analyzer;
pub mod constraints;
pub mod result;
pub mod solver;
pub mod tests;
pub mod types;
pub mod visuals;

// Re-export key types and functions for external use
pub use analyzer::TypeInferenceAnalyzer;
pub use result::TypeInferenceResult;
pub use solver::TypeInferenceError;
pub use types::Type;