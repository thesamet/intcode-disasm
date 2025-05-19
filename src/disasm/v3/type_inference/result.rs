//! Type inference result data structure.

use std::collections::HashMap;

use crate::disasm::v3::FunctionId;

/// Result of the type inference analysis.
#[derive(Debug, Clone, Default)]
pub struct TypeInferenceResult {
    /// Maps function IDs to their inferred types.
    /// This is a placeholder for now, will be expanded with actual type information.
    pub function_types: HashMap<FunctionId, ()>,
}

impl TypeInferenceResult {
    /// Create a new empty type inference result.
    pub fn new() -> Self {
        Self::default()
    }
}