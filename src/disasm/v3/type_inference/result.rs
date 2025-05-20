//! Type inference result data structure.

use std::collections::HashMap;

use crate::disasm::v3::ssa::SsaMemoryReference;
use crate::disasm::v3::FunctionId;

use super::types::{Type, TypeVarId};
use super::TypeVarState;

/// Stores inferred type information for a single function.
#[derive(Debug, Clone)]
pub struct FunctionTypeInfo {
    /// Maps SSA variables to their inferred types.
    pub var_types: HashMap<SsaMemoryReference, Type>,
}

impl FunctionTypeInfo {
    /// Creates a new empty `FunctionTypeInfo`.
    pub fn new() -> Self {
        Self {
            var_types: HashMap::new(),
        }
    }
}

impl Default for FunctionTypeInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of the type inference analysis.
#[derive(Debug, Clone, Default)]
pub struct TypeInferenceResult {
    pub type_vars: HashMap<TypeVarId, TypeVarState>,
    pub debug_markers: HashMap<char, TypeVarId>,
}

impl TypeInferenceResult {
    /// Create a new empty type inference result.
    pub fn new() -> Self {
        Self::default()
    }
}
