//! Type inference result data structure.

use std::collections::HashMap;

use itertools::Itertools;
use log::debug;

use crate::disasm::v3::ssa::SsaMemoryReference;

use super::type_bounds_map::{ChangeLogEntry, TypeVarRegistry};
use super::types::{Type, TypeVarId, TypeVarNode};
use super::{ConstraintStore, TypeInferenceQueryEngine, TypeVarState};

/// Stores inferred type information for a single function.
#[derive(Debug, Clone)]
pub struct FunctionTypeInfo {
    /// Maps SSA variables to their inferred types.
    pub _var_types: HashMap<SsaMemoryReference, Type>,
}

impl FunctionTypeInfo {
    /// Creates a new empty `FunctionTypeInfo`.
    pub fn new() -> Self {
        Self {
            _var_types: HashMap::new(),
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
    pub type_var_states: HashMap<TypeVarId, TypeVarState>,
    pub type_var_nodes: HashMap<TypeVarId, TypeVarNode>,
    pub mem_ref_to_type_var_id: HashMap<SsaMemoryReference, TypeVarId>,
    pub debug_markers: HashMap<char, TypeVarId>,
    pub query_engine: TypeInferenceQueryEngine,
    pub change_log: Vec<ChangeLogEntry>,
    pub constraint_store: ConstraintStore,
    pub generic_type_vars: HashMap<super::types::GenericTypeVarId, super::types::GenericTypeVar>,
}

impl TypeInferenceResult {
    /// Create a new empty type inference result.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_marker_type(&self, marker: char) -> Option<Type> {
        self.debug_markers.get(&marker).and_then(|typ| {
            match self.type_var_states.get(typ).unwrap() {
                v @ TypeVarState::Bounds { .. } => {
                    debug!(
                        "Type of marker {} has not converged: {}",
                        marker,
                        v.display_with(self)
                    );
                    None
                }
                TypeVarState::Converged(ty) => Some(ty.clone()),
            }
        })
    }

    pub fn get_all_inferred_types(&self) -> Vec<(TypeVarNode, Type)> {
        self.type_var_states
            .iter()
            .filter_map(|(id, state)| {
                if let TypeVarState::Converged(ty) = state {
                    Some((self.type_var_nodes.get(id).cloned().unwrap(), ty.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn print_all_type_bounds(&self) {
        for (id, state) in self.type_var_states.iter().sorted_by_key(|(id, _)| *id) {
            match state {
                v @ TypeVarState::Bounds { .. } => {
                    println!(
                        "{:<5} {} ∈ {}", // Restored original format string
                        id,
                        id.display_with(self),
                        v.display_with(self)
                    );
                }
                TypeVarState::Converged(ty) => {
                    println!(
                        "{:<5} {} == {:<20}",
                        id,
                        id.display_with(self),
                        ty.display_with(self)
                    );
                }
            }
        }
    }

    pub fn get_type_id_for(&self, t: SsaMemoryReference) -> TypeVarId {
        self.mem_ref_to_type_var_id
            .get(&t)
            .cloned()
            .unwrap_or_else(|| panic!("No type var for {}", t))
    }

    pub fn get_type_for(&self, t: SsaMemoryReference) -> Type {
        let tv_id = self.get_type_id_for(t);
        self.get_type_for_id(tv_id)
    }

    pub fn get_type_for_id(&self, t: TypeVarId) -> Type {
        match self.type_var_states.get(&t).unwrap() {
            TypeVarState::Converged(t) => t.clone(),
            TypeVarState::Bounds { .. } => Type::Any,
        }
    }

    pub fn type_id_for_node(&self, t: TypeVarNode) -> TypeVarId {
        *self.type_var_nodes.iter().find(|x| *x.1 == t).unwrap().0
    }
}

impl TypeVarRegistry for TypeInferenceResult {
    fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode> {
        self.type_var_nodes.get(tv_id)
    }
    fn get_type_var_state(&self, tv_id: &TypeVarId) -> Option<&TypeVarState> {
        self.type_var_states.get(tv_id)
    }
    fn get_generic_type_var(&self, id: &super::types::GenericTypeVarId) -> Option<&super::types::GenericTypeVar> {
        self.generic_type_vars.get(id)
    }
}
