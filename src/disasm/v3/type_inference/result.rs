//! Type inference result data structure.

use std::collections::HashMap;

use itertools::Itertools;
use log::debug;

use crate::disasm::v3::ssa::{SsaMemoryReference, VersionedMemoryReference};

use super::type_bounds_map::TypeVarRegistry;
use super::type_interval::TypeInterval;
use super::types::{Type, TypeVarId, TypeVarKind, TypeVarNode};
use super::{TypeInferenceQueryEngine, TypeVarState};

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
    pub type_var_states: HashMap<TypeVarId, TypeVarState>,
    pub type_var_nodes: HashMap<TypeVarId, TypeVarNode>,
    pub mem_ref_to_type_var_id: HashMap<SsaMemoryReference, TypeVarId>,
    pub debug_markers: HashMap<char, TypeVarId>,
    pub query_engine: TypeInferenceQueryEngine,
}

impl TypeInferenceResult {
    /// Create a new empty type inference result.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_marker_type(&self, marker: char) -> Option<Type> {
        self.debug_markers.get(&marker).and_then(|typ| {
            match self.type_var_states.get(typ).unwrap() {
                TypeInterval::Bounds {
                    lower_bound,
                    upper_bound,
                } => {
                    debug!(
                        "Type of marker {} has not converged: [{}, {}]",
                        marker,
                        lower_bound.display_with(self),
                        upper_bound.display_with(self)
                    );
                    None
                }
                TypeInterval::Converged(ty) => Some(ty.clone()),
            }
        })
    }

    pub fn get_all_inferred_types(&self) -> Vec<(TypeVarKind, Type)> {
        self.type_var_states
            .iter()
            .filter_map(|(id, state)| {
                if let TypeInterval::Converged(ty) = state {
                    Some((
                        self.type_var_nodes.get(id).unwrap().kind.clone(),
                        ty.clone(),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn print_all_type_bounds(&self) {
        for (id, state) in self.type_var_states.iter().sorted_by_key(|(id, _)| *id) {
            match state {
                TypeInterval::Bounds {
                    lower_bound,
                    upper_bound,
                } => {
                    println!(
                        "{:?<50} ∈ [{:<20}, {:<20}]", // Restored original format string
                        id.display_with(self),
                        lower_bound.display_with(self),
                        upper_bound.display_with(self)
                    );
                }
                TypeInterval::Converged(ty) => {
                    println!(
                        "{:?<50} == {:<20}",
                        id.display_with(self),
                        ty.display_with(self)
                    );
                }
            }
        }
    }

    pub fn get_type_for(&self, t: SsaMemoryReference) -> Type {
        let tv_id = self
            .mem_ref_to_type_var_id
            .get(&t)
            .expect(&format!("No type var for {}", t));
        self.get_type_for_id(*tv_id)
    }

    pub fn get_type_for_id(&self, t: TypeVarId) -> Type {
        match self.type_var_states.get(&t).unwrap() {
            TypeInterval::Converged(t) => t.clone(),
            TypeInterval::Bounds { .. } => Type::Any,
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
}
