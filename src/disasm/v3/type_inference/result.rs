//! Type inference result data structure.

use std::collections::HashMap;

use itertools::Itertools;
use log::debug;

use crate::disasm::symbol_renaming::{CustomTypeId, StructId, UserDefs};
use crate::disasm::v3::lir::TypeVarPath;
use crate::disasm::v3::model::{HasTypeInferenceResult, Model, ModelState};
use crate::disasm::v3::ssa::VersionedMemoryReference;
use crate::disasm::v3::type_inference::types::StructDef;
use crate::disasm::v3::FunctionId;

use super::type_bounds_map::{ChangeLogEntry, TypeVarRegistry};
use super::types::{Type, TypeVarId, TypeVarNode};
use super::{ConstraintStore, TypeVarState};

#[derive(Debug, Clone, Default)]
pub struct FunctionSignature {
    pub args: Vec<(VersionedMemoryReference, Type, TypeVarId)>,
    pub returns: Vec<(VersionedMemoryReference, Type, TypeVarId)>,
}

/// Result of the type inference analysis.
#[derive(Clone, Debug)]
pub struct TypeInferenceResult {
    pub type_var_states: HashMap<TypeVarId, TypeVarState>,
    pub type_var_nodes: HashMap<TypeVarId, TypeVarNode>,
    pub vmr_to_type_var_id: HashMap<VersionedMemoryReference, TypeVarId>,
    pub path_to_type_var_id: HashMap<TypeVarPath, TypeVarId>,
    pub debug_markers: HashMap<char, TypeVarId>,
    pub change_log: Vec<ChangeLogEntry>,
    pub constraint_store: ConstraintStore,
    pub generic_type_vars: HashMap<super::types::GenericTypeVarId, super::types::GenericTypeVar>,
    pub function_signatures: HashMap<FunctionId, FunctionSignature>,
    pub custom_type_names: HashMap<CustomTypeId, String>,
    pub struct_defs: HashMap<StructId, StructDef>,
    pub global_type_var_ids: HashMap<usize, TypeVarId>,
    pub user_defs: UserDefs,
}

impl<S> Model<S>
where
    S: ModelState + HasTypeInferenceResult,
{
    pub fn user_defs(&self) -> &UserDefs {
        &self.type_inference_result().user_defs
    }
}

impl TypeInferenceResult {
    /// Create a new empty type inference result.
    pub fn new() -> Self {
        Self {
            type_var_states: HashMap::new(),
            type_var_nodes: HashMap::new(),
            vmr_to_type_var_id: HashMap::new(),
            path_to_type_var_id: HashMap::new(),
            debug_markers: HashMap::new(),
            change_log: Vec::new(),
            constraint_store: ConstraintStore::new(),
            generic_type_vars: HashMap::new(),
            function_signatures: HashMap::new(),
            custom_type_names: HashMap::new(),
            global_type_var_ids: HashMap::new(),
            struct_defs: HashMap::new(),
            user_defs: UserDefs::new(),
        }
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

    pub fn get_type_id_for_vmr(&self, t: &VersionedMemoryReference) -> TypeVarId {
        self.vmr_to_type_var_id
            .get(t)
            .cloned()
            .unwrap_or_else(|| panic!("No type var for {}", t))
    }

    pub fn get_type_id_for_path(&self, t: &TypeVarPath) -> TypeVarId {
        *self.path_to_type_var_id.get(t).unwrap_or_else(|| {
            for p in self.path_to_type_var_id.keys() {
                if p.function_id() == t.function_id() && p.instruction_id() == t.instruction_id() {
                    println!("Found path {:?} :", p);
                }
            }
            panic!("No type var for {:?}", t)
        })
    }

    pub fn get_type_for(&self, t: &VersionedMemoryReference) -> Type {
        let tv_id = self.get_type_id_for_vmr(t);
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

    pub fn get_global_type_var_id(&self, addr: usize) -> Option<TypeVarId> {
        self.global_type_var_ids.get(&addr).cloned()
    }
}

impl TypeVarRegistry for TypeInferenceResult {
    fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode> {
        self.type_var_nodes.get(tv_id)
    }
    fn get_type_var_state(&self, tv_id: &TypeVarId) -> Option<&TypeVarState> {
        self.type_var_states.get(tv_id)
    }
    fn get_generic_type_var(
        &self,
        id: &super::types::GenericTypeVarId,
    ) -> Option<&super::types::GenericTypeVar> {
        self.generic_type_vars.get(id)
    }

    fn user_defs(&self) -> &UserDefs {
        &self.user_defs
    }
}
