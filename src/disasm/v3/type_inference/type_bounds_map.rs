// disasm/src/disasm/v3/type_inference/type_bounds_map.rs

use std::collections::{HashMap, HashSet};

// Assuming TypeVarId is usize for now. If it's a custom struct,
// it needs to be defined (e.g., in types.rs or here) and must derive/impl
// Clone, Debug, PartialEq, Eq, and Hash.
// Example:
// use super::types::TypeVarId; // If TypeVarId is defined in types.rs
// Or:
// #[derive(Clone, Debug, PartialEq, Eq, Hash)]
// pub struct TypeVarId { /* fields */ }
pub type TypeVarId = usize; // TODO: Replace with your actual TypeVarId definition if different

use log::trace;

// Import necessary types from your existing types.rs file.
// This path assumes type_bounds_map.rs and types.rs are in the same parent module,
// and types.rs exposes these publicly or they are accessible via `crate::...`
use super::types::{Type, TypeVarNode}; // Use `super::` if types.rs is in the parent directory (type_inference)
                                       // TypeVarKind is imported separately in the tests module if needed.

/// Holds the data associated with a single TypeVarId.
/// It includes the TypeVarNode information and its current best bounds.
#[derive(Clone, Debug)] // Requires Type and TypeVarNode to be Clone and Debug
pub struct TypeVarState {
    pub node_info: TypeVarNode,
    pub lower_bound: Type,
    pub upper_bound: Type,
}

/// Main data structure to hold the state of the iterative type inference algorithm.
/// This structure manages the upper and lower bounds for type variables.
pub struct InferenceAlgorithmState {
    /// Stores the state for each TypeVarId.
    type_var_states: HashMap<TypeVarId, TypeVarState>, // TypeVarId: Eq + Hash
    /// Tracks TypeVarIds whose bounds have changed since the last `take_updated_vars` call.
    updated_type_vars: HashSet<TypeVarId>, // TypeVarId: Eq + Hash
}

impl InferenceAlgorithmState {
    pub fn new() -> Self {
        InferenceAlgorithmState {
            type_var_states: HashMap::new(),
            updated_type_vars: HashSet::new(),
        }
    }

    /// Ensures a TypeVarId exists in the state. If not, it's created using `node_info_fn`
    /// and initialized with the widest bounds (Nothing/Any).
    /// Marks the TypeVarId as updated if it's newly created.
    fn ensure_type_var_exists(
        &mut self,
        tv_id: TypeVarId,
        node_info_fn: impl FnOnce() -> TypeVarNode,
    ) {
        if !self.type_var_states.contains_key(&tv_id) {
            let node_info = node_info_fn(); // Create node_info only if it's a new TypeVar
            self.type_var_states.insert(
                tv_id.clone(), // TypeVarId: Clone
                TypeVarState {
                    node_info,                  // TypeVarNode: Clone (due to TypeVarState deriving Clone)
                    lower_bound: Type::Nothing, // Smallest type in the lattice
                    upper_bound: Type::Any,     // Largest type in the lattice
                },
            );
            self.updated_type_vars.insert(tv_id); // TypeVarId: Clone
        }
    }

    /// Adds a new TypeVar to the state with explicit `node_info`.
    /// Initializes with bounds Type::Nothing and Type::Any.
    /// If the TypeVarId already exists, this function will not overwrite it or error.
    /// Modify if different behavior (e.g., update node_info, error) is desired for existing keys.
    pub fn add_type_var(&mut self, tv_id: TypeVarId, node_info: TypeVarNode) {
        if !self.type_var_states.contains_key(&tv_id) {
            self.type_var_states.insert(
                tv_id,
                TypeVarState {
                    node_info,
                    lower_bound: Type::Nothing,
                    upper_bound: Type::Any,
                },
            );
            self.updated_type_vars.insert(tv_id);
        }
    }

    /// Updates the lower bound for a given TypeVarId.
    /// The new lower bound is `current_lower_bound.lub(new_lower_constraint)`.
    /// Returns `true` if the bound was actually changed, `false` otherwise.
    /// If the TypeVarId does not exist, it will be added using `node_info_fn`.
    ///
    /// Panics if the new lower bound is not a subtype of the current upper bound,
    /// as this indicates an inconsistency in the type lattice or constraints.
    pub fn update_lower_bound(
        &mut self,
        tv_id: TypeVarId,
        new_lower_constraint: &Type,
        node_info_fn: impl FnOnce() -> TypeVarNode,
    ) -> bool {
        self.ensure_type_var_exists(tv_id.clone(), node_info_fn);

        let state = self.type_var_states.get(&tv_id).unwrap(); // Should exist due to ensure_type_var_exists

        // The new best lower bound is the LUB of the current one and the new constraint.
        let new_best_lower_opt = Type::lub(&state.lower_bound, new_lower_constraint);

        if let Some(new_best_lower) = new_best_lower_opt {
            if new_best_lower != state.lower_bound {
                // Type: PartialEq
                // CRITICAL CONSISTENCY CHECK:
                // The new lower bound must still be a subtype of the current upper bound.
                if !new_best_lower.is_subtype_of(&state.upper_bound) {
                    // This signifies a contradiction in constraints (e.g., lower bound crossed upper bound).
                    // Handling this depends on the desired solver behavior.
                    // For now, we panic as it's a critical state error.
                    // Alternatives: log error and don't update, or set bounds to Nothing/Any.
                    panic!(
                        "Type inference inconsistency for TypeVarId {:?}: \
                         New lower bound {:?} is not a subtype of current upper bound {:?}.",
                        tv_id,
                        new_best_lower,
                        state.upper_bound // TypeVarId, Type: Debug
                    );
                }
                let var = self.format_typevar_id(&tv_id);
                trace!(
                    "Updated {} <: {new_best_lower}, was {}",
                    var,
                    state.upper_bound,
                );
                let state = self.type_var_states.get_mut(&tv_id).unwrap(); // Should exist due to ensure_type_var_exists
                state.lower_bound = new_best_lower;
                self.updated_type_vars.insert(tv_id);
                return true;
            }
        }
        false
    }

    fn format_typevar_id(&self, tv_id: &TypeVarId) -> String {
        self.type_var_states
            .get(&tv_id)
            .unwrap()
            .node_info
            .to_string()
    }

    /// Updates the upper bound for a given TypeVarId.
    /// The new upper bound is `current_upper_bound.glb(new_upper_constraint)`.
    /// Returns `true` if the bound was actually changed, `false` otherwise.
    /// If the TypeVarId does not exist, it will be added using `node_info_fn`.
    ///
    /// Panics if the current lower bound is not a subtype of the new upper bound,
    /// as this indicates an inconsistency.
    pub fn update_upper_bound(
        &mut self,
        tv_id: TypeVarId,
        new_upper_constraint: &Type,
        node_info_fn: impl FnOnce() -> TypeVarNode,
    ) -> bool {
        self.ensure_type_var_exists(tv_id.clone(), node_info_fn);

        let state = self.type_var_states.get(&tv_id).unwrap();

        // The new best upper bound is the GLB of the current one and the new constraint.
        let new_best_upper_opt = Type::glb(&state.upper_bound, new_upper_constraint);

        if let Some(new_best_upper) = new_best_upper_opt {
            if new_best_upper != state.upper_bound {
                // Type: PartialEq
                // CRITICAL CONSISTENCY CHECK:
                // The current lower bound must still be a subtype of the new upper bound.
                if !state.lower_bound.is_subtype_of(&new_best_upper) {
                    panic!(
                        "Type inference inconsistency for TypeVarId {:?}: \
                         Current lower bound {:?} is not a subtype of new upper bound {:?}.",
                        tv_id,
                        state.lower_bound,
                        new_best_upper // TypeVarId, Type: Debug
                    );
                }
                let var = self.format_typevar_id(&tv_id);
                trace!(
                    "Updated {} <: {new_best_upper}, was {}",
                    var,
                    state.upper_bound,
                );
                let state = self.type_var_states.get_mut(&tv_id).unwrap();
                state.upper_bound = new_best_upper;
                self.updated_type_vars.insert(tv_id);
                return true;
            }
        }
        false
    }

    /// Retrieves the current lower and upper bounds for a given TypeVarId.
    /// Returns `None` if the TypeVarId is not found.
    pub fn get_bounds(&self, tv_id: &TypeVarId) -> Option<(&Type, &Type)> {
        self.type_var_states
            .get(tv_id)
            .map(|data| (&data.lower_bound, &data.upper_bound))
    }

    /// Retrieves the `TypeVarNode` for a given `TypeVarId`.
    /// Returns `None` if the `TypeVarId` is not found.
    pub fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode> {
        self.type_var_states.get(tv_id).map(|data| &data.node_info)
    }

    /// Retrieves a mutable reference to `TypeVarState` for a given `TypeVarId`.
    /// Useful for direct manipulations if needed, though updates typically go via specific methods.
    /// Returns `None` if the `TypeVarId` is not found.
    pub fn get_type_var_state_mut(&mut self, tv_id: &TypeVarId) -> Option<&mut TypeVarState> {
        self.type_var_states.get_mut(tv_id)
    }

    /// Provides an iterator over all `TypeVarId`s and their associated `TypeVarState`.
    pub fn iter_all_type_vars(&self) -> impl Iterator<Item = (&TypeVarId, &TypeVarState)> {
        self.type_var_states.iter()
    }

    /// Returns a `Vec` of `TypeVarId`s whose bounds have been updated since the last
    /// call to this method, and clears the internal tracking set.
    /// This "takes" the updated variables, resetting the tracker for the next iteration.
    pub fn take_updated_vars(&mut self) -> Vec<TypeVarId> {
        // TypeVarId must be Clone
        let updated_set = std::mem::take(&mut self.updated_type_vars);
        updated_set.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use dsl_macros_impl::build_expr;

    use super::*;
    use crate::disasm::v3::{lir::Expression, FunctionId, InstructionId};
    // Explicitly import TypeVarKind for the test module from the correct path.
    // `super` (type_bounds_map) -> `super` (type_inference) -> `types` (types.rs module)
    use super::super::types::TypeVarKind;

    // Mock/dummy TypeVarNode creation for tests
    // Ensure this is compatible with the actual TypeVarNode structure.
    fn make_node(
        kind: TypeVarKind,
        instruction_id: InstructionId,
        function_id: FunctionId,
    ) -> TypeVarNode {
        TypeVarNode {
            kind,
            instruction_id,
            function_id,
        }
    }

    #[test]
    fn test_add_and_get_bounds() {
        let mut state = InferenceAlgorithmState::new();
        let tv1_id: TypeVarId = 1;
        let node1_info_fn = || {
            make_node(
                TypeVarKind::Expression(build_expr!(10)),
                InstructionId::new(10),
                FunctionId::new(1),
            )
        };

        assert!(state.get_bounds(&tv1_id).is_none());
        state.update_lower_bound(tv1_id, &Type::Int, node1_info_fn);

        let (lower, upper) = state.get_bounds(&tv1_id).expect("tv1 should exist");
        // These assertions depend on Type::Nothing.lub(&Type::Int) resulting in Type::Int
        // and initial upper bound being Type::Any.
        // Also, Type must implement PartialEq for these comparisons.
        assert_eq!(*lower, Type::Int);
        assert_eq!(*upper, Type::Any);

        if let Some(node) = state.get_type_var_node(&tv1_id) {
            assert_eq!(node.kind, TypeVarKind::Expression(Expression::Constant(10)));
        // Assumes TypeVarKind has PartialEq
        } else {
            panic!("Node info not found for tv1_id");
        }
    }

    #[test]
    fn test_bound_updates_and_tracking() {
        let mut state = InferenceAlgorithmState::new();
        let tv1_id: TypeVarId = 1;
        let tv2_id: TypeVarId = 2;

        let node1_fn = || {
            make_node(
                TypeVarKind::Expression(build_expr!(1)),
                InstructionId::new(1),
                FunctionId::new(0),
            )
        };
        let node2_fn = || {
            make_node(
                TypeVarKind::Expression(build_expr!(2)),
                InstructionId::new(2),
                FunctionId::new(0),
            )
        }; // Changed MemoryReference to Expression for simplicity

        // Initial updates
        assert!(state.update_lower_bound(tv1_id, &Type::Int, node1_fn));
        assert!(state.update_upper_bound(tv1_id, &Type::Int, node1_fn)); // Any.glb(Int) = Int

        assert!(state.update_lower_bound(tv2_id, &Type::Bool, node2_fn));
        assert!(state.update_upper_bound(tv2_id, &Type::Truthy, node2_fn)); // Any.glb(Truthy) = Truthy

        let updated = state.take_updated_vars();
        assert_eq!(updated.len(), 2);
        assert!(updated.contains(&tv1_id));
        assert!(updated.contains(&tv2_id));

        // Tracker should be empty now
        assert!(state.take_updated_vars().is_empty());

        // No change update
        assert!(!state.update_lower_bound(tv1_id, &Type::Int, node1_fn)); // Int.lub(Int) = Int, no change
        assert!(state.take_updated_vars().is_empty()); // Still empty

        // Change update again (assuming Bool <: Truthy, so glb(Truthy, Bool) = Bool)
        assert!(state.update_upper_bound(tv2_id, &Type::Bool, node2_fn));
        let updated_again = state.take_updated_vars();
        assert_eq!(updated_again.len(), 1);
        assert!(updated_again.contains(&tv2_id));
    }

    // The panic messages depend on the Debug output of TypeVarId and Type.
    // Adjust the expected messages if your Debug impls differ significantly.
    #[test]
    #[should_panic(expected = "New lower bound Int is not a subtype of current upper bound Bool")]
    fn test_consistency_panic_lower_bound() {
        let mut state = InferenceAlgorithmState::new();
        let tv1_id: TypeVarId = 1;
        let node1_fn = || {
            make_node(
                TypeVarKind::Expression(build_expr!(1)),
                InstructionId::new(1),
                FunctionId::new(0),
            )
        };

        state.update_upper_bound(tv1_id, &Type::Bool, node1_fn); // Upper bound is Bool
        state.take_updated_vars();

        // Attempt to set lower to Int. This should panic if Int is not a subtype of Bool.
        // (Requires Type::Int.is_subtype_of(&Type::Bool) to be false)
        state.update_lower_bound(tv1_id, &Type::Int, node1_fn);
    }

    #[test]
    #[should_panic(expected = "Current lower bound Int is not a subtype of new upper bound Bool")]
    fn test_consistency_panic_upper_bound() {
        let mut state = InferenceAlgorithmState::new();
        let tv1_id: TypeVarId = 1;
        let node1_fn = || {
            make_node(
                TypeVarKind::Expression(build_expr!(15)),
                InstructionId::new(1),
                FunctionId::new(0),
            )
        };

        state.update_lower_bound(tv1_id, &Type::Int, node1_fn); // Lower bound is Int
        state.take_updated_vars();

        // Attempt to set upper to Bool. This should panic if Int is not a subtype of Bool.
        state.update_upper_bound(tv1_id, &Type::Bool, node1_fn);
    }

    #[test]
    fn test_add_type_var_explicitly() {
        let mut state = InferenceAlgorithmState::new();
        let tv_id: TypeVarId = 5;
        let node_info = make_node(
            TypeVarKind::Expression(build_expr!(34)),
            InstructionId::new(50),
            FunctionId::new(5),
        );

        state.add_type_var(tv_id, node_info.clone()); // node_info needs to be Clone

        let (lower, upper) = state
            .get_bounds(&tv_id)
            .expect("tv_id should exist after add_type_var");
        assert_eq!(*lower, Type::Nothing);
        assert_eq!(*upper, Type::Any);
        assert_eq!(state.get_type_var_node(&tv_id).unwrap(), &node_info); // Requires TypeVarNode to impl PartialEq

        let updated = state.take_updated_vars();
        assert_eq!(updated.len(), 1);
        assert!(updated.contains(&tv_id));

        // Adding again should not change anything or error with current implementation
        let another_node_info = make_node(
            TypeVarKind::Expression(build_expr!(35)),
            InstructionId::new(55),
            FunctionId::new(5),
        ); // Changed MemoryReference to Expression
        state.add_type_var(tv_id, another_node_info);
        assert_eq!(state.get_type_var_node(&tv_id).unwrap(), &node_info);
        assert!(state.take_updated_vars().is_empty());
    }
}
