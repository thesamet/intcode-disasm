// disasm/src/disasm/v3/type_inference/type_bounds_map.rs

use core::fmt;
use std::collections::{HashMap, HashSet};

use colored::Colorize;
use log::trace;

// Import necessary types from your existing types.rs file.
// This path assumes type_bounds_map.rs and types.rs are in the same parent module,
// and types.rs exposes these publicly or they are accessible via `crate::...`
use super::{
    types::{Type, TypeVarId, TypeVarNode},
    Constraint,
}; // Use `super::` if types.rs is in the parent directory (type_inference)
   // TypeVarKind is imported separately in the tests module if needed.

/// Holds the data associated with a single TypeVarId.
/// It includes the TypeVarNode information and its current best bounds.
#[derive(Clone, Debug)] // Requires Type and TypeVarNode to be Clone and Debug
pub enum TypeVarState {
    Bounds {
        lower_bound: Type,
        upper_bound: Type,
    },
    Converged(Type),
}

pub trait TypeVarRegistry {
    fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode>;
}

impl TypeVarRegistry for InferenceAlgorithmState {
    fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode> {
        self.type_var_nodes.get(tv_id)
    }
}

/// Main data structure to hold the state of the iterative type inference algorithm.
/// This structure manages the upper and lower bounds for type variables.
pub struct InferenceAlgorithmState {
    /// Stores the state for each TypeVarId.
    type_var_nodes: HashMap<TypeVarId, TypeVarNode>,
    type_var_states: HashMap<TypeVarId, TypeVarState>,
    /// Tracks TypeVarIds whose bounds have changed since the last `take_updated_vars` call.
    updated_type_vars: HashSet<TypeVarId>, // TypeVarId: Eq + Hash
}

#[derive(Debug)]
pub enum ChangeReason {
    Constraint(Constraint),
    ConcreteTypeRefinement,
    Test,
}

impl fmt::Display for ChangeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChangeReason::Constraint(constraint) => {
                write!(f, "Constraint: {:?}", constraint.reason)
            }
            ChangeReason::ConcreteTypeRefinement => write!(f, "ConcreteTypeRefinement"),
            ChangeReason::Test => write!(f, "Test"),
        }
    }
}

impl InferenceAlgorithmState {
    pub fn new() -> Self {
        InferenceAlgorithmState {
            type_var_states: HashMap::new(),
            type_var_nodes: HashMap::new(),
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
        if !self.type_var_nodes.contains_key(&tv_id) {
            let node_info = node_info_fn(); // Create node_info only if it's a new TypeVar
            self.type_var_nodes.insert(tv_id, node_info);
            self.type_var_states.insert(
                tv_id,
                TypeVarState::Bounds {
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
        self.ensure_type_var_exists(tv_id, || node_info);
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
        tv_id: &TypeVarId,
        new_lower_constraint: &Type,
        reason: ChangeReason,
    ) -> bool {
        let Some(state) = self.type_var_states.get(tv_id) else {
            panic!("TypeVarId {:?} not found", tv_id);
        };
        let TypeVarState::Bounds {
            lower_bound,
            upper_bound,
        } = state
        else {
            return false;
        };

        let upper_bound = self.resolve_type(upper_bound);
        let lower_bound = self.resolve_type(lower_bound);
        // The new best lower bound is the lub of the current one and the new constraint.
        let new_best_lower_opt = Type::lub(&lower_bound, new_lower_constraint);

        if let Some(new_best_lower) = new_best_lower_opt {
            if new_best_lower != lower_bound {
                let new_best_lower = match new_best_lower {
                    Type::LUB(ga, gb) if *ga.as_ref() == Type::TypeVar(*tv_id) => {
                        gb.as_ref().clone()
                    }
                    Type::LUB(ga, gb) if *gb.as_ref() == Type::TypeVar(*tv_id) => {
                        ga.as_ref().clone()
                    }
                    _ => new_best_lower,
                };
                trace!(
                    "Updated {} >: {}, was {}, {reason}",
                    tv_id.display_with(self),
                    new_best_lower.display_with(self),
                    lower_bound,
                );
                if new_best_lower == upper_bound {
                    self.handle_convergence(tv_id, new_best_lower);
                } else {
                    let upper_bound = upper_bound.clone();
                    let state = self.type_var_states.get_mut(&tv_id).unwrap();
                    *state = TypeVarState::Bounds {
                        lower_bound: new_best_lower.clone(),
                        upper_bound,
                    };
                }
                self.updated_type_vars.insert(*tv_id);
                return true;
            }
        }
        false
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
        tv_id: &TypeVarId,
        new_upper_constraint: &Type,
        reason: ChangeReason,
    ) -> bool {
        let Some(state) = self.type_var_states.get(tv_id) else {
            panic!("TypeVarId {:?} not found", tv_id);
        };
        let TypeVarState::Bounds {
            lower_bound,
            upper_bound,
        } = state
        else {
            return false;
        };

        let upper_bound = self.resolve_type(upper_bound);
        let lower_bound = self.resolve_type(lower_bound);

        // The new best upper bound is the glb of the current one and the new constraint.
        let new_best_upper_opt = Type::glb(&upper_bound, new_upper_constraint);

        if let Some(new_best_upper) = new_best_upper_opt {
            let new_best_upper = match new_best_upper {
                Type::GLB(ga, gb) if *ga.as_ref() == Type::TypeVar(*tv_id) => gb.as_ref().clone(),
                Type::GLB(ga, gb) if *gb.as_ref() == Type::TypeVar(*tv_id) => ga.as_ref().clone(),
                _ => new_best_upper,
            };
            if new_best_upper != upper_bound {
                trace!(
                    "Updated {} <: {}, was {}",
                    tv_id.display_with(self),
                    new_best_upper.display_with(self),
                    upper_bound.display_with(self),
                );
                if new_best_upper == lower_bound {
                    self.handle_convergence(tv_id, new_best_upper);
                } else {
                    let lower_bound = lower_bound.clone();
                    let state = self.type_var_states.get_mut(&tv_id).unwrap();
                    *state = TypeVarState::Bounds {
                        lower_bound,
                        upper_bound: new_best_upper,
                    };
                }
                self.updated_type_vars.insert(*tv_id);
                return true;
            }
        }
        false
    }

    pub fn handle_convergence(&mut self, tv_id: &TypeVarId, new_value: Type) {
        let state = self.type_var_states.remove(tv_id).unwrap();
        let TypeVarState::Bounds {
            lower_bound,
            upper_bound,
        } = state
        else {
            panic!("TypeVarState should be Bounds");
        };
        // One of the previous bounds must have been updated earlier to the new value.
        if lower_bound != new_value && upper_bound != new_value {
            panic!(
                "Handle_convergence called, but neither bounds equal to {}",
                new_value
            );
        }
        let msg = format!(
            "CONVERGENCE: {} == {}",
            tv_id.display_with(self),
            new_value.display_with(self)
        );
        trace!("{}", msg.green());
        self.type_var_states
            .insert(*tv_id, TypeVarState::Converged(new_value.clone()));
        let mut tvs = HashMap::new();
        for (id, state) in self.type_var_states.iter() {
            match state {
                TypeVarState::Bounds {
                    lower_bound,
                    upper_bound,
                } => {
                    let lower_bound = self.resolve_type(lower_bound);
                    let upper_bound = self.resolve_type(upper_bound);
                    tvs.insert(
                        *id,
                        TypeVarState::Bounds {
                            lower_bound,
                            upper_bound,
                        },
                    );
                }
                TypeVarState::Converged(t) => {
                    tvs.insert(*id, TypeVarState::Converged(self.resolve_type(t)));
                }
            }
        }
        self.type_var_states = tvs;
    }

    pub fn has_type_var(&self, tv_id: &TypeVarId) -> bool {
        self.type_var_nodes.contains_key(tv_id)
    }

    /// Retrieves the current lower and upper bounds for a given TypeVarId.
    /// Returns `None` if the TypeVarId is not found.
    pub fn get_bounds(&self, tv_id: &TypeVarId) -> Option<(&Type, &Type)> {
        match self.type_var_states.get(tv_id) {
            Some(TypeVarState::Bounds {
                lower_bound,
                upper_bound,
            }) => Some((lower_bound, upper_bound)),
            Some(TypeVarState::Converged(tv_id)) => Some((tv_id, tv_id)),
            _ => None,
        }
    }

    /// Retrieves the `TypeVarNode` for a given `TypeVarId`.
    /// Returns `None` if the `TypeVarId` is not found.
    pub fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode> {
        self.type_var_nodes.get(tv_id)
    }

    /// Provides an iterator over all `TypeVarId`s and their associated `TypeVarState`.
    pub fn iter_all_type_nodes(&self) -> impl Iterator<Item = (&TypeVarId, &TypeVarNode)> {
        self.type_var_nodes.iter()
    }

    pub fn iter_all_type_states(&self) -> impl Iterator<Item = (&TypeVarId, &TypeVarState)> {
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

    pub fn resolve_type(&self, typ: &Type) -> Type {
        let mut typ = typ.clone();
        loop {
            let mut changed = false;

            typ = typ.map(
                &mut |tv_id| match self.type_var_states.get(&tv_id).unwrap() {
                    TypeVarState::Converged(ty) => {
                        changed = true;
                        ty.clone()
                    }
                    _ => Type::TypeVar(*tv_id),
                },
            );
            if !changed {
                break typ;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use dsl_macros_impl::build_expr;

    use super::*;
    use crate::disasm::{
        test_utils::init_logging,
        v3::{lir::Expression, type_inference::ConstraintReason, FunctionId, InstructionId},
    };
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
        let tv1_id: TypeVarId = TypeVarId::new(1);
        state.add_type_var(
            tv1_id,
            make_node(
                TypeVarKind::Expression(build_expr!(10)),
                InstructionId::new(10),
                FunctionId::new(1),
            ),
        );

        state.update_lower_bound(&tv1_id, &Type::Int, ChangeReason::Test);

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
        init_logging();
        let mut state = InferenceAlgorithmState::new();
        let tv1_id: TypeVarId = TypeVarId::new(1);
        let tv2_id: TypeVarId = TypeVarId::new(2);

        state.add_type_var(
            tv1_id,
            make_node(
                TypeVarKind::Expression(build_expr!(1)),
                InstructionId::new(1),
                FunctionId::new(0),
            ),
        );

        state.add_type_var(
            tv2_id,
            make_node(
                TypeVarKind::Expression(build_expr!(2)),
                InstructionId::new(2),
                FunctionId::new(0),
            ),
        );

        // Initial updates
        assert!(state.update_lower_bound(&tv1_id, &Type::Int, ChangeReason::Test));
        assert!(state.update_upper_bound(&tv1_id, &Type::Int, ChangeReason::Test)); // Any.glb(Int) = Int

        assert!(state.update_lower_bound(&tv2_id, &Type::Bool, ChangeReason::Test));
        assert!(state.update_upper_bound(&tv2_id, &Type::Truthy, ChangeReason::Test)); // Any.glb(Truthy) = Truthy

        let updated = state.take_updated_vars();
        assert_eq!(updated.len(), 2);
        assert!(updated.contains(&tv1_id));
        assert!(updated.contains(&tv2_id));

        // Tracker should be empty now
        assert!(state.take_updated_vars().is_empty());

        // No change update
        assert!(!state.update_lower_bound(&tv1_id, &Type::Int, ChangeReason::Test)); // Int.lub(Int) = Int, no change
        assert!(state.take_updated_vars().is_empty()); // Still empty

        // Change update again (assuming Bool <: Truthy, so glb(Truthy, Bool) = Bool)
        assert!(state.update_upper_bound(&tv2_id, &Type::Bool, ChangeReason::Test));
        let updated_again = state.take_updated_vars();
        assert_eq!(updated_again.len(), 1);
        assert!(updated_again.contains(&tv2_id));
    }

    #[test]
    fn test_add_type_var_explicitly() {
        let mut state = InferenceAlgorithmState::new();
        let tv_id: TypeVarId = TypeVarId::new(5);
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
