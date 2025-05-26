// disasm/src/disasm/v3/type_inference/type_bounds_map.rs

use core::fmt;
use std::{
    collections::{HashMap, HashSet},
    path::Display,
};

use colored::Colorize;
use itertools::Itertools;
use log::trace;

// Import necessary types from your existing types.rs file.
// This path assumes type_bounds_map.rs and types.rs are in the same parent module,
// and types.rs exposes these publicly or they are accessible via `crate::...`
use super::{
    constraints::ConstraintId,
    type_interval::TypeInterval,
    types::{Type, TypeVarId, TypeVarNode},
    Constraint,
}; // Use `super::` if types.rs is in the parent directory (type_inference)
   // TypeVarKind is imported separately in the tests module if needed.

/// Holds the data associated with a single TypeVarId.
/// It includes the TypeVarNode information and its current best bounds.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeVarState {
    Bounds {
        lower_bounds: HashSet<Type>,
        upper_bounds: HashSet<Type>,
    },
    Converged(Type),
}

impl TypeVarState {
    pub fn display_with<'a, F>(&'a self, registry: &'a F) -> DisplayableTypeVarState<'a, F> {
        DisplayableTypeVarState {
            state: self,
            registry,
        }
    }
}

pub struct DisplayableTypeVarState<'a, F> {
    state: &'a TypeVarState,
    registry: &'a F,
}

impl<'a, F: TypeVarRegistry> fmt::Display for DisplayableTypeVarState<'a, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.state {
            TypeVarState::Bounds {
                lower_bounds,
                upper_bounds,
            } => {
                write!(
                    f,
                    "[{{{}}}, {{{}}}]",
                    lower_bounds
                        .iter()
                        .map(|t| t.display_with(self.registry))
                        .join(", "),
                    upper_bounds
                        .iter()
                        .map(|t| t.display_with(self.registry))
                        .join(", "),
                )
            }
            TypeVarState::Converged(typ) => {
                write!(f, "{}", typ.display_with(self.registry))
            }
        }
    }
}

impl fmt::Display for TypeVarState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeVarState::Bounds {
                lower_bounds,
                upper_bounds,
            } => write!(
                f,
                "[{{{}}}, {{{}}}]",
                lower_bounds.iter().join(", "),
                upper_bounds.iter().join(", ")
            ),
            TypeVarState::Converged(ty) => write!(f, "{}", ty),
        }
    }
}

pub trait TypeVarRegistry {
    fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode>;
    fn get_type_var_state(&self, tv_id: &TypeVarId) -> Option<&TypeVarState>;
    fn lower_bounds(&self, tv_id: &TypeVarId) -> HashSet<&Type> {
        match self.get_type_var_state(tv_id).unwrap() {
            TypeVarState::Bounds { lower_bounds, .. } => lower_bounds.iter().collect(),
            TypeVarState::Converged(ty) => HashSet::from([ty]),
        }
    }
    fn upper_bounds(&self, tv_id: &TypeVarId) -> HashSet<&Type> {
        match self.get_type_var_state(tv_id).unwrap() {
            TypeVarState::Bounds { upper_bounds, .. } => upper_bounds.iter().collect(),
            TypeVarState::Converged(ty) => HashSet::from([ty]),
        }
    }
}

impl TypeVarRegistry for InferenceAlgorithmState {
    fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode> {
        self.type_var_nodes.get(tv_id)
    }
    fn get_type_var_state(&self, tv_id: &TypeVarId) -> Option<&TypeVarState> {
        self.type_var_states.get(tv_id)
    }
}

/// Main data structure to hold the state of the iterative type inference algorithm.
/// This structure manages the upper and lower bounds for type variables.
#[derive(Debug, Clone, Default)]
pub struct InferenceAlgorithmState {
    /// Stores the state for each TypeVarId.
    type_var_nodes: HashMap<TypeVarId, TypeVarNode>,
    type_var_states: HashMap<TypeVarId, TypeVarState>,
    /// Tracks TypeVarIds whose bounds have changed since the last `take_updated_vars` call.
    updated_type_vars: HashSet<TypeVarId>, // TypeVarId: Eq + Hash
    pub change_log: Vec<ChangeLogEntry>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ChangeReason {
    Constraint(ConstraintId),
    ConvergenceOf(TypeVarId),
    ConcreteConvergence, // This is used when a concrete type converges to a specific type.
    ConvergeToLUB,
    ConvergeToGLB,
    NonConcreteConvergence,
    Test,
}

pub struct DisplayableChangeReason<'a, F> {
    reason: &'a ChangeReason,
    registry: &'a F,
}

impl<'a> ChangeReason {
    pub fn display_with<F>(&'a self, registry: &'a F) -> DisplayableChangeReason<'a, F> {
        DisplayableChangeReason {
            reason: self,
            registry,
        }
    }
}

impl<'a, F: TypeVarRegistry> fmt::Display for DisplayableChangeReason<'a, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason {
            ChangeReason::Constraint(constraint_id) => {
                write!(f, "Constraint: {:?}", constraint_id)
            }
            ChangeReason::ConvergenceOf(tv_id) => {
                write!(f, "convergence of {}", tv_id.display_with(self.registry))
            }
            ChangeReason::Test => write!(f, "test"),
            ChangeReason::ConcreteConvergence => write!(f, "concrete convergence"),
            ChangeReason::ConvergeToLUB => write!(f, "converge to LUB"),
            ChangeReason::ConvergeToGLB => write!(f, "converge to GLB"),
            ChangeReason::NonConcreteConvergence => write!(f, "non-concrete convergence"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum BoundDirection {
    Lower,
    Upper,
}

impl fmt::Display for ChangeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChangeReason::Constraint(constraint_id) => {
                write!(f, "Constraint: {:?}", constraint_id)
            }
            ChangeReason::ConvergenceOf(id) => {
                write!(f, "ConvergenceOf({})", id)
            }
            ChangeReason::Test => write!(f, "Test"),
            ChangeReason::ConcreteConvergence => write!(f, "ConcreteConvergence"),
            ChangeReason::ConvergeToLUB => write!(f, "ConvergeToLUB"),
            ChangeReason::ConvergeToGLB => write!(f, "ConvergeToGLB"),
            ChangeReason::NonConcreteConvergence => write!(f, "NonConcreteConvergence"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChangeLogEntry {
    pub tv_id: TypeVarId,
    pub state: TypeVarState,
    pub reason: ChangeReason,
}

impl InferenceAlgorithmState {
    fn update_bound_internal(
        &mut self,
        tv_id: &TypeVarId,
        new_bound: &Type,
        direction: BoundDirection,
        reason: ChangeReason,
    ) -> bool {
        if *new_bound == tv_id.to_type() {
            // No change if the new bound is the same as the current type
            return false;
        }
        let Some(state) = self.type_var_states.get_mut(tv_id) else {
            panic!("TypeVarId {:?} not found", tv_id);
        };
        let old_state = state.clone();
        let TypeVarState::Bounds {
            lower_bounds,
            upper_bounds,
        } = state
        else {
            return false; // Already converged or not in Bounds state
        };
        let changed = match direction {
            BoundDirection::Lower => lower_bounds.insert(new_bound.clone()),
            BoundDirection::Upper => upper_bounds.insert(new_bound.clone()),
        };
        if changed {
            trace!("Updated bounds {} to {}   was  {}", tv_id, state, old_state);
            self.updated_type_vars.insert(*tv_id);
            let state = state.clone();
            self.change_log.push(ChangeLogEntry {
                tv_id: *tv_id,
                state,
                reason,
            });
        }
        changed
    }

    pub fn converge(&mut self, tv_id: &TypeVarId, new_bound: Type, reason: ChangeReason) {
        let state = self.type_var_states.get_mut(tv_id).unwrap();
        if matches!(state, TypeVarState::Converged { .. }) {
            panic!("Type var id {:?} already converged.", tv_id);
        }
        self.type_var_states
            .insert(*tv_id, TypeVarState::Converged(new_bound.clone()));
        self.change_log.push(ChangeLogEntry {
            tv_id: *tv_id,
            state: TypeVarState::Converged(new_bound.clone()),
            reason,
        });
        trace!("{}", format!("{} converted to {}", tv_id, new_bound).red());
        let mut log_entries = vec![];
        self.type_var_states = self
            .type_var_states
            .iter()
            .map(|(id, v)| match (id, v) {
                (id, _) if id == tv_id => (*id, TypeVarState::Converged(new_bound.clone())),
                (
                    id,
                    TypeVarState::Bounds {
                        lower_bounds,
                        upper_bounds,
                    },
                ) => {
                    let new_lower_bounds: HashSet<Type> = lower_bounds
                        .iter()
                        .filter(|l| **l != tv_id.to_type())
                        .map(|l| self.resolve_type(l))
                        .collect();
                    let new_upper_bounds: HashSet<Type> = upper_bounds
                        .iter()
                        .filter(|u| **u != tv_id.to_type())
                        .map(|u| self.resolve_type(u))
                        .collect();
                    if new_lower_bounds != *lower_bounds || new_upper_bounds != *upper_bounds {
                        log_entries.push(ChangeLogEntry {
                            tv_id: *id,
                            state: TypeVarState::Bounds {
                                lower_bounds: new_lower_bounds.clone(),
                                upper_bounds: new_upper_bounds.clone(),
                            },
                            reason: ChangeReason::ConvergenceOf(*tv_id),
                        });
                    }
                    (
                        *id,
                        TypeVarState::Bounds {
                            lower_bounds: new_lower_bounds,
                            upper_bounds: new_upper_bounds,
                        },
                    )
                }
                (id, TypeVarState::Converged(ty)) => {
                    (*id, TypeVarState::Converged(self.resolve_type(ty)))
                }
            })
            .collect();
        self.change_log.extend(log_entries);
    }

    pub fn new() -> Self {
        InferenceAlgorithmState {
            type_var_states: HashMap::new(),
            type_var_nodes: HashMap::new(),
            updated_type_vars: HashSet::new(),
            change_log: Vec::new(),
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
                    lower_bounds: HashSet::new(),
                    upper_bounds: HashSet::new(),
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
        trace!("Adding variable {}: {}", tv_id, node_info);
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
        self.update_bound_internal(tv_id, new_lower_constraint, BoundDirection::Lower, reason)
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
        self.update_bound_internal(tv_id, new_upper_constraint, BoundDirection::Upper, reason)
    }

    /*
    pub fn handle_convergence(&mut self, tv_id: &TypeVarId, reason: &ChangeReason) {
    let intersection = lower_bounds
        .intersection(upper_bounds)
        .cloned()
        .collect_vec();
    assert!(
        intersection.len() <= 1,
        "Lower and upper bound have multiple shared elements"
    );
    if intersection.len() == 1 {
        *state = TypeVarState::Converged(intersection[0].clone());
        self.handle_convergence(tv_id, &reason);
        changed = true;
    }
        let state = self.type_var_states.remove(tv_id).unwrap();
        let TypeVarState::Converged(new_value) = state else {
            panic!("TypeVarState has not converged");
        };
        let msg = format!(
            "CONVERGENCE: {} ==> {}    Reason: {}",
            tv_id.display_with(self),
            new_value.display_with(self),
            reason.display_with(self)
        );
        trace!("{}", msg.green());
        self.change_log.push(ChangeLogEntry {
            tv_id: *tv_id,
            state: TypeVarState::Converged(new_value.clone()),
            reason: ChangeReason::ConvergenceOf(*tv_id),
        });
        let mut tvs = HashMap::new();
        for (id, state) in self.type_var_states.iter() {
            match state {
                TypeVarState::Bounds {
                    lower_bounds,
                    upper_bounds,
                } => {
                    let new_lower_bounds =
                        lower_bounds.iter().map(|t| self.resolve_type(t)).collect();
                    let new_upper_bounds =
                        upper_bounds.iter().map(|t| self.resolve_type(t)).collect();
                    tvs.insert(
                        *id,
                        TypeVarState::Bounds {
                            lower_bounds: new_lower_bounds,
                            upper_bounds: new_upper_bounds,
                        },
                    );
                    if tvs[id] != self.type_var_states[id] {
                        self.change_log.push(ChangeLogEntry {
                            tv_id: *id,
                            state: tvs[id].clone(),
                            reason: ChangeReason::ConvergenceOf(*tv_id),
                        });
                    }
                }
                TypeVarState::Converged(t) => {
                    tvs.insert(*id, TypeVarState::Converged(self.resolve_type(t)));
                    if tvs[id] != self.type_var_states[id] {
                        self.change_log.push(ChangeLogEntry {
                            tv_id: *id,
                            state: tvs[id].clone(),
                            reason: ChangeReason::ConvergenceOf(*tv_id),
                        });
                    }
                }
            }
        }
        self.type_var_states = tvs;
    }
    */

    pub fn has_type_var(&self, tv_id: &TypeVarId) -> bool {
        self.type_var_nodes.contains_key(tv_id)
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

            typ = typ.map(&mut |tv_id| match self
                .get_type_var_state(&tv_id)
                .unwrap_or_else(|| panic!("Could not get type_var_state for {tv_id}"))
            {
                TypeVarState::Converged(ty) => {
                    changed = true;
                    ty.clone()
                }
                _ => Type::TypeVar(*tv_id),
            });
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
}
