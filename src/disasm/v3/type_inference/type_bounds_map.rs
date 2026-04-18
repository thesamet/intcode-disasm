// disasm/src/disasm/v3/type_inference/type_bounds_map.rs

use core::fmt;
use std::collections::{HashMap, HashSet};

use itertools::Itertools;
use log::trace;
use petgraph::{
    visit::{GraphBase, GraphRef, IntoNeighbors, IntoNeighborsDirected, Reversed, Visitable},
    Direction,
};

use crate::disasm::{
    symbol_renaming::UserDefs,
    v3::{lir::TypeVarPath, ssa::VersionedMemoryReference},
};

// Import necessary types from your existing types.rs file.
// This path assumes type_bounds_map.rs and types.rs are in the same parent module,
// and types.rs exposes these publicly or they are accessible via `crate::...`
use super::{
    constraints::ConstraintId,
    types::{GenericTypeVar, GenericTypeVarId, Type, TypeBounds, TypeVarId, TypeVarNode},
};

/// Holds the best bounds for a single TypeVarId.
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

    /// Returns `true` if the type var state is [`Bounds`].
    ///
    /// [`Bounds`]: TypeVarState::Bounds
    #[must_use]
    pub fn is_bounds(&self) -> bool {
        matches!(self, Self::Bounds { .. })
    }

    /// Returns `true` if the type var state is [`Converged`].
    ///
    /// [`Converged`]: TypeVarState::Converged
    #[must_use]
    pub fn is_converged(&self) -> bool {
        matches!(self, Self::Converged(..))
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
            TypeVarState::Converged(ty) => write!(f, "{ty}"),
        }
    }
}

pub trait TypeVarRegistry {
    fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode>;
    fn get_type_var_state(&self, tv_id: &TypeVarId) -> Option<&TypeVarState>;
    fn get_generic_type_var(&self, id: &GenericTypeVarId) -> Option<&GenericTypeVar>;
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

    fn resolve_type(&self, typ: &Type) -> Type {
        let mut typ = typ.clone();
        loop {
            let mut changed = false;

            typ = typ.map(&mut |tv_id| match self
                .get_type_var_state(tv_id)
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

    // Provides access to user-supplied type definitions. Ideally this context would be
    // threaded through the constraint generation pipeline rather than accessed via the registry.
    fn user_defs(&self) -> &UserDefs;
}

impl TypeVarRegistry for InferenceAlgorithmState {
    fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode> {
        self.type_var_nodes.get(tv_id)
    }
    fn get_type_var_state(&self, tv_id: &TypeVarId) -> Option<&TypeVarState> {
        self.type_var_states.get(tv_id)
    }
    fn get_generic_type_var(&self, id: &GenericTypeVarId) -> Option<&GenericTypeVar> {
        self.generic_type_vars.get(id)
    }

    fn user_defs(&self) -> &UserDefs {
        &self.user_defs
    }
}

/// Main data structure to hold the state of the iterative type inference algorithm.
/// This structure manages the upper and lower bounds for type variables.
#[derive(Debug, Clone, Default)]
pub struct InferenceAlgorithmState {
    /// Stores the state for each TypeVarId.
    type_var_nodes: HashMap<TypeVarId, TypeVarNode>,
    type_var_states: HashMap<TypeVarId, TypeVarState>,
    // Maps a VersionedMemoryReference to a TypeVarId.
    // This ensures that each unique versioned memory reference gets one TypeVar.
    vmr_to_type_var: HashMap<VersionedMemoryReference, TypeVarId>,

    dependents: HashMap<TypeVarId, HashSet<TypeVarId>>,

    /// Tracks TypeVarIds whose bounds have changed since the last `take_updated_vars` call.
    updated_type_vars: HashSet<TypeVarId>, // TypeVarId: Eq + Hash
    pub change_log: Vec<ChangeLogEntry>,

    iteration: usize,
    next_type_var_id_counter: usize,

    /// Generic type variables introduced during inference
    generic_type_vars: HashMap<GenericTypeVarId, GenericTypeVar>,
    next_generic_id_counter: usize,
    user_defs: UserDefs,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BoundChangeReason {
    Constraint(ConstraintId),
    Test,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConverganceType {
    ConcreteConvergence, // This is used when a concrete type converges to a specific type.
    ConvergeToLUB,
    ConvergeToGLB,
    NonConcreteConvergence,
    ReplacedWithFunctionType,
    ReplacedWithTuple,
    ReplacedWithPointer,
    ReplacedWithGeneric,
}

impl fmt::Display for ConverganceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConverganceType::ConcreteConvergence => write!(f, "ConcreteConvergence"),
            ConverganceType::ConvergeToLUB => write!(f, "ConvergeToLUB"),
            ConverganceType::ConvergeToGLB => write!(f, "ConvergeToGLB"),
            ConverganceType::NonConcreteConvergence => write!(f, "NonConcreteConvergence"),
            ConverganceType::ReplacedWithFunctionType => write!(f, "ReplacedWithFunctionType"),
            ConverganceType::ReplacedWithTuple => write!(f, "ReplacedWithTuple"),
            ConverganceType::ReplacedWithPointer => write!(f, "ReplacedWithPointer"),
            ConverganceType::ReplacedWithGeneric => write!(f, "ReplacedWithGeneric"),
        }
    }
}

pub struct DisplayableChangeReason<'a, F> {
    reason: &'a BoundChangeReason,
    _registry: &'a F,
}

impl<'a> BoundChangeReason {
    pub fn display_with<F>(&'a self, registry: &'a F) -> DisplayableChangeReason<'a, F> {
        DisplayableChangeReason {
            reason: self,
            _registry: registry,
        }
    }
}

impl<'a, F: TypeVarRegistry> fmt::Display for DisplayableChangeReason<'a, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason {
            BoundChangeReason::Constraint(constraint_id) => {
                write!(f, "Constraint: {constraint_id:?}")
            }
            BoundChangeReason::Test => write!(f, "Test"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BoundDirection {
    Lower,
    Upper,
}

impl fmt::Display for BoundDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundDirection::Lower => write!(f, ":>"),
            BoundDirection::Upper => write!(f, "<:"),
        }
    }
}

impl fmt::Display for BoundChangeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundChangeReason::Constraint(constraint_id) => {
                write!(f, "Constraint: {constraint_id:?}")
            }
            BoundChangeReason::Test => write!(f, "Test"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeLogEntry {
    pub iteration: usize,
    pub tv_id: TypeVarId,
    pub kind: ChangeLogKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Represents the different kinds of changes that can occur during type inference.
pub enum ChangeLogKind {
    /// A new bound (lower or upper) was added to a type variable.
    AddedBound {
        direction: BoundDirection,
        new_bound: Type,
        reason: BoundChangeReason,
    },
    /// A type variable has converged to a specific type.
    Converged {
        new_type: Type,
        convergence_type: ConverganceType,
    },
    /// A depenedency fo the type var in ChangeLogEntry has converged, triggering a
    /// rewrite.
    DependencyConverged {
        dependent_var_id: TypeVarId,
        new_value: Type,
    },
}

impl InferenceAlgorithmState {
    pub fn next_iteration(&mut self) {
        self.iteration += 1;
    }

    fn update_bound_internal(
        &mut self,
        tv_id: &TypeVarId,
        new_bound: &Type,
        direction: BoundDirection,
        reason: BoundChangeReason,
    ) -> bool {
        if *new_bound == tv_id.to_type() {
            // No change if the new bound is the same as the current type
            return false;
        }
        let Some(state) = self.type_var_states.get_mut(tv_id) else {
            panic!("TypeVarId {tv_id:?} not found");
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
            let involved_type_vars = new_bound.involved_type_vars();
            for dep in involved_type_vars {
                self.dependents.entry(dep).or_default().insert(*tv_id);
            }
            self.change_log.push(ChangeLogEntry {
                tv_id: *tv_id,
                kind: ChangeLogKind::AddedBound {
                    direction,
                    new_bound: new_bound.clone(),
                    reason,
                },
                iteration: self.iteration,
            });
        }
        changed
    }

    /// If `u`'s bounds depend on `v`, then `u` is added to `v`'s dependents list.
    /// That means when type `v` is updated, type variable `u` is considered a
    /// "dependent".  This means that `u`'s bounds might need to be re-evaluated when `v` changes.
    ///
    /// In other words, this function records that `u` depends on `v`.
    ///
    /// Note: the dependents map stores the reverse mapping: from a type variable to the set of type
    /// variables that depend on it.
    pub fn add_dependency(&mut self, u: &TypeVarId, v: &Type) {
        // Iterate through all type variables involved in `v` and add `u` as a dependent.
        for dep_tv_id in v.involved_type_vars() {
            self.dependents.entry(dep_tv_id).or_default().insert(*u);
        }
    }

    pub fn converge(
        &mut self,
        tv_id: &TypeVarId,
        new_value: Type,
        convergence_type: ConverganceType,
    ) {
        let state = self.type_var_states.get(tv_id).unwrap();
        if matches!(state, TypeVarState::Converged { .. }) {
            panic!("Type var id {tv_id:?} already converged.");
        }
        self.type_var_states
            .insert(*tv_id, TypeVarState::Converged(new_value.clone()));
        self.updated_type_vars.insert(*tv_id);
        self.change_log.push(ChangeLogEntry {
            iteration: self.iteration,
            tv_id: *tv_id,
            kind: ChangeLogKind::Converged {
                new_type: new_value.clone(),
                convergence_type,
            },
        });

        let kind = || ChangeLogKind::DependencyConverged {
            dependent_var_id: *tv_id,
            new_value: new_value.clone(),
        };

        let mut log_entries = vec![];
        for id in self.get_all_dependents(tv_id) {
            if id == *tv_id {
                continue;
            }
            self.add_dependency(&id, &new_value);
            match self.type_var_states.get(&id).unwrap() {
                TypeVarState::Bounds {
                    lower_bounds,
                    upper_bounds,
                } => {
                    let new_lower_bounds: HashSet<Type> = lower_bounds
                        .iter()
                        .map(|l| self.resolve_type(l))
                        .filter(|l| *l != id.to_type())
                        .collect();
                    let new_upper_bounds: HashSet<Type> = upper_bounds
                        .iter()
                        .map(|u| self.resolve_type(u))
                        .filter(|l| *l != id.to_type())
                        .collect();
                    if new_lower_bounds != *lower_bounds || new_upper_bounds != *upper_bounds {
                        self.updated_type_vars.insert(id);
                        log_entries.push(ChangeLogEntry {
                            iteration: self.iteration,
                            tv_id: id,
                            kind: kind(),
                        });
                        self.type_var_states.insert(
                            id,
                            TypeVarState::Bounds {
                                lower_bounds: new_lower_bounds,
                                upper_bounds: new_upper_bounds,
                            },
                        );
                    }
                }
                TypeVarState::Converged(ty) => {
                    self.type_var_states
                        .insert(id, TypeVarState::Converged(self.resolve_type(ty)));
                }
            }
        }
        self.change_log.extend(log_entries);
    }

    pub fn new() -> Self {
        InferenceAlgorithmState {
            type_var_states: HashMap::new(),
            type_var_nodes: HashMap::new(),
            dependents: HashMap::new(),
            updated_type_vars: HashSet::new(),
            change_log: Vec::new(),
            next_type_var_id_counter: 0,

            iteration: 0,
            vmr_to_type_var: HashMap::new(),

            generic_type_vars: HashMap::new(),
            next_generic_id_counter: 0,
            user_defs: UserDefs::new(),
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
        if let std::collections::hash_map::Entry::Vacant(e) = self.type_var_nodes.entry(tv_id) {
            let node_info = node_info_fn(); // Create node_info only if it's a new TypeVar
            e.insert(node_info);
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
    pub fn add_type_var(&mut self, node_info: TypeVarNode) -> TypeVarId {
        let tv_id = self.fresh_type_var_id();
        trace!("Adding variable {}: {}", tv_id, node_info);
        self.ensure_type_var_exists(tv_id, || node_info);
        tv_id
    }

    fn fresh_type_var_id(&mut self) -> TypeVarId {
        let id = self.next_type_var_id_counter;
        self.next_type_var_id_counter += 1;
        TypeVarId::new(id)
    }

    /// Gets or creates a TypeVar for a VersionedMemoryReference within a specific function.
    pub fn get_or_create_type_var_for_vmr(
        &mut self,
        vmr: &VersionedMemoryReference,
        path: TypeVarPath,
    ) -> TypeVarId {
        if let Some(tv_id) = self.vmr_to_type_var.get(vmr) {
            // Create the path alias to this id
            return *tv_id;
        }

        let new_tv_id = self.create_memory_reference_type_var(path, *vmr);
        self.vmr_to_type_var.insert(*vmr, new_tv_id);
        new_tv_id
    }

    pub fn get_type_id_for_vmr(&self, vmr: &VersionedMemoryReference) -> Option<TypeVarId> {
        self.vmr_to_type_var.get(vmr).copied()
    }

    /// Creates a new TypeVar for an expression result or intermediate value.
    pub fn make_expression_type_var(&mut self, type_var_path: TypeVarPath) -> TypeVarId {
        let node_info = TypeVarNode {
            path: type_var_path,
            vmr: None,
        };
        self.add_type_var(node_info)
    }

    pub fn make_const_type_var(&mut self, type_var_path: TypeVarPath) -> TypeVarId {
        let node_info = TypeVarNode {
            path: type_var_path,
            vmr: None,
        };
        self.add_type_var(node_info)
    }

    fn create_memory_reference_type_var(
        &mut self,
        type_var_path: TypeVarPath,
        vmr: VersionedMemoryReference,
    ) -> TypeVarId {
        let node_info = TypeVarNode {
            path: type_var_path,
            vmr: Some(vmr),
        };
        self.add_type_var(node_info)
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
        reason: BoundChangeReason,
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
        reason: BoundChangeReason,
    ) -> bool {
        self.update_bound_internal(tv_id, new_upper_constraint, BoundDirection::Upper, reason)
    }

    pub fn has_type_var(&self, tv_id: &TypeVarId) -> bool {
        self.type_var_nodes.contains_key(tv_id)
    }

    /// Retrieves the `TypeVarNode` for a given `TypeVarId`.
    /// Returns `None` if the `TypeVarId` is not found.
    pub fn get_type_var_node(&self, tv_id: &TypeVarId) -> Option<&TypeVarNode> {
        self.type_var_nodes.get(tv_id)
    }

    /// Provides an iterator over all `TypeVarId`s and their associated `TypeVarState`.
    /// Returns items in deterministic order sorted by TypeVarId.
    pub fn iter_all_type_nodes(&self) -> impl Iterator<Item = (&TypeVarId, &TypeVarNode)> {
        let mut items: Vec<_> = self.type_var_nodes.iter().collect();
        items.sort_by_key(|(id, _)| id.index());
        items.into_iter()
    }

    pub fn iter_all_type_states(&self) -> impl Iterator<Item = (&TypeVarId, &TypeVarState)> {
        let mut items: Vec<_> = self.type_var_states.iter().collect();
        items.sort_by_key(|(id, _)| id.index());
        items.into_iter()
    }

    pub fn iter_all_vmr_to_type_var_id(
        &self,
    ) -> impl Iterator<Item = (&VersionedMemoryReference, &TypeVarId)> {
        let mut items: Vec<_> = self.vmr_to_type_var.iter().collect();
        items.sort_by_key(|(_, type_var_id)| type_var_id.index());
        items.into_iter()
    }

    /// Returns a `Vec` of `TypeVarId`s whose bounds have been updated since the last
    /// call to this method, and clears the internal tracking set.
    /// This "takes" the updated variables, resetting the tracker for the next iteration.
    pub fn take_updated_vars(&mut self) -> Vec<TypeVarId> {
        // TypeVarId must be Clone
        let updated_set = std::mem::take(&mut self.updated_type_vars);
        updated_set.into_iter().collect()
    }

    pub fn get_updated_type_vars(&self) -> &HashSet<TypeVarId> {
        &self.updated_type_vars
    }

    pub fn get_all_dependencies(&self, tv_id: &TypeVarId) -> HashSet<TypeVarId> {
        let g = TypeVarDependencyGraph { state: self };
        let mut dfs = petgraph::visit::Dfs::new(&g, *tv_id);
        let mut out = HashSet::new();
        while let Some(v) = dfs.next(&g) {
            out.insert(v);
        }
        out
    }

    pub fn get_all_dependents(&self, tv_id: &TypeVarId) -> HashSet<TypeVarId> {
        let g = Reversed(TypeVarDependencyGraph { state: self });
        let mut dfs = petgraph::visit::Dfs::new(&g, *tv_id);
        let mut out = HashSet::new();
        while let Some(v) = dfs.next(&g) {
            out.insert(v);
        }
        out
    }

    /// Creates a new generic type variable
    pub fn create_generic_type_var(
        &mut self,
        name: String,
        bounds: TypeBounds,
    ) -> GenericTypeVarId {
        let id = GenericTypeVarId::new(self.next_generic_id_counter);
        self.next_generic_id_counter += 1;

        let generic_var = GenericTypeVar { id, name, bounds };
        self.generic_type_vars.insert(id, generic_var);

        id
    }

    /// Creates a new generic type variable with automatic naming
    pub fn create_generic_type_var_with_bounds(&mut self, bounds: TypeBounds) -> GenericTypeVarId {
        let id = GenericTypeVarId::new(self.next_generic_id_counter);
        let name = Self::generate_generic_name(self.next_generic_id_counter);
        self.next_generic_id_counter += 1;

        let generic_var = GenericTypeVar { id, name, bounds };
        self.generic_type_vars.insert(id, generic_var);

        id
    }

    /// Generate a generic type variable name (T, U, V, etc.)
    fn generate_generic_name(index: usize) -> String {
        // Use T, U, V, W, X, Y, Z, then T1, T2, etc.
        const GENERIC_NAMES: &[&str] = &["T", "U", "V", "W", "X", "Y", "Z"];
        if index < GENERIC_NAMES.len() {
            GENERIC_NAMES[index].to_string()
        } else {
            format!("T{}", index - GENERIC_NAMES.len() + 1)
        }
    }

    /// Gets a generic type variable by ID
    pub fn get_generic_type_var(&self, id: &GenericTypeVarId) -> Option<&GenericTypeVar> {
        self.generic_type_vars.get(id)
    }

    /// Get the current generic ID counter value
    pub fn get_generic_id_counter(&self) -> usize {
        self.next_generic_id_counter
    }

    /// Set the generic ID counter value
    pub fn set_generic_id_counter(&mut self, value: usize) {
        self.next_generic_id_counter = value;
    }

    /// Get all generic type variables
    pub fn generic_type_vars(&self) -> HashMap<GenericTypeVarId, GenericTypeVar> {
        self.generic_type_vars.clone()
    }

    pub(crate) fn get_iteration(&self) -> usize {
        self.iteration
    }
}

#[derive(Copy, Clone)]
struct TypeVarDependencyGraph<'a> {
    state: &'a InferenceAlgorithmState,
}

impl GraphBase for TypeVarDependencyGraph<'_> {
    type EdgeId = ();

    type NodeId = TypeVarId;
}

impl<'a> IntoNeighborsDirected for TypeVarDependencyGraph<'a> {
    type NeighborsDirected = <HashSet<TypeVarId> as IntoIterator>::IntoIter;

    fn neighbors_directed(self, n: Self::NodeId, d: Direction) -> Self::NeighborsDirected {
        match d {
            Direction::Outgoing => IntoNeighbors::neighbors(self, n),
            Direction::Incoming => self
                .state
                .dependents
                .get(&n)
                .cloned()
                .unwrap_or_else(HashSet::new)
                .into_iter(),
        }
    }
}

impl<'a> IntoNeighbors for TypeVarDependencyGraph<'a> {
    type Neighbors = <HashSet<TypeVarId> as IntoIterator>::IntoIter;

    fn neighbors(self, tv_id: TypeVarId) -> Self::Neighbors {
        let mut out = HashSet::new();
        match self.state.get_type_var_state(&tv_id) {
            Some(TypeVarState::Bounds {
                lower_bounds,
                upper_bounds,
            }) => {
                let mut out = HashSet::new();
                for bound in upper_bounds.iter().chain(lower_bounds.iter()) {
                    bound.insert_involved_type_vars(&mut out);
                }
            }
            Some(TypeVarState::Converged(ty)) => {
                // A converged type may have depenenencies. It may converged say to a Pointer(tv_id_other)
                ty.insert_involved_type_vars(&mut out);
            }
            None => panic!("TypeVarId {tv_id:?} not found"),
        }
        out.into_iter()
    }
}

impl GraphRef for TypeVarDependencyGraph<'_> {}

impl Visitable for TypeVarDependencyGraph<'_> {
    type Map = HashSet<TypeVarId>;

    #[doc = r" Create a new visitor map"]
    fn visit_map(&self) -> Self::Map {
        HashSet::new()
    }

    #[doc = r" Reset the visitor map (and resize to new size of graph if needed)"]
    fn reset_map(&self, map: &mut Self::Map) {
        map.clear()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::disasm::{
        test_utils::init_logging,
        v3::{
            lir::{ExpressionPath, TypeVarPath},
            FunctionId, InstructionId,
        },
    };

    // Mock/dummy TypeVarNode creation for tests
    // Ensure this is compatible with the actual TypeVarNode structure.
    fn make_node(instruction_id: InstructionId, function_id: FunctionId) -> TypeVarNode {
        TypeVarNode {
            path: TypeVarPath::Output {
                function_id,
                instruction_id,
                expression_path: ExpressionPath::root(),
            },
            vmr: None,
        }
    }

    #[test]
    fn test_bound_updates_and_tracking() {
        init_logging();
        let mut state = InferenceAlgorithmState::new();

        let tv1_id = state.add_type_var(make_node(InstructionId::new(1), FunctionId::new(0)));

        let tv2_id = state.add_type_var(make_node(InstructionId::new(2), FunctionId::new(0)));

        // Initial updates
        assert!(state.update_lower_bound(&tv1_id, &Type::Int, BoundChangeReason::Test));
        assert!(state.update_upper_bound(&tv1_id, &Type::Int, BoundChangeReason::Test)); // Any.glb(Int) = Int

        assert!(state.update_lower_bound(&tv2_id, &Type::Bool, BoundChangeReason::Test));
        assert!(state.update_upper_bound(&tv2_id, &Type::NumericLiteral, BoundChangeReason::Test)); // Any.glb(Truthy) = Truthy

        let updated = state.take_updated_vars();
        assert_eq!(updated.len(), 2);
        assert!(updated.contains(&tv1_id));
        assert!(updated.contains(&tv2_id));

        // Tracker should be empty now
        assert!(state.take_updated_vars().is_empty());

        // No change update
        assert!(!state.update_lower_bound(&tv1_id, &Type::Int, BoundChangeReason::Test)); // Int.lub(Int) = Int, no change
        assert!(state.take_updated_vars().is_empty()); // Still empty

        // Change update again (assuming Bool <: Truthy, so glb(Truthy, Bool) = Bool)
        assert!(state.update_upper_bound(&tv2_id, &Type::Bool, BoundChangeReason::Test));
        let updated_again = state.take_updated_vars();
        assert_eq!(updated_again.len(), 1);
        assert!(updated_again.contains(&tv2_id));
    }
}
