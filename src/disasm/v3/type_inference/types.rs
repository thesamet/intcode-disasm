use itertools::Itertools;
use log::trace;

use crate::disasm::v3::{
    define_id_type,
    lir::Expression,
    ssa::{SsaMemoryReference, VersionedMemoryReference},
    FunctionId, InstructionId,
};

define_id_type!(TypeVarId);

impl TypeVarId {
    pub fn display_with<'a>(
        &self,
        registry: &'a (impl TypeVarRegistry + Sized),
    ) -> DisplayableTypeVarId<'a> {
        DisplayableTypeVarId {
            id: *self,
            registry,
        }
    }

    pub fn to_type(&self) -> Type {
        Type::TypeVar(*self)
    }
}

pub struct DisplayableTypeVarId<'a> {
    id: TypeVarId,
    registry: &'a dyn TypeVarRegistry,
}

impl<'a> fmt::Display for DisplayableTypeVarId<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = &self
            .registry
            .get_type_var_node(&self.id)
            .unwrap_or_else(|| panic!("TypeVarId {} not found", self.id))
            .kind;
        write!(f, "{kind}")
    }
}

/// Represents the possible types in our type system
use std::fmt;

use super::{
    type_bounds_map::{BoundDirection, TypeVarRegistry},
    InferenceAlgorithmState, TypeVarState,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Type {
    /// Nothing type (bottom of the lattice, subtype of all types)
    Nothing,
    /// Integer type
    Int,
    /// Boolean type (result of comparisons)
    Bool,
    /// Character type (for input/output operations)
    Char,
    /// Pointer type with optional pointee type
    Pointer(Box<Type>),
    /// Function type with parameter and return types. The types must be tuples.
    Function {
        params: Box<Type>,  // Should be Type::Tuple
        returns: Box<Type>, // Should be Type::Tuple
    },
    /// Type variable used during inference
    TypeVar(TypeVarId),
    /// Tuple type (for function arguments and returns)
    Tuple(Vec<Type>),
    // A marker type representing anything that can be used as a condition.
    Truthy,
    /// Any type (top of the lattice, supertype of all types)
    Any,

    /// Symbolic representation of the Greatest Lower Bound of other types.
    GLB(Vec<Type>),
    /// Symbolic representation of the Least Upper Bound of other types.
    LUB(Vec<Type>),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum YesNoMaybe {
    Yes,
    No,
    Maybe,
}

impl YesNoMaybe {
    pub fn is_yes(&self) -> bool {
        match self {
            YesNoMaybe::Yes => true,
            _ => false,
        }
    }
}

impl From<bool> for YesNoMaybe {
    fn from(b: bool) -> Self {
        if b {
            YesNoMaybe::Yes
        } else {
            YesNoMaybe::No
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CanonicalFormOperation {
    GLB,
    LUB,
}
impl Type {
    pub fn is_concrete_type(&self) -> bool {
        match self {
            Type::Int | Type::Bool | Type::Char => true,
            Type::Any | Type::Nothing | Type::Truthy => false,
            Type::Pointer(pointee) => pointee.is_concrete_type(),
            Type::Function { params, returns } => {
                params.is_concrete_type() && returns.is_concrete_type()
            }
            Type::Tuple(elements) => elements.iter().all(|e| e.is_concrete_type()),
            Type::GLB(types) => types.iter().all(|t| t.is_concrete_type()),
            Type::LUB(types) => types.iter().all(|t| t.is_concrete_type()),
            Type::TypeVar(_) => false,
        }
    }

    pub fn resolve(&self, registry: &impl TypeVarRegistry) -> Type {
        let mut typ = self.clone();
        loop {
            let mut changed = false;

            typ = typ.map(
                &mut |tv_id| match registry.get_type_var_state(&tv_id).unwrap() {
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

    fn resolve_bounds(&self, registry: &impl TypeVarRegistry) -> (Type, Type) {
        let v = match self {
            Type::Nothing | Type::Int | Type::Bool | Type::Char | Type::Truthy | Type::Any => {
                (self.clone(), self.clone())
            }

            Type::Function { params, returns } => {
                let (lower_params, upper_params) = params.resolve_bounds(registry);
                let (lower_returns, upper_returns) = returns.resolve_bounds(registry);
                (
                    Type::Function {
                        params: Box::new(upper_params),
                        returns: Box::new(lower_returns),
                    },
                    Type::Function {
                        params: Box::new(lower_params),
                        returns: Box::new(upper_returns),
                    },
                )
            }
            Type::TypeVar(type_var_id) => (
                registry.lower_bound(type_var_id).resolve(registry),
                registry.upper_bound(type_var_id).resolve(registry),
            ),
            Type::Tuple(items) => {
                let mut lower_items = Vec::new();
                let mut upper_items = Vec::new();
                for item in items {
                    let (lower, upper) = item.resolve_bounds(registry);
                    lower_items.push(lower);
                    upper_items.push(upper);
                }
                (Type::Tuple(lower_items), Type::Tuple(upper_items))
            }
            Type::Pointer(p) => {
                let (lower, upper) = p.resolve_bounds(registry);
                (
                    Type::Pointer(Box::new(lower)),
                    Type::Pointer(Box::new(upper)),
                )
            }
            Type::GLB(items) => {
                let mut lower_components = Vec::new();
                let mut upper_components = Vec::new();
                for item in items {
                    let (lower, upper) = item.resolve_bounds(registry);
                    lower_components.push(lower);
                    upper_components.push(upper);
                }
                (Type::GLB(lower_components), Type::GLB(upper_components))
            }
            Type::LUB(items) => {
                let mut lower_components = Vec::new();
                let mut upper_components = Vec::new();
                for item in items {
                    let (lower, upper) = item.resolve_bounds(registry);
                    lower_components.push(lower);
                    upper_components.push(upper);
                }
                (Type::LUB(lower_components), Type::LUB(upper_components))
            }
        };
        v
    }

    /// Checks if `self` is a subtype of `other` (self <: other).
    pub fn is_subtype_of(&self, other: &Type, registry: &impl TypeVarRegistry) -> YesNoMaybe {
        println!("Performing is_subtype for {} and {}", self, other);
        if self == other {
            return true.into();
        }
        if *self == Type::Nothing {
            return true.into();
        }
        if *other == Type::Any {
            return true.into();
        }
        if *other == Type::Nothing {
            if *self == Type::Nothing {
                return YesNoMaybe::Yes;
            }
            if self.is_var_free() {
                return YesNoMaybe::No;
            }
            return YesNoMaybe::Maybe;
        }
        if *self == Type::Any {
            if *other == Type::Any {
                return YesNoMaybe::Yes;
            }
            if other.is_var_free() {
                return YesNoMaybe::No;
            }
            return YesNoMaybe::Maybe;
        }
        match (self, other) {
            (x, y) if x == y => true.into(),
            (_, Type::Any) => true.into(),
            (Type::Nothing, _) => true.into(),
            (Type::Any, other) => {
                let (resolved_lower, resolved_upper) = other.resolve_bounds(registry);
                if resolved_lower == Type::Any {
                    true.into()
                } else if resolved_upper.is_var_free() && resolved_upper != Type::Any {
                    false.into()
                } else {
                    YesNoMaybe::Maybe
                }
            }
            (other, Type::Nothing) => {
                let (resolved_lower, resolved_upper) = other.resolve_bounds(registry);
                if resolved_upper == Type::Nothing {
                    true.into()
                } else if resolved_lower.is_var_free() && resolved_lower != Type::Nothing {
                    false.into()
                } else {
                    YesNoMaybe::Maybe
                }
            }
            (Type::TypeVar(tv_id), other) => {
                let ub = registry.upper_bound(tv_id);
                println!("for {} we have {}", tv_id, ub);
                println!(
                    " and other  ({}) bounds are: {} ",
                    other,
                    other.resolve_bounds(registry).0,
                );
                println!(
                    "So for {} <:  {} we have.... {:?}",
                    self,
                    other,
                    ub.is_subtype_of(&other.resolve_bounds(registry).0, registry)
                );
                if ub != self
                    && ub
                        .is_subtype_of(&other.resolve_bounds(registry).0, registry)
                        .is_yes()
                {
                    YesNoMaybe::Yes
                } else {
                    YesNoMaybe::Maybe
                }
            }
            (Type::Char, Type::Int) => true.into(),
            (Type::Bool, Type::Int) => true.into(),
            (Type::Pointer(_), Type::Int) => true.into(),
            (Type::Function { .. }, Type::Int) => true.into(),

            (Type::Function { .. }, Type::Pointer(p_target)) => {
                // Function <: Pointer(Int) and Function <: Pointer(Any)
                (**p_target == Type::Int || **p_target == Type::Any).into()
            }

            (Type::Int, Type::Truthy) => true.into(),
            (Type::Bool, Type::Truthy) => true.into(),
            (Type::Char, Type::Truthy) => true.into(),
            (Type::Pointer(_), Type::Truthy) => true.into(),
            (Type::Function { .. }, Type::Truthy) => true.into(),

            (Type::Pointer(p1), Type::Pointer(p2)) => p1.is_subtype_of(p2, registry),
            (
                Type::Function {
                    params: params1,
                    returns: returns1,
                },
                Type::Function {
                    params: params2,
                    returns: returns2,
                },
            ) => {
                match (
                    params2.is_subtype_of(params1, registry),
                    returns1.is_subtype_of(returns2, registry),
                ) {
                    (YesNoMaybe::Yes, YesNoMaybe::Yes) => YesNoMaybe::Yes,
                    (YesNoMaybe::No, _) => YesNoMaybe::No,
                    (_, YesNoMaybe::No) => YesNoMaybe::No,
                    _ => YesNoMaybe::Maybe,
                }
            }
            (Type::Tuple(v1), Type::Tuple(v2)) => {
                if v1.len() < v2.len() {
                    return YesNoMaybe::No;
                }
                let mut result = YesNoMaybe::Yes;
                for (i, t2_elem) in v2.iter().enumerate() {
                    match v1[i].is_subtype_of(t2_elem, registry) {
                        YesNoMaybe::Yes => {}
                        YesNoMaybe::No => return YesNoMaybe::No,
                        YesNoMaybe::Maybe => result = YesNoMaybe::Maybe,
                    }
                }
                result
            }
            (_, Type::GLB(types)) => {
                // For X <: GLB(A, B, ...), we need X <: A and X <: B and ...
                let mut result = YesNoMaybe::Yes;
                for t in types.iter() {
                    match self.is_subtype_of(t, registry) {
                        YesNoMaybe::Yes => {}
                        YesNoMaybe::No => return YesNoMaybe::No,
                        YesNoMaybe::Maybe => result = YesNoMaybe::Maybe,
                    }
                }
                result
            }
            (Type::GLB(types), _) => {
                // For GLB(A, B, ...) <: X, we need at least one of A <: X or B <: X or ...
                // However, this is not always sufficient. The correct rule is that
                // GLB(A, B, ...) <: X if GLB(A, B, ...) is well-defined and represents
                // a type that is a subtype of X. For simplicity, we check if any component
                // is a subtype, which gives us a sufficient condition.
                let mut has_yes = false;
                let mut has_maybe = false;

                for t in types.iter() {
                    match t.is_subtype_of(other, registry) {
                        YesNoMaybe::Yes => has_yes = true,
                        YesNoMaybe::Maybe => has_maybe = true,
                        YesNoMaybe::No => {} // Continue checking other types
                    }
                }

                if has_yes {
                    YesNoMaybe::Yes
                } else if has_maybe {
                    YesNoMaybe::Maybe
                } else {
                    YesNoMaybe::Maybe // Conservative: we can't definitively say No
                }
            }
            (Type::LUB(types), _) => {
                // LUB(A, B, ...) <: T if all A <: T and B <: T and ...
                // This is because LUB represents the least upper bound (join) of all component types,
                // so for the LUB to be a subtype of T, every component must also be a subtype of T.
                let mut result = YesNoMaybe::Yes;
                for t in types.iter() {
                    match t.is_subtype_of(other, registry) {
                        YesNoMaybe::Yes => {}
                        YesNoMaybe::No => return YesNoMaybe::No,
                        YesNoMaybe::Maybe => result = YesNoMaybe::Maybe,
                    }
                }
                result
            }
            (_, Type::LUB(types)) => {
                // For X <: LUB(A, B, ...), we need X <: A or X <: B or ... (at least one)
                // This is because LUB represents the least upper bound (join) of all component types,
                // so for X to be a subtype of the LUB, X needs to be a subtype of at least one
                // component. We check if any component is a supertype of X, which gives us
                // a sufficient condition.
                let mut has_yes = false;
                let mut has_maybe = false;

                for t in types.iter() {
                    match self.is_subtype_of(t, registry) {
                        YesNoMaybe::Yes => has_yes = true,
                        YesNoMaybe::Maybe => has_maybe = true,
                        YesNoMaybe::No => {} // Continue checking other types
                    }
                }

                if has_yes {
                    YesNoMaybe::Yes
                } else if has_maybe {
                    YesNoMaybe::Maybe
                } else {
                    YesNoMaybe::Maybe // Conservative: we can't definitively say No
                }
            }

            (other, Type::TypeVar(tv_id)) => {
                /*
                if other
                    .resolve_bounds(registry)
                    .1
                    .is_subtype_of(&registry.lower_bound(tv_id), registry)
                    .is_yes()
                {
                    YesNoMaybe::Yes
                } else {
                    YesNoMaybe::Maybe
                }
                */
                YesNoMaybe::Maybe
            }

            _ => false.into(),
        }
    }

    /// Applies a mapping function to all TypeVarIds within the type.
    pub fn map<F>(&self, var_mapper: &mut F) -> Type
    where
        F: FnMut(&TypeVarId) -> Type,
    {
        match self {
            Type::TypeVar(id) => var_mapper(id),
            Type::Tuple(elements) => {
                Type::Tuple(elements.iter().map(|e| e.map(var_mapper)).collect())
            }
            Type::Function { params, returns } => Type::Function {
                params: Box::new(params.map(var_mapper)),
                returns: Box::new(returns.map(var_mapper)),
            },
            Type::GLB(types) => Type::GLB(types.iter().map(|t| t.map(var_mapper)).collect()),
            Type::LUB(types) => Type::LUB(types.iter().map(|t| t.map(var_mapper)).collect()),
            Type::Nothing => Type::Nothing,
            Type::Int => Type::Int,
            Type::Bool => Type::Bool,
            Type::Char => Type::Char,
            Type::Pointer(pointee) => Type::Pointer(Box::new(pointee.map(var_mapper))),
            Type::Truthy => Type::Truthy,
            Type::Any => Type::Any,
        }
    }

    /// Computes the greatest lower bound (GLB) of two types, returning a canonical form.
    /// Assumes Type::GLB is `GLB(Vec<Type>)`.
    pub fn glb(t1: &Type, t2: &Type, registry: &impl TypeVarRegistry) -> Type {
        println!(
            "GLB of {} and {}",
            t1.display_with(registry),
            t2.display_with(registry)
        );
        // Shortcut: if one is a subtype of the other
        if t1.is_subtype_of(t2, registry).is_yes() {
            return t1.clone();
        }
        if t2.is_subtype_of(t1, registry).is_yes() {
            return t2.clone();
        }

        // Structural rules
        match (t1, t2) {
            (Type::Pointer(p1), Type::Pointer(p2)) => {
                let inner_glb = Self::glb(p1.as_ref(), p2.as_ref(), registry);
                if inner_glb == Type::Nothing {
                    return Type::Nothing;
                }
                Type::Pointer(Box::new(inner_glb))
            }
            (
                Type::Function {
                    params: params1,
                    returns: returns1,
                },
                Type::Function {
                    params: params2,
                    returns: returns2,
                },
            ) => {
                // Parameters are contravariant (LUB for GLB of functions)
                // Returns are covariant (GLB for GLB of functions)
                let lub_params = Self::lub(params1.as_ref(), params2.as_ref(), registry);
                let glb_returns = Self::glb(returns1.as_ref(), returns2.as_ref(), registry);

                if lub_params == Type::Any || glb_returns == Type::Nothing {
                    Type::Nothing // This function signature is impossible
                } else {
                    Type::Function {
                        params: Box::new(lub_params),
                        returns: Box::new(glb_returns),
                    }
                }
            }
            (Type::Tuple(v1), Type::Tuple(v2)) => {
                let len1 = v1.len();
                let len2 = v2.len();
                let max_len = std::cmp::max(len1, len2);
                let mut res_vec = Vec::with_capacity(max_len);
                for i in 0..max_len {
                    match (v1.get(i), v2.get(i)) {
                        (Some(e1), Some(e2)) => {
                            res_vec.push(Self::glb(e1, e2, registry));
                        }
                        (Some(e1), None) => res_vec.push(e1.clone()),
                        (None, Some(e2)) => res_vec.push(e2.clone()),
                        (None, None) => unreachable!(),
                    }
                }
                Type::Tuple(res_vec)
            }
            // Cases for fundamentally incompatible concrete types that are not covered by subtyping
            (Type::Bool, Type::Pointer(_)) | (Type::Pointer(_), Type::Bool) => Type::Nothing,
            (Type::Char, Type::Pointer(_)) | (Type::Pointer(_), Type::Char) => Type::Nothing,
            // GLB(Int, Pointer) could be argued depending on pointer representation.
            // Current is_subtype_of implies Pointer(_) <: Int. So GLB(Int, Pointer(X)) = Pointer(X). This is handled by shortcut.
            // If they are not subtypes, then GLB(Int, Pointer(X)) = Nothing.
            (Type::Int, Type::Pointer(p))
                if !Type::Pointer(p.clone())
                    .is_subtype_of(&Type::Int, registry)
                    .is_yes() =>
            {
                Type::Nothing
            }
            (Type::Pointer(p), Type::Int)
                if !Type::Pointer(p.clone())
                    .is_subtype_of(&Type::Int, registry)
                    .is_yes() =>
            {
                Type::Nothing
            }

            (Type::Bool, Type::Function { .. }) | (Type::Function { .. }, Type::Bool) => {
                Type::Nothing
            }
            // Add Char vs Function
            (Type::Char, Type::Function { .. }) | (Type::Function { .. }, Type::Char) => {
                Type::Nothing
            }
            (Type::Char, Type::Bool) | (Type::Bool, Type::Char) => Type::Nothing,
            // Add Int vs Function (if not covered by Function <: Int)
            (Type::Int, Type::Function { .. })
                if !Type::Function {
                    params: Box::new(Type::Any),
                    returns: Box::new(Type::Any),
                }
                .is_subtype_of(&Type::Int, registry)
                .is_yes() =>
            {
                Type::Nothing
            }
            (Type::Function { .. }, Type::Int)
                if !Type::Function {
                    params: Box::new(Type::Any),
                    returns: Box::new(Type::Any),
                }
                .is_subtype_of(&Type::Int, registry)
                .is_yes() =>
            {
                Type::Nothing
            }

            (Type::GLB(types), x) | (x, Type::GLB(types)) => {
                let mut t = types.clone();
                t.push(x.clone()); // x is &Type, push expects Type
                Self::build_compound_type(&t, CanonicalFormOperation::GLB, registry)
            }
            // Default: form a symbolic GLB. This handles TypeVars not caught by shortcuts.
            _ => Type::GLB(vec![t1.clone(), t2.clone()]),
        }
    }

    /// Computes the least upper bound (LUB) of two types, returning a canonical form.
    /// Assumes Type::LUB is `LUB(Vec<Type>)`.
    pub fn lub(t1: &Type, t2: &Type, registry: &impl TypeVarRegistry) -> Type {
        // Shortcut: if one is a supertype of the other (t2 <: t1 means t1 is supertype)
        if t2.is_subtype_of(t1, registry).is_yes() {
            return t1.clone();
        }
        if t1.is_subtype_of(t2, registry).is_yes() {
            return t2.clone();
        }

        // Structural rules
        match (t1, t2) {
            (Type::Pointer(p1), Type::Pointer(p2)) => {
                Type::Pointer(Box::new(Self::lub(p1.as_ref(), p2.as_ref(), registry)))
            }
            (
                Type::Function {
                    params: params1,
                    returns: returns1,
                },
                Type::Function {
                    params: params2,
                    returns: returns2,
                },
            ) => {
                // Parameters are contravariant (GLB for LUB of functions)
                // Returns are covariant (LUB for LUB of functions)
                let glb_params = Self::glb(params1.as_ref(), params2.as_ref(), registry);
                let lub_returns = Self::lub(returns1.as_ref(), returns2.as_ref(), registry);

                if glb_params == Type::Nothing || lub_returns == Type::Any {
                    Type::Any
                } else {
                    Type::Function {
                        params: Box::new(glb_params),
                        returns: Box::new(lub_returns),
                    }
                }
            }
            (Type::Tuple(v1), Type::Tuple(v2)) => {
                let min_len = std::cmp::min(v1.len(), v2.len());
                let mut res_vec = Vec::with_capacity(min_len);
                for i in 0..min_len {
                    res_vec.push(Self::lub(&v1[i], &v2[i], registry));
                }
                Type::Tuple(res_vec)
            }

            // Specific handling for Bool/Char LUB based on tests
            (Type::Bool, Type::Char) | (Type::Char, Type::Bool) => Type::Truthy,

            // General Truthy promotion: if both are subtypes of Truthy, their LUB is Truthy.
            // This applies if shortcuts didn't (i.e., they are not subtypes of each other).
            (a, b)
                if a.is_subtype_of(&Type::Truthy, registry).is_yes()
                    && b.is_subtype_of(&Type::Truthy, registry).is_yes() =>
            {
                Type::Truthy
            }

            (Type::LUB(types), x) | (x, Type::LUB(types)) => {
                let mut new_types = types.clone();
                new_types.push(x.clone());
                Self::build_compound_type(&new_types, CanonicalFormOperation::LUB, registry)
            }

            // Default case, including TypeVars not caught by shortcuts, or other unhandled pairs.
            // Forms a LUB construct.
            _ => Type::LUB(vec![t1.clone(), t2.clone()]),
        }
    }

    pub fn glb_types(types: &[Type], registry: &impl TypeVarRegistry) -> Type {
        Self::build_compound_type(types, CanonicalFormOperation::GLB, registry)
    }

    pub fn lub_types(types: &[Type], registry: &impl TypeVarRegistry) -> Type {
        Self::build_compound_type(types, CanonicalFormOperation::LUB, registry)
    }

    fn build_compound_type(
        types: &[Type],
        operation: CanonicalFormOperation,
        registry: &impl TypeVarRegistry,
    ) -> Type {
        println!("Build compound: {:?}", types);
        let mut queue = types.iter().cloned().collect_vec();
        let mut flat_types = Vec::new();
        while let Some(t) = queue.pop() {
            match t {
                Type::GLB(types) if operation == CanonicalFormOperation::GLB => {
                    queue.extend(types.iter().cloned())
                }
                Type::LUB(types) if operation == CanonicalFormOperation::LUB => {
                    queue.extend(types.iter().cloned())
                }
                _ => flat_types.push(t.clone()),
            }
        }
        let mut flat_types = flat_types.into_iter().unique().sorted().collect_vec();
        let mut types_to_remove = vec![];
        let mut types_to_add = vec![];
        let mut changed = true;
        while changed {
            changed = false;
            for (i, t1) in flat_types.iter().enumerate() {
                for (j, t2) in flat_types.iter().enumerate().skip(i + 1) {
                    let inner = match operation {
                        CanonicalFormOperation::GLB => Self::glb(t1, t2, registry),
                        CanonicalFormOperation::LUB => Self::lub(t1, t2, registry),
                    };
                    match inner {
                        Type::GLB(_) if operation == CanonicalFormOperation::GLB => {}
                        Type::LUB(_) if operation == CanonicalFormOperation::LUB => {}
                        other => {
                            // types could be simplified
                            types_to_remove.push(i);
                            types_to_remove.push(j);
                            types_to_add.push(other);
                            changed = true;
                        }
                    }
                }
            }
            if changed {
                flat_types = flat_types
                    .into_iter()
                    .enumerate()
                    .filter(|(i, _)| !types_to_remove.contains(i))
                    .map(|(_, t)| t)
                    .chain(types_to_add.iter().cloned())
                    .unique()
                    .sorted()
                    .collect_vec();
            }
        }
        if flat_types.is_empty() {
            match operation {
                CanonicalFormOperation::GLB => return Type::Nothing,
                CanonicalFormOperation::LUB => return Type::Any,
            }
        }

        if flat_types.is_empty() {
            match operation {
                CanonicalFormOperation::GLB => return Type::Any,
                CanonicalFormOperation::LUB => return Type::Nothing,
            }
        }

        if flat_types.len() == 1 {
            return flat_types[0].clone();
        }
        match operation {
            CanonicalFormOperation::GLB => Type::GLB(flat_types),
            CanonicalFormOperation::LUB => Type::LUB(flat_types),
        }
    }

    pub fn display_with<'a, 'b, F>(&'a self, registry: &'b F) -> DisplayableType<'a, 'b, F>
    where
        F: TypeVarRegistry,
    {
        DisplayableType { ty: self, registry }
    }

    pub fn pointer(pointee: Type) -> Type {
        Type::Pointer(Box::new(pointee))
    }

    pub fn tuple(elements: &[Type]) -> Type {
        Type::Tuple(elements.to_vec())
    }

    pub fn function(params_type: Type, returns_type: Type) -> Type {
        // Renamed args to params_type
        Type::Function {
            params: Box::new(params_type),
            returns: Box::new(returns_type),
        }
    }

    // When computing upper bounds or lower bounds, it could happen that the same type we are computing bounds for
    // appears in a top-level GLB or LUB. This function removes the given variable from the top-level GLB and LUB,
    // and attempts simplifying it before returning it. If the type is not a GLB or LUB, it is returned unchanged.
    pub fn remove_cycles_from_glb_lub(
        &self,
        t: &TypeVarId,
        state: &InferenceAlgorithmState,
        direction: BoundDirection,
    ) -> Type {
        match self {
            Type::TypeVar(s) if s == t => {
                // If the type is the same as the variable, remove it.
                return match direction {
                    BoundDirection::Lower => Type::Nothing,
                    BoundDirection::Upper => Type::Any,
                };
            }
            Type::GLB(types) => {
                let filtered_types: Vec<Type> = types
                    .iter()
                    .filter(|typ| match typ {
                        Type::TypeVar(id) => id != t,
                        _ => true,
                    })
                    .cloned()
                    .collect();
                Type::glb_types(&filtered_types, state)
            }
            Type::LUB(types) => {
                let filtered_types: Vec<Type> = types
                    .iter()
                    .filter(|typ| match typ {
                        Type::TypeVar(id) => id != t,
                        _ => true,
                    })
                    .cloned()
                    .collect();
                Type::lub_types(&filtered_types, state)
            }
            _ => self.clone(),
        }
    }

    // The public wrappers `form_canonical_glb` and `form_canonical_lub` were removed in the previous step
    // as the public `glb` and `lub` now call `_form_canonical_compound_type` directly in their default cases
    // and for canonicalizing inputs in shortcut cases.

    /// Collects all TypeVarIds involved in this type, including nested ones.
    ///
    /// # Arguments
    /// * `type_vars`: A mutable HashSet to which discovered TypeVarIds will be added.
    pub fn collect_involved_type_vars(&self, type_vars: &mut std::collections::HashSet<TypeVarId>) {
        match self {
            Type::TypeVar(id) => {
                type_vars.insert(*id);
            }
            Type::Pointer(inner_type) => {
                inner_type.collect_involved_type_vars(type_vars);
            }
            Type::Function { params, returns } => {
                params.collect_involved_type_vars(type_vars);
                returns.collect_involved_type_vars(type_vars);
            }
            Type::Tuple(elements) => {
                for element_type in elements {
                    element_type.collect_involved_type_vars(type_vars);
                }
            }
            Type::GLB(types) | Type::LUB(types) => {
                types
                    .iter()
                    .for_each(|t| t.collect_involved_type_vars(type_vars));
            }
            // Primitive types and Any/Nothing/Truthy don't contain TypeVars directly
            Type::Nothing | Type::Int | Type::Bool | Type::Char | Type::Truthy | Type::Any => {
                // No nested type vars
            }
        }
    }

    pub fn is_var_free(&self) -> bool {
        match self {
            Type::TypeVar(_) => false,
            Type::Tuple(elements) => elements.iter().all(|e| e.is_var_free()),
            Type::Function { params, returns } => params.is_var_free() && returns.is_var_free(),
            Type::GLB(types) | Type::LUB(types) => types.iter().all(|t| t.is_var_free()),
            Type::Nothing | Type::Int | Type::Bool | Type::Char | Type::Truthy | Type::Any => true,
            Type::Pointer(pointee) => pointee.is_var_free(),
        }
    }

    pub fn function_pointer_type(args: &[Type], returns: &[Type]) -> Type {
        // Represent function pointers directly as Function signatures
        Type::Function {
            params: Box::new(Type::Tuple(args.to_vec())),
            returns: Box::new(Type::Tuple(returns.to_vec())),
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Nothing => write!(f, "Nothing"),
            Type::Int => write!(f, "Int"),
            Type::Bool => write!(f, "Bool"),
            Type::Char => write!(f, "Char"),
            Type::Pointer(pointee) => write!(f, "Pointer<{}>", pointee),
            Type::Function { params, returns } => write!(f, "Function<{} -> {}>", params, returns),
            Type::TypeVar(id) => write!(f, "TypeVar({})", id),
            Type::Tuple(elements) => {
                let elements_str: Vec<String> = elements.iter().map(|e| e.to_string()).collect();
                write!(f, "Tuple({})", elements_str.join(", "))
            }
            Type::Truthy => write!(f, "Truthy"),
            Type::Any => write!(f, "Any"),
            Type::GLB(types) => {
                let inner: Vec<String> = types.iter().map(|t| t.to_string()).collect();
                write!(f, "GLB({})", inner.join(", "))
            }
            Type::LUB(types) => {
                let inner: Vec<String> = types.iter().map(|t| t.to_string()).collect();
                write!(f, "LUB({})", inner.join(", "))
            }
        }
    }
}

/// Represents the different kinds of type variables we can have.
#[derive(Clone, Debug, PartialEq)]
pub enum TypeVarKind {
    /// A constant value.
    Const(i128),
    /// The variable is linked to a memory reference.
    MemoryReference(SsaMemoryReference),
    /// An expression with an unknown type. This variant stores the expression itself for debugging and linking.
    Expression(Expression<SsaMemoryReference>),
    /// The arguments to a function call at the call site.
    CallSiteArgs,
    /// The return type from a function call at the call site.
    CallSiteReturns,
    // Arguments to a functino within the function
    CalleeArgs(FunctionId),
    // Return values at the function call.
    CalleeReturns(FunctionId),
}

impl TypeVarKind {
    pub fn as_memory_reference(&self) -> Option<&SsaMemoryReference> {
        match self {
            TypeVarKind::MemoryReference(memref) => Some(memref),
            _ => None,
        }
    }

    pub fn as_versioned_memory(&self) -> Option<&VersionedMemoryReference> {
        match self {
            TypeVarKind::MemoryReference(memref) => memref.as_versioned(),
            _ => None,
        }
    }

    pub fn as_const(&self) -> Option<&i128> {
        match self {
            TypeVarKind::Const(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_expression(&self) -> Option<&Expression<SsaMemoryReference>> {
        match self {
            TypeVarKind::Expression(expr) => Some(expr),
            _ => None,
        }
    }

    pub fn as_function_args(&self) -> Option<()> {
        match self {
            TypeVarKind::CallSiteArgs => Some(()),
            _ => None,
        }
    }
}

impl fmt::Display for TypeVarKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeVarKind::Const(v) => write!(f, "Const({})", v),
            TypeVarKind::MemoryReference(memref) => write!(f, "{}", memref),
            TypeVarKind::Expression(expr) => write!(f, "T({})", expr),
            TypeVarKind::CallSiteArgs => write!(f, "CallSiteArgs"),
            TypeVarKind::CallSiteReturns => write!(f, "CallSiteReturns"),
            TypeVarKind::CalleeArgs(function_id) => write!(f, "CalleeArgs({})", function_id),
            TypeVarKind::CalleeReturns(function_id) => write!(f, "CalleeReturns({})", function_id),
        }
    }
}

/// Stores information about the origin of a type variable.
#[derive(Clone, Debug, PartialEq)]
pub struct TypeVarNode {
    /// What kind of type variable is this?
    pub kind: TypeVarKind,
    /// What instruction ID introduced this type variable?
    pub instruction_id: InstructionId,
    /// What function ID contains this type variable?
    pub function_id: FunctionId,
}

impl fmt::Display for TypeVarNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)
    }
}

pub struct DisplayableType<'a, 'b, F>
where
    F: TypeVarRegistry,
{
    ty: &'a Type,
    registry: &'b F,
}

impl<'a, 'b, F: TypeVarRegistry> fmt::Display for DisplayableType<'a, 'b, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ty {
            Type::TypeVar(id) => write!(f, "{}", id.display_with(self.registry)),
            Type::Tuple(elements) => {
                let elements_str: Vec<String> = elements
                    .iter()
                    .map(|e| e.display_with(self.registry).to_string())
                    .collect();
                write!(f, "Tuple({})", elements_str.join(", "))
            }
            Type::Function { params, returns } => {
                write!(
                    f,
                    "Function<{} -> {}>",
                    params.display_with(self.registry),
                    returns.display_with(self.registry)
                )
            }
            Type::GLB(types) => {
                let inner: Vec<String> = types
                    .iter()
                    .map(|t| t.display_with(self.registry).to_string())
                    .collect();
                write!(f, "GLB({})", inner.join(", "))
            }
            Type::LUB(types) => {
                let inner: Vec<String> = types
                    .iter()
                    .map(|t| t.display_with(self.registry).to_string())
                    .collect();
                write!(f, "LUB({})", inner.join(", "))
            }
            Type::Nothing => write!(f, "Nothing"),
            Type::Int => write!(f, "Int"),
            Type::Bool => write!(f, "Bool"),
            Type::Char => write!(f, "Char"),
            Type::Pointer(pointee) => write!(f, "Pointer<{}>", pointee.display_with(self.registry)),
            Type::Truthy => write!(f, "Truthy"),
            Type::Any => write!(f, "Any"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::disasm::v3::type_inference::type_bounds_map::ChangeReason;

    use super::*;

    // Helper functions for test readability
    fn int() -> Type {
        Type::Int
    }
    fn bool() -> Type {
        Type::Bool
    }
    fn char() -> Type {
        Type::Char
    }
    fn nothing() -> Type {
        Type::Nothing
    }
    fn any() -> Type {
        Type::Any
    }
    fn truthy() -> Type {
        Type::Truthy
    }
    fn pointer(pointee: Type) -> Type {
        Type::Pointer(Box::new(pointee))
    }
    fn tuple(elements: &[Type]) -> Type {
        Type::Tuple(elements.to_vec())
    }
    fn function(params_type: Type, returns_type: Type) -> Type {
        // Renamed args to params_type
        Type::Function {
            params: Box::new(params_type),
            returns: Box::new(returns_type),
        }
    }

    struct NoRegistry {}

    impl NoRegistry {
        fn new() -> Self {
            NoRegistry {}
        }
    }

    impl TypeVarRegistry for NoRegistry {
        fn get_type_var_node(&self, _tv_id: &TypeVarId) -> Option<&TypeVarNode> {
            todo!()
        }

        fn get_type_var_state(
            &self,
            _tv_id: &TypeVarId,
        ) -> Option<&crate::disasm::v3::type_inference::TypeVarState> {
            todo!()
        }
    }

    #[test]
    fn test_is_subtype_of() {
        let registry = NoRegistry::new();
        assert!(int().is_subtype_of(&int(), &registry).is_yes());
        assert!(bool().is_subtype_of(&int(), &registry).is_yes());
        assert!(bool().is_subtype_of(&bool(), &registry).is_yes());
        assert!(char().is_subtype_of(&int(), &registry).is_yes());
        assert!(nothing().is_subtype_of(&int(), &registry).is_yes());
        assert!(nothing().is_subtype_of(&bool(), &registry).is_yes());
        assert!(nothing().is_subtype_of(&char(), &registry).is_yes());
        assert!(!any().is_subtype_of(&int(), &registry).is_yes()); // Expecting !Yes, which means No or Maybe
        assert!(!truthy().is_subtype_of(&bool(), &registry).is_yes()); // Expecting !Yes, which means No or Maybe
        assert!(pointer(int()).is_subtype_of(&truthy(), &registry).is_yes());
        assert!(pointer(bool())
            .is_subtype_of(&pointer(int()), &registry)
            .is_yes());
        assert!(tuple(&[char()])
            .is_subtype_of(&tuple(&[]), &registry)
            .is_yes());
        assert!(!tuple(&[])
            .is_subtype_of(&tuple(&[char()]), &registry)
            .is_yes()); // Expecting !Yes, which means No or Maybe

        let fn_ty = function(tuple(&[]), tuple(&[]));
        assert!(fn_ty.is_subtype_of(&pointer(int()), &registry).is_yes());
        assert!(fn_ty.is_subtype_of(&pointer(any()), &registry).is_yes());
        assert!(fn_ty.is_subtype_of(&int(), &registry).is_yes());
        assert!(fn_ty.is_subtype_of(&truthy(), &registry).is_yes());
    }

    #[test]
    fn test_lub() {
        let registry = NoRegistry::new();
        assert_eq!(Type::lub(&int(), &int(), &registry), int());
        assert_eq!(Type::lub(&int(), &bool(), &registry), int());
        assert_eq!(Type::lub(&bool(), &int(), &registry), int());
        assert_eq!(Type::lub(&bool(), &bool(), &registry), bool());
        assert_eq!(Type::lub(&char(), &int(), &registry), int());
        assert_eq!(Type::lub(&char(), &bool(), &registry), truthy());
        assert_eq!(Type::lub(&char(), &char(), &registry), char());
        assert_eq!(Type::lub(&nothing(), &int(), &registry), int());
        assert_eq!(Type::lub(&nothing(), &bool(), &registry), bool());
        assert_eq!(Type::lub(&nothing(), &char(), &registry), char());
        assert_eq!(Type::lub(&any(), &int(), &registry), any());
        assert_eq!(Type::lub(&truthy(), &bool(), &registry), truthy());
        assert_eq!(Type::lub(&truthy(), &pointer(int()), &registry), truthy());
        assert_eq!(
            Type::lub(&pointer(bool()), &pointer(int()), &registry),
            pointer(int())
        );
        assert_eq!(
            Type::lub(&pointer(pointer(any())), &bool(), &registry),
            truthy()
        );
    }

    #[test]
    fn test_lub_tuples() {
        let registry = NoRegistry::new();
        assert_eq!(
            Type::lub(&tuple(&[bool(), int()]), &tuple(&[bool()]), &registry),
            tuple(&[bool()])
        );
        assert_eq!(
            Type::lub(&tuple(&[bool()]), &tuple(&[bool(), char()]), &registry),
            tuple(&[bool()])
        );
        assert_eq!(
            Type::lub(
                &tuple(&[int(), bool(), char()]),
                &tuple(&[int(), int()]),
                &registry
            ),
            tuple(&[int(), int()])
        );
        assert_eq!(
            Type::lub(
                &tuple(&[bool(), int()]),
                &tuple(&[int(), bool()]),
                &registry
            ),
            tuple(&[int(), int()])
        );
        assert_eq!(
            Type::lub(&tuple(&[bool(), int()]), &tuple(&[]), &registry),
            tuple(&[])
        );
    }

    #[test]
    fn test_lub_functions() {
        let registry = NoRegistry::new();
        let fn1_params = tuple(&[int(), bool()]);
        let fn1_ret = tuple(&[int()]);
        let fn1 = function(fn1_params.clone(), fn1_ret.clone());

        assert_eq!(Type::lub(&fn1, &fn1, &registry), fn1.clone());

        let fn2_params = tuple(&[int()]);
        let fn2 = function(fn2_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn2, &registry),
            function(tuple(&[int(), bool()]), tuple(&[int()]))
        );

        let fn3_ret = tuple(&[bool()]);
        let fn3 = function(fn1_params.clone(), fn3_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn3, &registry),
            function(tuple(&[int(), bool()]), tuple(&[int()]))
        );

        let fn4_ret = tuple(&[char()]);
        let fn4 = function(fn1_params.clone(), fn4_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn4, &registry),
            function(tuple(&[int(), bool()]), tuple(&[int()]))
        );

        let fn5_params = tuple(&[int(), bool(), char()]);
        let fn5 = function(fn5_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn5, &registry),
            function(tuple(&[int(), bool(), char()]), tuple(&[int()]))
        );
    }

    #[test]
    fn test_glb() {
        let registry = NoRegistry::new();
        assert_eq!(Type::glb(&int(), &int(), &registry), int());
        assert_eq!(Type::glb(&int(), &bool(), &registry), bool());
        assert_eq!(Type::glb(&bool(), &int(), &registry), bool());
        assert_eq!(Type::glb(&bool(), &bool(), &registry), bool());
        assert_eq!(Type::glb(&char(), &int(), &registry), char());
        assert_eq!(Type::glb(&char(), &bool(), &registry), nothing());
        assert_eq!(Type::glb(&char(), &char(), &registry), char());
        assert_eq!(Type::glb(&nothing(), &int(), &registry), nothing());
        assert_eq!(Type::glb(&nothing(), &bool(), &registry), nothing());
        assert_eq!(Type::glb(&nothing(), &char(), &registry), nothing());
        assert_eq!(Type::glb(&any(), &int(), &registry), int());
        assert_eq!(Type::glb(&truthy(), &bool(), &registry), bool());
        assert_eq!(
            Type::glb(&truthy(), &pointer(int()), &registry),
            pointer(int())
        );
        assert_eq!(
            Type::glb(&pointer(bool()), &pointer(int()), &registry),
            pointer(bool())
        );
        assert_eq!(
            Type::glb(&pointer(pointer(any())), &bool(), &registry),
            Type::Nothing
        );
    }

    #[test]
    fn test_glb_tuples() {
        let registry = NoRegistry::new();
        assert_eq!(
            Type::glb(
                &tuple(&[bool(), pointer(int())]),
                &tuple(&[bool()]),
                &registry
            ),
            tuple(&[bool(), pointer(int())])
        );
        assert_eq!(
            Type::glb(&tuple(&[bool()]), &tuple(&[bool(), int()]), &registry),
            tuple(&[bool(), int()])
        );
        assert_eq!(
            Type::glb(&tuple(&[int(), bool()]), &tuple(&[int(), int()]), &registry),
            tuple(&[int(), bool()])
        );
        assert_eq!(
            Type::glb(&tuple(&[]), &tuple(&[bool(), int()]), &registry),
            tuple(&[bool(), int()])
        );
    }

    #[test]
    fn test_glb_functions() {
        let registry = NoRegistry::new();
        let fn1_params = tuple(&[int(), bool()]); // Changed args to params
        let fn1_ret = tuple(&[int()]);
        let fn1 = function(fn1_params.clone(), fn1_ret.clone());
        assert_eq!(Type::glb(&fn1, &fn1, &registry), fn1.clone());

        let fn2_params = tuple(&[int()]); // Changed args to params
        let fn2 = function(fn2_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::glb(&fn1, &fn2, &registry),
            function(tuple(&[int()]), tuple(&[int()]))
        );

        let fn3_params = tuple(&[int(), char()]); // Changed args to params
        let fn3 = function(fn3_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::glb(&fn1, &fn3, &registry),
            function(tuple(&[int(), truthy()]), tuple(&[int()]))
        );

        let fn4_ret = tuple(&[char()]);
        let fn4 = function(fn1_params.clone(), fn4_ret.clone());
        assert_eq!(
            Type::glb(&fn1, &fn4, &registry),
            function(tuple(&[int(), bool()]), tuple(&[char()]))
        );
    }

    #[test]
    fn test_glb_and_bounds() {
        let mut registry = InferenceAlgorithmState::new();
        let var1 = TypeVarId::new(1);
        registry.add_type_var(
            var1,
            TypeVarNode {
                kind: TypeVarKind::Const(42),
                instruction_id: InstructionId::new(1),
                function_id: FunctionId::new(1),
            },
        );
        let var2 = TypeVarId::new(2);
        registry.add_type_var(
            var2,
            TypeVarNode {
                kind: TypeVarKind::Const(43),
                instruction_id: InstructionId::new(1),
                function_id: FunctionId::new(1),
            },
        );

        registry.update_upper_bound(
            &var1,
            &Type::glb(&Type::Int, &var2.to_type(), &registry),
            ChangeReason::Test,
        );
        registry.update_lower_bound(&var2, &var1.to_type(), ChangeReason::Test);
        registry.update_upper_bound(&var2, &Type::Int, ChangeReason::Test);
        // We have:
        //    var1 <: glb(int, var2)
        //    var1 <: var2 <: int
        for (id, node) in registry.iter_all_type_states() {
            println!("TypeVarId: {}, Node: {:?}", id, node);
        }
        assert!(Type::glb(&Type::Int, &var2.to_type(), &registry)
            .is_subtype_of(&var2.to_type(), &registry)
            .is_yes());
        println!("Got the yes!");

        assert_eq!(
            var1.to_type().is_subtype_of(&var2.to_type(), &registry),
            YesNoMaybe::Yes
        );
        registry.update_lower_bound(&var2, &Type::Int, ChangeReason::Test);
    }
}
