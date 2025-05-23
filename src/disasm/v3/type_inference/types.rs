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

use super::type_bounds_map::TypeVarRegistry;

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

enum YesNoMaybe {
    Yes,
    No,
    Maybe,
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

    /// Checks if `self` is a subtype of `other` (self <: other).
    pub fn is_subtype_of(&self, other: &Type) -> bool {
        if self == other {
            return true;
        }
        if *self == Type::Nothing {
            return true;
        }
        if *other == Type::Any {
            return true;
        }
        if *other == Type::Nothing {
            return *self == Type::Nothing;
        }
        if *self == Type::Any {
            return *other == Type::Any;
        }

        match (self, other) {
            (Type::Char, Type::Int) => true,
            (Type::Bool, Type::Int) => true,
            (Type::Pointer(_), Type::Int) => true,
            (Type::Function { .. }, Type::Int) => true,

            (Type::Function { .. }, Type::Pointer(p_target)) => {
                // Function <: Pointer(Int) and Function <: Pointer(Any)
                **p_target == Type::Int || **p_target == Type::Any
            }

            (Type::Int, Type::Truthy) => true,
            (Type::Bool, Type::Truthy) => true,
            (Type::Char, Type::Truthy) => true,
            (Type::Pointer(_), Type::Truthy) => true,
            (Type::Function { .. }, Type::Truthy) => true,

            (Type::Pointer(p1), Type::Pointer(p2)) => p1.is_subtype_of(p2),
            (
                Type::Function {
                    params: params1,
                    returns: returns1,
                },
                Type::Function {
                    params: params2,
                    returns: returns2,
                },
            ) => params2.is_subtype_of(params1) && returns1.is_subtype_of(returns2),
            (Type::Tuple(v1), Type::Tuple(v2)) => {
                v1.len() >= v2.len()
                    && v2
                        .iter()
                        .enumerate()
                        .all(|(i, t2_elem)| v1[i].is_subtype_of(t2_elem))
            }
            (_, Type::GLB(types)) => types.iter().all(|t| self.is_subtype_of(t)),
            (Type::GLB(types), _) => types.iter().any(|t| t.is_subtype_of(other)), // this condition is sufficient but not necessary: other could be a type between glb and ga, or between glb and gb.
            (Type::LUB(types), _) => types.iter().all(|t| t.is_subtype_of(other)),
            (_, Type::LUB(types)) => types.iter().any(|t| self.is_subtype_of(t)), // this condition is sufficient but not necessary: other could be a type between la and ga, or between la and glb.
            (Type::TypeVar(_), _) => false,
            (_, Type::TypeVar(_)) => false,

            _ => false,
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
    pub fn glb(t1: &Type, t2: &Type) -> Type {
        // Shortcut: if one is a subtype of the other
        if t1.is_subtype_of(t2) {
            // Return t1, but ensure it's canonical if it's already a GLB/LUB
            return Self::_form_canonical_compound_type(
                vec![t1.clone()],
                CanonicalFormOperation::GLB,
            );
        }
        if t2.is_subtype_of(t1) {
            return Self::_form_canonical_compound_type(
                vec![t2.clone()],
                CanonicalFormOperation::GLB,
            );
        }

        // Handle Nothing and Any
        if *t1 == Type::Nothing || *t2 == Type::Nothing {
            return Type::Nothing;
        }
        if *t1 == Type::Any {
            return Self::_form_canonical_compound_type(
                vec![t2.clone()],
                CanonicalFormOperation::GLB,
            );
        }
        if *t2 == Type::Any {
            return Self::_form_canonical_compound_type(
                vec![t1.clone()],
                CanonicalFormOperation::GLB,
            );
        }

        // Structural rules
        match (t1, t2) {
            (Type::Pointer(p1), Type::Pointer(p2)) => {
                let inner_glb = Self::glb(p1.as_ref(), p2.as_ref());
                if inner_glb == Type::Nothing {
                    return Type::Nothing; // Pointer to Nothing is ill-formed or effectively Nothing itself.
                }
                return Type::Pointer(Box::new(inner_glb));
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
                // Parameters are contravariant (LUB), returns are covariant (GLB)
                let lub_params = Self::lub(params1.as_ref(), params2.as_ref());
                let glb_returns = Self::glb(returns1.as_ref(), returns2.as_ref());

                if lub_params == Type::Any || glb_returns == Type::Nothing {
                    // Or other conditions for "impossible function"
                    return Type::Nothing; // This function signature is impossible
                }
                return Type::Function {
                    params: Box::new(lub_params),
                    returns: Box::new(glb_returns),
                };
            }
            (Type::Tuple(v1), Type::Tuple(v2)) => {
                let len1 = v1.len();
                let len2 = v2.len();
                let max_len = std::cmp::max(len1, len2); // GLB of tuples can extend
                let mut res_vec = Vec::with_capacity(max_len);
                for i in 0..max_len {
                    match (v1.get(i), v2.get(i)) {
                        (Some(e1), Some(e2)) => {
                            let elem_glb = Self::glb(e1, e2);
                            if elem_glb == Type::Nothing
                                && !(e1.is_subtype_of(e2) || e2.is_subtype_of(e1))
                            {
                                // If elements are incompatible, resulting tuple is ill-formed.
                                return Type::Nothing;
                            }
                            res_vec.push(elem_glb);
                        }
                        (Some(e1), None) => res_vec.push(e1.clone()), // Element from longer tuple
                        (None, Some(e2)) => res_vec.push(e2.clone()), // Element from longer tuple
                        (None, None) => unreachable!(),               // Max_len ensures one is Some
                    }
                }
                return Type::Tuple(res_vec);
            }
            // Cases for fundamentally incompatible concrete types that are not covered by subtyping
            // For example, Bool and Pointer(X)
            (Type::Bool, Type::Pointer(_)) | (Type::Pointer(_), Type::Bool) => {
                return Type::Nothing
            }
            (Type::Char, Type::Pointer(_)) | (Type::Pointer(_), Type::Char) => {
                return Type::Nothing
            } // Assuming Char GLB Pointer is Nothing
            (Type::Int, Type::Pointer(_)) | (Type::Pointer(_), Type::Int) => {
                // If int can be a pointer address, this might be Pointer, otherwise Nothing
                // For now, let's assume they are incompatible for a simple GLB
                return Type::Nothing;
            }
            (Type::Bool, Type::Function { .. }) | (Type::Function { .. }, Type::Bool) => {
                return Type::Nothing
            }
            // Add more known disjoint pairs if necessary...

            // Default: defer to the canonical form helper
            _ => Self::_form_canonical_compound_type(
                vec![t1.clone(), t2.clone()],
                CanonicalFormOperation::GLB,
            ),
        }
    }

    /// Private helper to form a canonical GLB from a list of operand types.
    /// Assumes Type::GLB is `GLB(Vec<Type>)`.
    fn _form_canonical_compound_type(
        initial_operands: Vec<Type>,
        operation: CanonicalFormOperation,
    ) -> Type {
        let mut flat_operands: Vec<Type> = Vec::new();
        let mut worklist = initial_operands;

        // 1. Flatten nested types (GLB for GLB op, LUB for LUB op)
        while let Some(typ) = worklist.pop() {
            match operation {
                CanonicalFormOperation::GLB => match typ {
                    Type::Nothing => return Type::Nothing, // GLB with Nothing is Nothing
                    Type::Any => continue,                 // Any is identity for GLB's operands
                    Type::GLB(inner_types) => worklist.extend(inner_types.into_iter().rev()),
                    _ => flat_operands.push(typ),
                },
                CanonicalFormOperation::LUB => match typ {
                    Type::Any => return Type::Any, // LUB with Any is Any
                    Type::Nothing => continue,     // Nothing is identity for LUB's operands
                    Type::LUB(inner_types) => worklist.extend(inner_types.into_iter().rev()),
                    _ => flat_operands.push(typ),
                },
            }
        }

        // 2. Handle empty effective operands
        if flat_operands.is_empty() {
            return match operation {
                CanonicalFormOperation::GLB => Type::Any,
                CanonicalFormOperation::LUB => Type::Nothing,
            };
        }

        // 3. Sort and remove exact duplicates for consistent processing
        //    Type must implement Ord for this sort to be canonical.
        flat_operands.sort_unstable(); // Or sort() if stable sort is important for Ord impl
        flat_operands.dedup();

        // 4. Filter out subsumed types (if X <: Y, Y is redundant in GLB(X, Y, ...))
        let mut minimal_set: Vec<Type> = Vec::new();
        if flat_operands.len() == 1 {
            // Optimization
            minimal_set.push(flat_operands.remove(0));
        } else {
            for candidate_type in flat_operands {
                // If candidate_type is already subsumed by something in minimal_set, skip it.
                if minimal_set
                    .iter()
                    .any(|minimal_elem| minimal_elem.is_subtype_of(&candidate_type))
                {
                    continue;
                }
                // Remove elements from minimal_set that are subsumed by candidate_type.
                minimal_set.retain(|minimal_elem| !candidate_type.is_subtype_of(minimal_elem));
                minimal_set.push(candidate_type);
            }
        }

        // Sort again as retain might change order, for canonical GLB operand order
        minimal_set.sort_unstable();

        // 5. Check for fundamental incompatibilities in the minimal_set
        //    If the minimal_set contains types that are known to be disjoint.
        if minimal_set.len() > 1 {
            // This check needs to be careful. We're checking if the *combination* is Nothing.
            // Example: minimal_set = [Bool, Pointer(Char)]. Their GLB is Nothing.
            // A simple pairwise check for pre-defined disjoint types:
            for i in 0..minimal_set.len() {
                for j in (i + 1)..minimal_set.len() {
                    let ti = &minimal_set[i];
                    let tj = &minimal_set[j];
                    // Use a helper for direct, non-recursive disjoint checks or rely on binary GLB's specific rules
                    match (ti, tj) {
                        (Type::Bool, Type::Pointer(_)) | (Type::Pointer(_), Type::Bool) => {
                            return Type::Nothing
                        }
                        (Type::Bool, Type::Char) | (Type::Char, Type::Bool) => {
                            return Type::Nothing
                        }
                        (Type::Char, Type::Pointer(_)) | (Type::Pointer(_), Type::Char) => {
                            return Type::Nothing
                        }
                        (Type::Int, Type::Pointer(_)) | (Type::Pointer(_), Type::Int) => {
                            return Type::Nothing
                        } // Assuming incompatibility
                        (Type::Bool, Type::Function { .. })
                        | (Type::Function { .. }, Type::Bool) => return Type::Nothing,
                        (Type::Int, Type::Function { .. }) | (Type::Function { .. }, Type::Int) => {
                            return Type::Nothing
                        }
                        (Type::Char, Type::Function { .. })
                        | (Type::Function { .. }, Type::Char) => return Type::Nothing,
                        (Type::Pointer(_), Type::Function { .. })
                        | (Type::Function { .. }, Type::Pointer(_)) => return Type::Nothing,
                        // If Int & Char -> Char, Bool & Int -> Bool, these are not "Nothing"
                        _ => {}
                    }
                }
            }
        }

        // 6. Construct final Type
        if minimal_set.is_empty() {
            // Should be caught by flat_operands.is_empty earlier
            Type::Any
        } else if minimal_set.len() == 1 {
            minimal_set.remove(0) // Return the single type directly
        } else {
            Type::GLB(minimal_set)
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

    /// Computes the least upper bound (LUB) of two types, returning a canonical form.
    /// Assumes Type::LUB is `LUB(Vec<Type>)`.
    pub fn lub(t1: &Type, t2: &Type) -> Type {
        // Shortcut: if one is a subtype of the other (LUB is the supertype)
        if t1.is_subtype_of(t2) {
            return Self::_form_canonical_compound_type(
                vec![t2.clone()],
                CanonicalFormOperation::LUB,
            );
        }
        if t2.is_subtype_of(t1) {
            return Self::_form_canonical_compound_type(
                vec![t1.clone()],
                CanonicalFormOperation::LUB,
            );
        }

        // Handle Any and Nothing
        if *t1 == Type::Any || *t2 == Type::Any {
            return Type::Any;
        }
        if *t1 == Type::Nothing {
            // Nothing is identity for LUB
            return Self::_form_canonical_compound_type(
                vec![t2.clone()],
                CanonicalFormOperation::LUB,
            );
        }
        if *t2 == Type::Nothing {
            return Self::_form_canonical_compound_type(
                vec![t1.clone()],
                CanonicalFormOperation::LUB,
            );
        }

        // Structural rules
        match (t1, t2) {
            (Type::Pointer(p1), Type::Pointer(p2)) => {
                let inner_lub = Self::lub(p1.as_ref(), p2.as_ref()); // Use public lub
                return Type::Pointer(Box::new(inner_lub));
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
                let glb_params = Self::glb(params1.as_ref(), params2.as_ref()); // Use public glb
                let lub_returns = Self::lub(returns1.as_ref(), returns2.as_ref()); // Use public lub
                if glb_params == Type::Nothing {
                    return Type::Any;
                }
                return Type::Function {
                    params: Box::new(glb_params),
                    returns: Box::new(lub_returns),
                };
            }
            (Type::Tuple(v1), Type::Tuple(v2)) => {
                let min_len = std::cmp::min(v1.len(), v2.len());
                let mut res_vec = Vec::with_capacity(min_len);
                for i in 0..min_len {
                    res_vec.push(Self::lub(&v1[i], &v2[i])); // Use public lub
                }
                return Type::Tuple(res_vec);
            }

            // Specific LUBs based on common supertypes from lattice
            (Type::Char, Type::Bool) | (Type::Bool, Type::Char) => Type::Truthy,
            (Type::Bool, Type::Pointer(_)) | (Type::Pointer(_), Type::Bool) => Type::Truthy,
            (Type::Char, Type::Pointer(_)) | (Type::Pointer(_), Type::Char) => Type::Int,
            (Type::Int, Type::Pointer(_)) | (Type::Pointer(_), Type::Int) => Type::Int,
            (Type::Int, Type::Bool) | (Type::Bool, Type::Int) => Type::Int,
            (Type::Int, Type::Char) | (Type::Char, Type::Int) => Type::Int,
            (Type::Function { .. }, Type::Bool) | (Type::Bool, Type::Function { .. }) => {
                Type::Truthy
            }
            (Type::Function { .. }, Type::Char) | (Type::Char, Type::Function { .. }) => Type::Int,
            (Type::Function { .. }, Type::Int) | (Type::Int, Type::Function { .. }) => Type::Int,
            (Type::Function { .. }, Type::Pointer(_))
            | (Type::Pointer(_), Type::Function { .. }) => Type::Truthy,

            // Default: defer to the canonical form helper
            _ => Self::_form_canonical_compound_type(
                vec![t1.clone(), t2.clone()],
                CanonicalFormOperation::LUB,
            ),
        }
    }

    // When computing upper bounds or lower bounds, it could happen that the same type we are computing bounds for
    // appears in a top-level GLB or LUB. This function removes the given variable from the top-level GLB and LUB,
    // and attempts simplifying it before returning it. If the type is not a GLB or LUB, it is returned unchanged.
    pub fn remove_references_from_glb_lub(&self, t: &TypeVarId) -> Type {
        match self {
            Type::GLB(types) => {
                let filtered_types: Vec<Type> = types
                    .iter()
                    .filter(|typ| match typ {
                        Type::TypeVar(id) => id != t,
                        _ => true,
                    })
                    .cloned()
                    .collect();
                if filtered_types.len() == types.len() {
                    // No change, return the original type
                    return self.clone();
                }
                if filtered_types.is_empty() {
                    return Type::Any;
                }
                if filtered_types.len() == 1 {
                    return filtered_types[0].clone();
                }
                Self::_form_canonical_compound_type(filtered_types, CanonicalFormOperation::GLB)
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
                if filtered_types.len() == types.len() {
                    // No change, return the original type
                    return self.clone();
                }
                if filtered_types.is_empty() {
                    return Type::Nothing;
                }
                if filtered_types.len() == 1 {
                    return filtered_types[0].clone();
                }
                Self::_form_canonical_compound_type(filtered_types, CanonicalFormOperation::LUB)
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

    #[test]
    fn test_is_subtype_of() {
        assert!(int().is_subtype_of(&int()));
        assert!(bool().is_subtype_of(&int()));
        assert!(bool().is_subtype_of(&bool()));
        assert!(char().is_subtype_of(&int()));
        assert!(nothing().is_subtype_of(&int()));
        assert!(nothing().is_subtype_of(&bool()));
        assert!(nothing().is_subtype_of(&char()));
        assert!(!any().is_subtype_of(&int()));
        assert!(!truthy().is_subtype_of(&bool()));
        assert!(pointer(int()).is_subtype_of(&truthy()));
        assert!(pointer(bool()).is_subtype_of(&pointer(int())));
        assert!(tuple(&[char()]).is_subtype_of(&tuple(&[])));
        assert!(!tuple(&[]).is_subtype_of(&tuple(&[char()])));

        let fn_ty = function(tuple(&[]), tuple(&[]));
        assert!(fn_ty.is_subtype_of(&pointer(int())));
        assert!(fn_ty.is_subtype_of(&pointer(any())));
        assert!(fn_ty.is_subtype_of(&int()));
        assert!(fn_ty.is_subtype_of(&truthy()));
    }

    #[test]
    fn test_lub() {
        assert_eq!(Type::lub(&int(), &int()), int());
        assert_eq!(Type::lub(&int(), &bool()), int());
        assert_eq!(Type::lub(&bool(), &int()), int());
        assert_eq!(Type::lub(&bool(), &bool()), bool());
        assert_eq!(Type::lub(&char(), &int()), int());
        assert_eq!(Type::lub(&char(), &bool()), truthy());
        assert_eq!(Type::lub(&char(), &char()), char());
        assert_eq!(Type::lub(&nothing(), &int()), int());
        assert_eq!(Type::lub(&nothing(), &bool()), bool());
        assert_eq!(Type::lub(&nothing(), &char()), char());
        assert_eq!(Type::lub(&any(), &int()), any());
        assert_eq!(Type::lub(&truthy(), &bool()), truthy());
        assert_eq!(Type::lub(&truthy(), &pointer(int())), truthy());
        assert_eq!(Type::lub(&pointer(bool()), &pointer(int())), pointer(int()));
        assert_eq!(Type::lub(&pointer(pointer(any())), &bool()), truthy());
    }

    #[test]
    fn test_lub_tuples() {
        assert_eq!(
            Type::lub(&tuple(&[bool(), int()]), &tuple(&[bool()])),
            tuple(&[bool()])
        );
        assert_eq!(
            Type::lub(&tuple(&[bool()]), &tuple(&[bool(), char()])),
            tuple(&[bool()])
        );
        assert_eq!(
            Type::lub(&tuple(&[int(), bool(), char()]), &tuple(&[int(), int()])),
            tuple(&[int(), int()])
        );
        assert_eq!(
            Type::lub(&tuple(&[bool(), int()]), &tuple(&[int(), bool()])),
            tuple(&[int(), int()])
        );
        assert_eq!(Type::lub(&tuple(&[bool(), int()]), &tuple(&[])), tuple(&[]));
    }

    #[test]
    fn test_lub_functions() {
        let fn1_params = tuple(&[int(), bool()]);
        let fn1_ret = tuple(&[int()]);
        let fn1 = function(fn1_params.clone(), fn1_ret.clone());

        assert_eq!(Type::lub(&fn1, &fn1), fn1.clone());

        let fn2_params = tuple(&[int()]);
        let fn2 = function(fn2_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn2),
            function(tuple(&[int(), bool()]), tuple(&[int()]))
        );

        let fn3_ret = tuple(&[bool()]);
        let fn3 = function(fn1_params.clone(), fn3_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn3),
            function(tuple(&[int(), bool()]), tuple(&[int()]))
        );

        let fn4_ret = tuple(&[char()]);
        let fn4 = function(fn1_params.clone(), fn4_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn4),
            function(tuple(&[int(), bool()]), tuple(&[int()]))
        );

        let fn5_params = tuple(&[int(), bool(), char()]);
        let fn5 = function(fn5_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn5),
            function(tuple(&[int(), bool(), char()]), tuple(&[int()]))
        );
    }

    #[test]
    fn test_glb() {
        assert_eq!(Type::glb(&int(), &int()), int());
        assert_eq!(Type::glb(&int(), &bool()), bool());
        assert_eq!(Type::glb(&bool(), &int()), bool());
        assert_eq!(Type::glb(&bool(), &bool()), bool());
        assert_eq!(Type::glb(&char(), &int()), char());
        assert_eq!(Type::glb(&char(), &bool()), nothing());
        assert_eq!(Type::glb(&char(), &char()), char());
        assert_eq!(Type::glb(&nothing(), &int()), nothing());
        assert_eq!(Type::glb(&nothing(), &bool()), nothing());
        assert_eq!(Type::glb(&nothing(), &char()), nothing());
        assert_eq!(Type::glb(&any(), &int()), int());
        assert_eq!(Type::glb(&truthy(), &bool()), bool());
        assert_eq!(Type::glb(&truthy(), &pointer(int())), pointer(int()));
        assert_eq!(
            Type::glb(&pointer(bool()), &pointer(int())),
            pointer(bool())
        );
        assert_eq!(Type::glb(&pointer(pointer(any())), &bool()), Type::Nothing);
    }

    #[test]
    fn test_glb_tuples() {
        assert_eq!(
            Type::glb(&tuple(&[bool(), pointer(int())]), &tuple(&[bool()])),
            tuple(&[bool(), pointer(int())])
        );
        assert_eq!(
            Type::glb(&tuple(&[bool()]), &tuple(&[bool(), int()])),
            tuple(&[bool(), int()])
        );
        assert_eq!(
            Type::glb(&tuple(&[int(), bool()]), &tuple(&[int(), int()])),
            tuple(&[int(), bool()])
        );
        assert_eq!(
            Type::glb(&tuple(&[]), &tuple(&[bool(), int()])),
            tuple(&[bool(), int()])
        );
        assert_eq!(
            Type::glb(
                &tuple(&[int(), int(), bool()]),
                &tuple(&[int(), bool(), char()])
            ),
            nothing()
        );
        assert_eq!(
            Type::glb(&tuple(&[bool(),]), &tuple(&[char(), int()])),
            nothing()
        );
    }

    #[test]
    fn test_glb_functions() {
        let fn1_params = tuple(&[int(), bool()]); // Changed args to params
        let fn1_ret = tuple(&[int()]);
        let fn1 = function(fn1_params.clone(), fn1_ret.clone());
        assert_eq!(Type::glb(&fn1, &fn1), fn1.clone());

        let fn2_params = tuple(&[int()]); // Changed args to params
        let fn2 = function(fn2_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::glb(&fn1, &fn2),
            function(tuple(&[int()]), tuple(&[int()]))
        );

        let fn3_params = tuple(&[int(), char()]); // Changed args to params
        let fn3 = function(fn3_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::glb(&fn1, &fn3),
            function(tuple(&[int(), truthy()]), tuple(&[int()]))
        );

        let fn4_ret = tuple(&[char()]);
        let fn4 = function(fn1_params.clone(), fn4_ret.clone());
        assert_eq!(
            Type::glb(&fn1, &fn4),
            function(tuple(&[int(), bool()]), tuple(&[char()]))
        );
    }
}
