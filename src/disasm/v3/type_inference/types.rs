use crate::disasm::v3::{
    define_id_type,
    lir::{Expression, Instruction, InstructionNode},
    model::{HasFoldedSsaResult, Model, ModelState},
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
        let path = &self
            .registry
            .get_type_var_node(&self.id)
            .unwrap_or_else(|| panic!("TypeVarId {} not found", self.id))
            .path;
        write!(f, "{:?}", path)
    }
}

/// Represents the possible types in our type system
use std::{collections::HashSet, fmt};

use super::type_bounds_map::TypeVarRegistry;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Type {
    /// Any type (top of the lattice, supertype of all types)
    Any,
    // This type represents anything that can be used as a condition. It is top-level type for
    // Int, Bool, Char, Pointer, Function, Tuple. What distinguishes it from numeric literal is
    // that it can be inferred from being used in an int condition. NumericLiteral <: Truthy
    Truthy,

    // A marker that stands for a number literal that was found in the code. It could represent
    // an Int, Bool, Char, Pointer or Function, but not a Tuple.  Type inference rules produce
    // literals as a last resort.
    NumericLiteral,

    /// Integer type
    Int,
    /// Boolean type (result of comparisons)
    Bool,
    /// Character type (for input/output operations)
    Char,
    /// Pointer type with optional pointee type
    Pointer(Box<Type>),
    /// Tuple type (for function arguments and returns)
    Tuple(Vec<Type>),
    /// Function type with parameter and return types. The types must be tuples.
    Function {
        params: Box<Type>,  // Should be Type::Tuple
        returns: Box<Type>, // Should be Type::Tuple
    },
    /// Type variable used during inference
    TypeVar(TypeVarId),
    /// Nothing type (bottom of the lattice, subtype of all types)
    Nothing,
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
    pub fn is_no(&self) -> bool {
        match self {
            YesNoMaybe::No => true,
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

impl Type {
    pub fn is_concrete_type(&self) -> bool {
        match self {
            Type::Int | Type::Bool | Type::Char | Type::Truthy | Type::NumericLiteral => true,
            Type::Any | Type::Nothing => false,
            Type::Pointer(pointee) => pointee.is_concrete_type(),
            Type::Function { params, returns } => {
                params.is_concrete_type() && returns.is_concrete_type()
            }
            Type::Tuple(elements) => elements.iter().all(|e| e.is_concrete_type()),
            Type::TypeVar(_) => false,
        }
    }

    pub fn is_function(&self) -> bool {
        match self {
            Type::Function { .. } => true,
            _ => false,
        }
    }

    pub fn as_type_var_id(&self) -> Option<&TypeVarId> {
        match self {
            Type::TypeVar(id) => Some(id),
            _ => None,
        }
    }

    /*
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
        };
        v
    }
    */

    pub fn is_subtype_of(&self, other: &Type, registry: &impl TypeVarRegistry) -> YesNoMaybe {
        let mut visited = HashSet::new();
        self.is_subtype_of_inner(other, &mut visited, registry)
    }
    /// Checks if `self` is a subtype of `other` (self <: other).

    fn is_subtype_of_inner<'a>(
        &'a self,
        other: &'a Type,
        visited: &mut HashSet<(&'a Type, &'a Type)>,
        registry: &'a impl TypeVarRegistry,
    ) -> YesNoMaybe {
        if !visited.insert((self, other)) {
            return YesNoMaybe::Maybe;
        }
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
                if *other == Type::Any {
                    YesNoMaybe::Yes
                } else if other.is_var_free() {
                    YesNoMaybe::No
                } else {
                    YesNoMaybe::Maybe
                }
            }
            (other, Type::Nothing) => {
                if *other == Type::Nothing {
                    YesNoMaybe::Yes
                } else if other.is_var_free() {
                    YesNoMaybe::No
                } else {
                    YesNoMaybe::Maybe
                }
            }
            (Type::TypeVar(tv_id), other) => {
                let ub = registry.upper_bounds(tv_id);
                for b in ub.iter() {
                    if b.is_subtype_of_inner(other, visited, registry).is_yes() {
                        return YesNoMaybe::Yes;
                    }
                }
                YesNoMaybe::Maybe
            }
            (other, Type::TypeVar(tv_id)) => {
                let lb = registry.lower_bounds(tv_id);
                for b in &lb {
                    if other.is_subtype_of_inner(b, visited, registry).is_yes() {
                        return YesNoMaybe::Yes;
                    }
                }
                YesNoMaybe::Maybe
            }
            (Type::NumericLiteral, Type::Truthy) => true.into(),
            (Type::Char, Type::Truthy) => true.into(),
            (Type::Char, Type::NumericLiteral) => true.into(),
            (Type::Bool, Type::Truthy) => true.into(),
            (Type::Bool, Type::NumericLiteral) => true.into(),
            (Type::Int, Type::Truthy) => true.into(),
            (Type::Int, Type::NumericLiteral) => true.into(),
            (Type::Pointer(_), Type::Truthy) => true.into(),
            (Type::Pointer(_), Type::NumericLiteral) => true.into(),
            (Type::Function { .. }, Type::Truthy) => true.into(),
            (Type::Function { .. }, Type::NumericLiteral) => true.into(),
            (Type::Function { .. }, Type::Pointer(p_target)) => (**p_target
                == Type::NumericLiteral
                || **p_target == Type::Truthy
                || **p_target == Type::Any)
                .into(),

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
            Type::Nothing => Type::Nothing,
            Type::Int => Type::Int,
            Type::Bool => Type::Bool,
            Type::Char => Type::Char,
            Type::Pointer(pointee) => Type::Pointer(Box::new(pointee.map(var_mapper))),
            Type::NumericLiteral => Type::NumericLiteral,
            Type::Truthy => Type::Truthy,
            Type::Any => Type::Any,
        }
    }

    /*
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
    */

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

    /// Collects all TypeVarIds involved in this type, including nested ones.
    ///
    /// # Arguments
    /// * `type_vars`: A mutable HashSet to which discovered TypeVarIds will be added.
    pub fn insert_involved_type_vars(&self, type_vars: &mut HashSet<TypeVarId>) {
        match self {
            Type::TypeVar(id) => {
                type_vars.insert(*id);
            }
            Type::Pointer(inner_type) => {
                inner_type.insert_involved_type_vars(type_vars);
            }
            Type::Function { params, returns } => {
                params.insert_involved_type_vars(type_vars);
                returns.insert_involved_type_vars(type_vars);
            }
            Type::Tuple(elements) => {
                for element_type in elements {
                    element_type.insert_involved_type_vars(type_vars);
                }
            }
            // Primitive types and Any/Nothing/Truthy don't contain TypeVars directly
            Type::Nothing
            | Type::Int
            | Type::Bool
            | Type::Char
            | Type::NumericLiteral
            | Type::Truthy
            | Type::Any => {
                // No nested type vars
            }
        }
    }

    pub fn involved_type_vars(&self) -> HashSet<TypeVarId> {
        let mut involved_vars = HashSet::new();
        self.insert_involved_type_vars(&mut involved_vars);
        involved_vars
    }

    pub fn is_var_free(&self) -> bool {
        match self {
            Type::TypeVar(_) => false,
            Type::Tuple(elements) => elements.iter().all(|e| e.is_var_free()),
            Type::Function { params, returns } => params.is_var_free() && returns.is_var_free(),
            Type::Nothing
            | Type::Int
            | Type::Bool
            | Type::Char
            | Type::NumericLiteral
            | Type::Truthy
            | Type::Any => true,
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

    /// Returns `true` if the type is [`NumericLiteral`].
    ///
    /// [`NumericLiteral`]: Type::NumericLiteral
    #[must_use]
    pub fn is_numeric_literal(&self) -> bool {
        matches!(self, Self::NumericLiteral)
    }

    /// Returns `true` if the type is [`Tuple`].
    ///
    /// [`Tuple`]: Type::Tuple
    #[must_use]
    pub fn is_tuple(&self) -> bool {
        matches!(self, Self::Tuple(..))
    }

    pub fn tuple_arity(&self) -> Option<usize> {
        match self {
            Type::Tuple(elements) => Some(elements.len()),
            _ => None,
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
            Type::TypeVar(id) => write!(f, "{}", id),
            Type::Tuple(elements) => {
                let elements_str: Vec<String> = elements.iter().map(|e| e.to_string()).collect();
                write!(f, "({})", elements_str.join(", "))
            }
            Type::NumericLiteral => write!(f, "NumericLiteral"),
            Type::Truthy => write!(f, "Truthy"),
            Type::Any => write!(f, "Any"),
        }
    }
}

/// Represents the different kinds of type variables we can have.
#[derive(Clone, Debug, PartialEq)]
pub enum TypeVarKind {
    /// A constant value.
    Const(i128),
    /// The variable is linked to a memory reference.
    MemoryReference(SsaMemoryReference, Option<String>),
    /// An expression with an unknown type. This variant stores the expression itself for debugging and linking.
    Expression(Expression<SsaMemoryReference>),
    /// The arguments to a function call at the call site.
    CallSiteArgs {
        addr: TypeVarId,
    },
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
            TypeVarKind::MemoryReference(memref, ..) => Some(memref),
            _ => None,
        }
    }

    pub fn as_versioned_memory(&self) -> Option<&VersionedMemoryReference> {
        match self {
            TypeVarKind::MemoryReference(memref, ..) => memref.as_versioned(),
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
            TypeVarKind::CallSiteArgs { .. } => Some(()),
            _ => None,
        }
    }
}

impl fmt::Display for TypeVarKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeVarKind::Const(v) => write!(f, "Const({})", v),
            TypeVarKind::MemoryReference(memref, role) => {
                write!(
                    f,
                    "{} {}",
                    memref,
                    role.as_ref().map(|s| s.as_str()).unwrap_or("")
                )
            }
            TypeVarKind::Expression(expr) => write!(f, "T({})", expr),
            TypeVarKind::CallSiteArgs { addr } => write!(f, "CallSiteArgs for {addr}"),
            TypeVarKind::CallSiteReturns => write!(f, "CallSiteReturns"),
            TypeVarKind::CalleeArgs(function_id) => write!(f, "CalleeArgs({})", function_id),
            TypeVarKind::CalleeReturns(function_id) => write!(f, "CalleeReturns({})", function_id),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ExpressionPathElement {
    BinaryLeft,
    BinaryRight,
    Unary,
    Deref,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExpressionPath(Vec<ExpressionPathElement>);

impl ExpressionPath {
    pub fn root() -> Self {
        ExpressionPath(vec![])
    }

    pub fn extending(&self, element: ExpressionPathElement) -> Self {
        let mut new_path = self.clone();
        new_path.0.push(element);
        new_path
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get_subexpression<'a>(
        &self,
        expression: &'a Expression<SsaMemoryReference>,
    ) -> &'a Expression<SsaMemoryReference> {
        let mut current_expression = expression;
        while let Expression::DebugMarker(_, expr) = current_expression {
            current_expression = expr;
        }
        for element in &self.0 {
            match element {
                ExpressionPathElement::BinaryLeft => {
                    if let Expression::Binary { lhs, .. } = current_expression {
                        current_expression = lhs;
                    } else {
                        panic!("Invalid path: expected Binary with left hand side");
                    }
                }
                ExpressionPathElement::BinaryRight => {
                    if let Expression::Binary { rhs, .. } = current_expression {
                        current_expression = rhs;
                    } else {
                        panic!("Invalid path: expected Binary with right hand side");
                    }
                }
                ExpressionPathElement::Unary => {
                    if let Expression::Unary { arg, .. } = current_expression {
                        current_expression = arg;
                    } else {
                        panic!("Invalid path: expected Unary expression");
                    }
                }
                ExpressionPathElement::Deref => {
                    if let Expression::Addressable(SsaMemoryReference::Deref(expr)) =
                        current_expression
                    {
                        current_expression = expr;
                    } else {
                        panic!("Invalid path: expected Addressable::Deref expression");
                    }
                }
            }
            while let Expression::DebugMarker(_, expr) = current_expression {
                current_expression = expr;
            }
        }
        current_expression
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeVarPath {
    FunctionDefArg {
        function_id: FunctionId,
        index: usize,
    },
    FunctionDefArgTuple {
        function_id: FunctionId,
    },
    FunctionDefRet {
        function_id: FunctionId,
        index: usize,
    },
    FunctionDefRetTuple {
        function_id: FunctionId,
    },
    AssignmentTargetVersioned {
        function_id: FunctionId,
        instruction_id: InstructionId,
        vmr: VersionedMemoryReference,
    },
    AssignmentTargetDeref {
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression_path: ExpressionPath,
    },
    AssignmentSrc {
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression_path: ExpressionPath,
    },
    IfCond {
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression_path: ExpressionPath,
    },
    Output {
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression_path: ExpressionPath,
    },
    CallAddress {
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression_path: ExpressionPath,
    },
    CallArgTuple {
        function_id: FunctionId,
        instruction_id: InstructionId,
    },
    CallArg {
        function_id: FunctionId,
        instruction_id: InstructionId,
        index: usize,
        expression_path: ExpressionPath,
    },
    CallRetTuple {
        function_id: FunctionId,
        instruction_id: InstructionId,
    },
    CallRet {
        function_id: FunctionId,
        instruction_id: InstructionId,
        index: usize,
        vmr: VersionedMemoryReference,
    },
    PhiAssignment {
        function_id: FunctionId,
        instruction_id: InstructionId,
    },
    PhiAssignmentArg {
        function_id: FunctionId,
        instruction_id: InstructionId,
        index: usize,
    },

    // When we discover that a type var has a function type as an upper bound, we converge it to a function type.
    // with args and returns typles. The path of these new type vars is FunctionsArgsRefinement and FunctionsRetsRefinement.
    FunctionArgsRefinement {
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
    },
    FunctionRetsRefinement {
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
    },
    /// When we are inferring a type has a tuple as an upper bound, it means it is also a tuple with arity as least as the upper bound.
    TupleRefinement {
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
        index: usize,
    },
}

impl TypeVarPath {
    pub fn function_id(&self) -> FunctionId {
        match self {
            TypeVarPath::FunctionDefArg { function_id, .. }
            | TypeVarPath::FunctionDefArgTuple { function_id, .. }
            | TypeVarPath::FunctionDefRet { function_id, .. }
            | TypeVarPath::FunctionDefRetTuple { function_id, .. }
            | TypeVarPath::AssignmentTargetVersioned { function_id, .. }
            | TypeVarPath::AssignmentTargetDeref { function_id, .. }
            | TypeVarPath::AssignmentSrc { function_id, .. }
            | TypeVarPath::IfCond { function_id, .. }
            | TypeVarPath::Output { function_id, .. }
            | TypeVarPath::CallAddress { function_id, .. }
            | TypeVarPath::CallArg { function_id, .. }
            | TypeVarPath::CallArgTuple { function_id, .. }
            | TypeVarPath::CallRet { function_id, .. }
            | TypeVarPath::CallRetTuple { function_id, .. }
            | TypeVarPath::PhiAssignment { function_id, .. }
            | TypeVarPath::PhiAssignmentArg { function_id, .. }
            | TypeVarPath::FunctionArgsRefinement { function_id, .. }
            | TypeVarPath::FunctionRetsRefinement { function_id, .. }
            | TypeVarPath::TupleRefinement { function_id, .. } => *function_id,
        }
    }

    pub fn instruction_id(&self) -> Option<InstructionId> {
        match self {
            TypeVarPath::AssignmentTargetVersioned { instruction_id, .. }
            | TypeVarPath::AssignmentTargetDeref { instruction_id, .. }
            | TypeVarPath::AssignmentSrc { instruction_id, .. }
            | TypeVarPath::IfCond { instruction_id, .. }
            | TypeVarPath::Output { instruction_id, .. }
            | TypeVarPath::CallAddress { instruction_id, .. }
            | TypeVarPath::CallArg { instruction_id, .. }
            | TypeVarPath::CallRet { instruction_id, .. }
            | TypeVarPath::PhiAssignment { instruction_id, .. }
            | TypeVarPath::PhiAssignmentArg { instruction_id, .. }
            | TypeVarPath::CallArgTuple { instruction_id, .. }
            | TypeVarPath::CallRetTuple { instruction_id, .. } => Some(*instruction_id),
            TypeVarPath::FunctionDefArg { .. }
            | TypeVarPath::FunctionDefArgTuple { .. }
            | TypeVarPath::FunctionDefRet { .. }
            | TypeVarPath::FunctionDefRetTuple { .. }
            | TypeVarPath::FunctionArgsRefinement { .. }
            | TypeVarPath::FunctionRetsRefinement { .. }
            | TypeVarPath::TupleRefinement { .. } => None,
        }
    }

    pub fn expression_path(&self) -> Option<&ExpressionPath> {
        match self {
            TypeVarPath::FunctionDefArg { .. }
            | TypeVarPath::FunctionDefArgTuple { .. }
            | TypeVarPath::FunctionDefRet { .. }
            | TypeVarPath::FunctionDefRetTuple { .. }
            | TypeVarPath::AssignmentTargetVersioned { .. }
            | TypeVarPath::CallArgTuple { .. }
            | TypeVarPath::CallRet { .. }
            | TypeVarPath::PhiAssignment { .. }
            | TypeVarPath::PhiAssignmentArg { .. }
            | TypeVarPath::CallRetTuple { .. }
            | TypeVarPath::FunctionArgsRefinement { .. }
            | TypeVarPath::FunctionRetsRefinement { .. }
            | TypeVarPath::TupleRefinement { .. } => None,
            TypeVarPath::AssignmentSrc {
                expression_path, ..
            }
            | TypeVarPath::AssignmentTargetDeref {
                expression_path, ..
            }
            | TypeVarPath::IfCond {
                expression_path, ..
            }
            | TypeVarPath::Output {
                expression_path, ..
            }
            | TypeVarPath::CallAddress {
                expression_path, ..
            }
            | TypeVarPath::CallArg {
                expression_path, ..
            } => Some(expression_path),
        }
    }

    pub fn with_expression_path(&self, expression_path: ExpressionPath) -> TypeVarPath {
        match self {
            TypeVarPath::AssignmentTargetDeref {
                function_id,
                instruction_id,
                ..
            } => TypeVarPath::AssignmentTargetDeref {
                function_id: *function_id,
                instruction_id: *instruction_id,
                expression_path,
            },
            TypeVarPath::AssignmentSrc {
                function_id,
                instruction_id,
                ..
            } => TypeVarPath::AssignmentSrc {
                function_id: *function_id,
                instruction_id: *instruction_id,
                expression_path,
            },
            TypeVarPath::IfCond {
                function_id,
                instruction_id,
                ..
            } => TypeVarPath::IfCond {
                function_id: *function_id,
                instruction_id: *instruction_id,
                expression_path,
            },
            TypeVarPath::Output {
                function_id,
                instruction_id,
                ..
            } => TypeVarPath::Output {
                function_id: *function_id,
                instruction_id: *instruction_id,
                expression_path,
            },
            TypeVarPath::CallAddress {
                function_id,
                instruction_id,
                ..
            } => TypeVarPath::CallAddress {
                function_id: *function_id,
                instruction_id: *instruction_id,
                expression_path,
            },
            TypeVarPath::CallArg {
                function_id,
                instruction_id,
                index,
                ..
            } => TypeVarPath::CallArg {
                function_id: *function_id,
                instruction_id: *instruction_id,
                index: *index,
                expression_path,
            },
            _ => panic!("Cannot add expression path to {:?}", self),
        }
    }

    pub fn extending_path(&self, element: ExpressionPathElement) -> TypeVarPath {
        self.with_expression_path(
            self.expression_path()
                .unwrap_or_else(|| {
                    panic!("Cannot extend path for {:?} / element {:?}", self, element)
                })
                .extending(element),
        )
    }

    pub fn instruction_from_model<'a, S>(
        &self,
        model: &'a Model<S>,
    ) -> Option<&'a InstructionNode<SsaMemoryReference>>
    where
        S: ModelState + HasFoldedSsaResult,
    {
        let Some(instruction_id) = self.instruction_id() else {
            return None;
        };
        let f = model.function(&self.function_id());
        f.blocks()
            .map(|(_, block)| &block.folded_ssa().instructions)
            .flatten()
            .find(|instruction| instruction.id == instruction_id)
    }

    pub fn expression_from_model<'a, S>(
        &self,
        model: &'a Model<S>,
    ) -> Option<&'a Expression<SsaMemoryReference>>
    where
        S: ModelState + HasFoldedSsaResult,
    {
        let Some(inst) = self.instruction_from_model(model) else {
            return None;
        };
        let Some(path) = self.expression_path() else {
            return None;
        };
        let expr = match (self, &inst.kind) {
            (
                TypeVarPath::AssignmentTargetDeref { .. },
                Instruction::Assign {
                    target: SsaMemoryReference::Deref(expr),
                    ..
                },
            ) => expr,
            (TypeVarPath::AssignmentSrc { .. }, Instruction::Assign { src, .. }) => src,
            (TypeVarPath::IfCond { .. }, Instruction::If { cond, .. }) => cond,
            (TypeVarPath::Output { .. }, Instruction::Output(output)) => output,
            (TypeVarPath::CallAddress { .. }, Instruction::Call { addr, .. }) => addr,
            (TypeVarPath::CallArg { index, .. }, Instruction::Call { args, .. }) => &args[*index],
            _ => panic!(
                "Unexpected combination of TypeVarPath and Instruction: {:?}",
                self
            ),
        };
        Some(path.get_subexpression(expr))
    }
}

/// Stores information about the origin of a type variable.
#[derive(Clone, Debug, PartialEq)]
pub struct TypeVarNode {
    pub path: TypeVarPath,
    pub vmr: Option<VersionedMemoryReference>,
}

impl fmt::Display for TypeVarNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.path)
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
                write!(f, "({})", elements_str.join(", "))
            }
            Type::Function { params, returns } => {
                write!(
                    f,
                    "Function{} -> {}",
                    params.display_with(self.registry),
                    returns.display_with(self.registry)
                )
            }
            Type::Nothing => write!(f, "Nothing"),
            Type::Int => write!(f, "Int"),
            Type::Bool => write!(f, "Bool"),
            Type::Char => write!(f, "Char"),
            Type::Pointer(pointee) => write!(f, "Pointer<{}>", pointee.display_with(self.registry)),
            Type::NumericLiteral => write!(f, "NumericLiteral"),
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
        Type::NumericLiteral
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

    fn numeric() -> Type {
        Type::NumericLiteral
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
        assert!(bool().is_subtype_of(&int(), &registry).is_no());
        assert!(bool().is_subtype_of(&bool(), &registry).is_yes());
        assert!(char().is_subtype_of(&int(), &registry).is_no());
        assert!(char().is_subtype_of(&bool(), &registry).is_no());
        assert!(char().is_subtype_of(&numeric(), &registry).is_yes());
        assert!(nothing().is_subtype_of(&int(), &registry).is_yes());
        assert!(nothing().is_subtype_of(&bool(), &registry).is_yes());
        assert!(nothing().is_subtype_of(&char(), &registry).is_yes());
        assert!(!any().is_subtype_of(&int(), &registry).is_yes()); // Expecting !Yes, which means No or Maybe
        assert!(!truthy().is_subtype_of(&bool(), &registry).is_yes()); // Expecting !Yes, which means No or Maybe
        assert!(pointer(int()).is_subtype_of(&truthy(), &registry).is_yes());
        assert!(pointer(bool())
            .is_subtype_of(&pointer(int()), &registry)
            .is_no());
        assert!(pointer(bool())
            .is_subtype_of(&pointer(truthy()), &registry)
            .is_yes());
        assert!(tuple(&[char()])
            .is_subtype_of(&tuple(&[]), &registry)
            .is_yes());
        assert!(!tuple(&[])
            .is_subtype_of(&tuple(&[char()]), &registry)
            .is_yes()); // Expecting !Yes, which means No or Maybe

        let fn_ty = function(tuple(&[]), tuple(&[]));
        assert!(fn_ty.is_subtype_of(&pointer(truthy()), &registry).is_yes());
        assert!(fn_ty.is_subtype_of(&pointer(any()), &registry).is_yes());
        assert!(fn_ty.is_subtype_of(&int(), &registry).is_no());
        assert!(fn_ty.is_subtype_of(&truthy(), &registry).is_yes());
    }
}
