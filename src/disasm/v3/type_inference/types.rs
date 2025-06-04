use crate::disasm::{
    symbol_renaming::CustomTypeId,
    v3::{
        define_id_type,
        lir::{Expression, Instruction, InstructionNode},
        model::{HasFoldedSsaResult, Model, ModelState},
        ssa::{SsaMemoryReference, VersionedMemoryReference},
        FunctionId, InstructionId,
    },
};

define_id_type!(TypeVarId);
define_id_type!(GenericTypeVarId);

impl GenericTypeVarId {
    pub fn display_with<'a>(
        &self,
        registry: &'a (impl TypeVarRegistry + Sized),
    ) -> DisplayableGenericTypeVarId<'a> {
        DisplayableGenericTypeVarId {
            id: *self,
            registry,
        }
    }
}

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

pub struct DisplayableGenericTypeVarId<'a> {
    id: GenericTypeVarId,
    registry: &'a dyn TypeVarRegistry,
}

impl<'a> fmt::Display for DisplayableGenericTypeVarId<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(generic_var) = self.registry.get_generic_type_var(&self.id) {
            write!(f, "{}", generic_var.name)
        } else {
            write!(f, "G{}", self.id.0)
        }
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
    /// Generic type variable (T, U, V, etc.)
    Generic(GenericTypeVarId),
    /// Nothing type (bottom of the lattice, subtype of all types)
    Nothing,
    CustomType(CustomTypeId),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum YesNoMaybe {
    Yes,
    No,
    Maybe,
}

impl YesNoMaybe {
    pub fn is_yes(&self) -> bool {
        matches!(self, YesNoMaybe::Yes)
    }
    pub fn is_no(&self) -> bool {
        matches!(self, YesNoMaybe::No)
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
            Type::Int
            | Type::Bool
            | Type::Char
            | Type::Truthy
            | Type::NumericLiteral
            | Type::CustomType(_) => true,
            Type::Any | Type::Nothing => false,
            Type::Pointer(pointee) => pointee.is_concrete_type(),
            Type::Function { params, returns } => {
                params.is_concrete_type() && returns.is_concrete_type()
            }
            Type::Tuple(elements) => elements.iter().all(|e| e.is_concrete_type()),
            Type::TypeVar(_) => false,
            Type::Generic(_) => false,
        }
    }

    pub fn is_function(&self) -> bool {
        matches!(self, Type::Function { .. })
    }

    pub fn as_type_var_id(&self) -> Option<&TypeVarId> {
        match self {
            Type::TypeVar(id) => Some(id),
            _ => None,
        }
    }

    pub fn pointee(&self) -> Option<&Type> {
        match self {
            Type::Pointer(pointee) => Some(pointee),
            _ => None,
        }
    }

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
            // Generic types are handled similarly to TypeVar for now
            (Type::Generic(_), _) | (_, Type::Generic(_)) => YesNoMaybe::Maybe,
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
            Type::Generic(id) => Type::Generic(*id),
            Type::CustomType(id) => Type::CustomType(*id),
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
            Type::Nothing
            | Type::CustomType(_)
            | Type::Int
            | Type::Bool
            | Type::Char
            | Type::NumericLiteral
            | Type::Truthy
            | Type::Any
            | Type::Generic(_) => {
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
            Type::Generic(_) => false,
            Type::Tuple(elements) => elements.iter().all(|e| e.is_var_free()),
            Type::Function { params, returns } => params.is_var_free() && returns.is_var_free(),
            Type::Nothing
            | Type::Int
            | Type::Bool
            | Type::Char
            | Type::NumericLiteral
            | Type::Truthy
            | Type::CustomType(_)
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

    /// Returns `true` if the type is [`Pointer`].
    ///
    /// [`Pointer`]: Type::Pointer
    #[must_use]
    pub fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(..))
    }

    pub fn tuple_arity(&self) -> Option<usize> {
        match self {
            Type::Tuple(elements) => Some(elements.len()),
            _ => None,
        }
    }

    pub fn as_pointer(&self) -> Option<&Type> {
        if let Self::Pointer(v) = self {
            Some(v.as_ref())
        } else {
            None
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
            Type::CustomType(id) => write!(f, "CustomType{}", id),
            Type::TypeVar(id) => write!(f, "{}", id),
            Type::Generic(id) => write!(f, "T{}", id.0),
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

/// Represents a generic type variable (T, U, V, etc.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenericTypeVar {
    pub id: GenericTypeVarId,
    pub name: String, // "T", "U", "V", etc.
    pub bounds: TypeBounds,
}

/// Bounds for a generic type variable
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeBounds {
    pub upper_bounds: HashSet<Type>,
    pub lower_bounds: HashSet<Type>,
}

impl Default for TypeBounds {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeBounds {
    pub fn new() -> Self {
        Self {
            upper_bounds: HashSet::new(),
            lower_bounds: HashSet::new(),
        }
    }

    pub fn with_upper_bounds(bounds: HashSet<Type>) -> Self {
        Self {
            upper_bounds: bounds,
            lower_bounds: HashSet::new(),
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
    SymbolRenaming {
        function_id: FunctionId,
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
    PointerRefinement {
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
    },
}

impl TypeVarPath {
    #[must_use]
    pub fn function_def_arg(function_id: FunctionId, index: usize) -> Self {
        Self::FunctionDefArg { function_id, index }
    }

    #[must_use]
    pub fn function_def_arg_tuple(function_id: FunctionId) -> Self {
        Self::FunctionDefArgTuple { function_id }
    }

    #[must_use]
    pub fn function_def_ret(function_id: FunctionId, index: usize) -> Self {
        Self::FunctionDefRet { function_id, index }
    }

    #[must_use]
    pub fn function_def_ret_tuple(function_id: FunctionId) -> Self {
        Self::FunctionDefRetTuple { function_id }
    }

    #[must_use]
    pub fn assignment_target_versioned(
        function_id: FunctionId,
        instruction_id: InstructionId,
        vmr: VersionedMemoryReference,
    ) -> Self {
        Self::AssignmentTargetVersioned {
            function_id,
            instruction_id,
            vmr,
        }
    }

    #[must_use]
    pub fn assignment_target_deref(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::AssignmentTargetDeref {
            function_id,
            instruction_id,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn assignment_src(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::AssignmentSrc {
            function_id,
            instruction_id,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn if_cond(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::IfCond {
            function_id,
            instruction_id,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn output(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::Output {
            function_id,
            instruction_id,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn call_address(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::CallAddress {
            function_id,
            instruction_id,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn call_arg_tuple(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::CallArgTuple {
            function_id,
            instruction_id,
        }
    }

    #[must_use]
    pub fn call_arg(function_id: FunctionId, instruction_id: InstructionId, index: usize) -> Self {
        Self::CallArg {
            function_id,
            instruction_id,
            index,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn call_ret_tuple(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::CallRetTuple {
            function_id,
            instruction_id,
        }
    }

    #[must_use]
    pub fn call_ret(
        function_id: FunctionId,
        instruction_id: InstructionId,
        index: usize,
        vmr: VersionedMemoryReference,
    ) -> Self {
        Self::CallRet {
            function_id,
            instruction_id,
            index,
            vmr,
        }
    }

    #[must_use]
    pub fn phi_assignment(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::PhiAssignment {
            function_id,
            instruction_id,
        }
    }

    #[must_use]
    pub fn phi_assignment_arg(
        function_id: FunctionId,
        instruction_id: InstructionId,
        index: usize,
    ) -> Self {
        Self::PhiAssignmentArg {
            function_id,
            instruction_id,
            index,
        }
    }

    #[must_use]
    pub fn function_args_refinement(
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
    ) -> Self {
        Self::FunctionArgsRefinement {
            function_id,
            original_type_var_id,
        }
    }

    #[must_use]
    pub fn function_rets_refinement(
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
    ) -> Self {
        Self::FunctionRetsRefinement {
            function_id,
            original_type_var_id,
        }
    }

    #[must_use]
    pub fn tuple_refinement(
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
        index: usize,
    ) -> Self {
        Self::TupleRefinement {
            function_id,
            original_type_var_id,
            index,
        }
    }

    #[must_use]
    pub fn pointer_refinement(function_id: FunctionId, original_type_var_id: TypeVarId) -> Self {
        Self::PointerRefinement {
            function_id,
            original_type_var_id,
        }
    }
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
            | TypeVarPath::TupleRefinement { function_id, .. }
            | TypeVarPath::PointerRefinement { function_id, .. }
            | TypeVarPath::SymbolRenaming { function_id, .. } => *function_id,
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
            | TypeVarPath::TupleRefinement { .. }
            | TypeVarPath::SymbolRenaming { .. }
            | TypeVarPath::PointerRefinement { .. } => None,
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
            | TypeVarPath::TupleRefinement { .. }
            | TypeVarPath::SymbolRenaming { .. }
            | TypeVarPath::PointerRefinement { .. } => None,
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
        let instruction_id = self.instruction_id()?;
        let f = model.function(&self.function_id());
        f.blocks()
            .flat_map(|(_, block)| &block.folded_ssa().instructions)
            .find(|instruction| instruction.id == instruction_id)
    }

    pub fn expression_from_model<'a, S>(
        &self,
        model: &'a Model<S>,
    ) -> Option<&'a Expression<SsaMemoryReference>>
    where
        S: ModelState + HasFoldedSsaResult,
    {
        let inst = self.instruction_from_model(model)?;
        let path = self.expression_path()?;
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
            Type::CustomType(id) => {
                write!(f, "{}", self.registry.get_custom_type_name(*id).unwrap())
            }
            Type::Any => write!(f, "Any"),
            Type::Generic(id) => write!(f, "T{}", id.0),
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

        fn get_generic_type_var(&self, _id: &GenericTypeVarId) -> Option<&GenericTypeVar> {
            todo!()
        }

        fn get_custom_type_name(&self, _custom_type_id: CustomTypeId) -> Option<&String> {
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
