use crate::disasm::v3::{
    define_id_type, lir::Expression, ssa::SsaMemoryReference, FunctionId, InstructionId,
};

define_id_type!(TypeVarId);

/// Represents the possible types in our type system
use std::fmt;

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

    /// Symbolic representation of the Greatest Lower Bound of two types.
    GLB(Box<Type>, Box<Type>),
    /// Symbolic representation of the Least Upper Bound of two types.
    LUB(Box<Type>, Box<Type>),
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
            Type::GLB(t1, t2) => write!(f, "GLB({}, {})", t1, t2),
            Type::LUB(t1, t2) => write!(f, "LUB({}, {})", t1, t2),
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
    /// The arguments to a function.
    FunctionArgs,
    /// The return type of a function.
    FunctionReturn,
}

impl fmt::Display for TypeVarKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeVarKind::Const(v) => write!(f, "Const({})", v),
            TypeVarKind::MemoryReference(memref) => write!(f, "{}", memref),
            TypeVarKind::Expression(expr) => write!(f, "{}", expr),
            TypeVarKind::FunctionArgs => write!(f, "FunctionArgs"),
            TypeVarKind::FunctionReturn => write!(f, "FunctionReturn"),
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

impl Type {
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

            (_, Type::GLB(ga, gb)) => self.is_subtype_of(ga) && self.is_subtype_of(gb),
            (Type::GLB(s_ga, s_gb), _) => s_ga.is_subtype_of(other) && s_gb.is_subtype_of(other),

            (_, Type::LUB(la, lb)) => self.is_subtype_of(la) || self.is_subtype_of(lb),
            (Type::LUB(s_la, s_lb), _) => s_la.is_subtype_of(other) && s_lb.is_subtype_of(other),

            (Type::TypeVar(_), _) => false,
            (_, Type::TypeVar(_)) => false,

            _ => false,
        }
    }

    pub fn glb(t1: &Type, t2: &Type) -> Option<Type> {
        if t1.is_subtype_of(t2) {
            return Some(t1.clone());
        }
        if t2.is_subtype_of(t1) {
            return Some(t2.clone());
        }

        if *t1 == Type::Nothing || *t2 == Type::Nothing {
            return Some(Type::Nothing);
        }

        match (t1, t2) {
            (Type::Pointer(_), Type::Bool) => None,
            (Type::Bool, Type::Pointer(_)) => None,

            (Type::Char, Type::Bool) | (Type::Bool, Type::Char) => Some(Type::Nothing),

            (Type::Pointer(p1), Type::Pointer(p2)) => {
                Type::glb(p1, p2).map(|t| Type::Pointer(Box::new(t)))
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
            ) => match (Type::lub(params1, params2), Type::glb(returns1, returns2)) {
                (Some(p_lub), Some(r_glb)) => Some(Type::Function {
                    params: Box::new(p_lub),
                    returns: Box::new(r_glb),
                }),
                _ => None,
            },
            (Type::Tuple(v1), Type::Tuple(v2)) => {
                let len1 = v1.len();
                let len2 = v2.len();
                let min_len = std::cmp::min(len1, len2);
                let max_len = std::cmp::max(len1, len2);
                let mut res_vec = Vec::with_capacity(max_len);
                let mut possible = true;
                for i in 0..min_len {
                    match Type::glb(&v1[i], &v2[i]) {
                        Some(t) => res_vec.push(t),
                        None => {
                            possible = false;
                            break;
                        }
                    }
                }
                if !possible {
                    return None;
                }

                if len1 > len2 {
                    res_vec.extend(v1[min_len..].iter().cloned());
                } else if len2 > len1 {
                    res_vec.extend(v2[min_len..].iter().cloned());
                }
                Some(Type::Tuple(res_vec))
            }

            (Type::TypeVar(_), _)
            | (_, Type::TypeVar(_))
            | (Type::GLB(_, _), _)
            | (_, Type::GLB(_, _))
            | (Type::LUB(_, _), _)
            | (_, Type::LUB(_, _)) => Some(Type::GLB(Box::new(t1.clone()), Box::new(t2.clone()))),

            _ => Some(Type::Nothing),
        }
    }

    pub fn lub(t1: &Type, t2: &Type) -> Option<Type> {
        if t1.is_subtype_of(t2) {
            return Some(t2.clone());
        }
        if t2.is_subtype_of(t1) {
            return Some(t1.clone());
        }

        if *t1 == Type::Any || *t2 == Type::Any {
            return Some(Type::Any);
        }

        match (t1, t2) {
            (Type::Char, Type::Bool) | (Type::Bool, Type::Char) => Some(Type::Truthy), // Ensure this case returns Truthy

            (Type::Pointer(p1), Type::Pointer(p2)) => {
                Type::lub(p1, p2).map(|t| Type::Pointer(Box::new(t)))
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
            ) => match (Type::glb(params1, params2), Type::lub(returns1, returns2)) {
                (Some(p_glb), Some(r_lub)) => Some(Type::Function {
                    params: Box::new(p_glb),
                    returns: Box::new(r_lub),
                }),
                _ => Some(Type::Any),
            },
            (Type::Tuple(v1), Type::Tuple(v2)) => {
                let min_len = std::cmp::min(v1.len(), v2.len());
                let mut res_vec = Vec::with_capacity(min_len);
                for i in 0..min_len {
                    match Type::lub(&v1[i], &v2[i]) {
                        Some(t) => res_vec.push(t),
                        None => return Some(Type::Any),
                    }
                }
                Some(Type::Tuple(res_vec))
            }
            (Type::Bool, Type::Pointer(_)) | (Type::Pointer(_), Type::Bool) => Some(Type::Truthy),
            (Type::Pointer(_), Type::Function { .. })
            | (Type::Function { .. }, Type::Pointer(_)) => Some(Type::Pointer(Box::new(Type::Any))),
            (Type::Char, Type::Pointer(_)) | (Type::Pointer(_), Type::Char) => Some(Type::Int),
            (Type::Char, Type::Function { .. }) | (Type::Function { .. }, Type::Char) => {
                Some(Type::Int)
            }
            (Type::Bool, Type::Function { .. }) | (Type::Function { .. }, Type::Bool) => {
                Some(Type::Int)
            }

            (Type::TypeVar(_), _)
            | (_, Type::TypeVar(_))
            | (Type::GLB(_, _), _)
            | (_, Type::GLB(_, _))
            | (Type::LUB(_, _), _)
            | (_, Type::LUB(_, _)) => Some(Type::LUB(Box::new(t1.clone()), Box::new(t2.clone()))),

            _ => Some(Type::Any),
        }
    }

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
            Type::GLB(t1, t2) | Type::LUB(t1, t2) => {
                t1.collect_involved_type_vars(type_vars);
                t2.collect_involved_type_vars(type_vars);
            }
            // Primitive types and Any/Nothing/Truthy don't contain TypeVars directly
            Type::Nothing | Type::Int | Type::Bool | Type::Char | Type::Truthy | Type::Any => {
                // No nested type vars
            }
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
        assert_eq!(Type::lub(&int(), &int()), Some(int()));
        assert_eq!(Type::lub(&int(), &bool()), Some(int()));
        assert_eq!(Type::lub(&bool(), &int()), Some(int()));
        assert_eq!(Type::lub(&bool(), &bool()), Some(bool()));
        assert_eq!(Type::lub(&char(), &int()), Some(int()));
        assert_eq!(Type::lub(&char(), &bool()), Some(truthy()));
        assert_eq!(Type::lub(&char(), &char()), Some(char()));
        assert_eq!(Type::lub(&nothing(), &int()), Some(int()));
        assert_eq!(Type::lub(&nothing(), &bool()), Some(bool()));
        assert_eq!(Type::lub(&nothing(), &char()), Some(char()));
        assert_eq!(Type::lub(&any(), &int()), Some(any()));
        assert_eq!(Type::lub(&truthy(), &bool()), Some(truthy()));
        assert_eq!(Type::lub(&truthy(), &pointer(int())), Some(truthy()));
        assert_eq!(
            Type::lub(&pointer(bool()), &pointer(int())),
            Some(pointer(int()))
        );
        assert_eq!(Type::lub(&pointer(pointer(any())), &bool()), Some(truthy()));
    }

    #[test]
    fn test_lub_tuples() {
        assert_eq!(
            Type::lub(&tuple(&[bool(), int()]), &tuple(&[bool()])),
            Some(tuple(&[bool()]))
        );
        assert_eq!(
            Type::lub(&tuple(&[bool()]), &tuple(&[bool(), char()])),
            Some(tuple(&[bool()]))
        );
        assert_eq!(
            Type::lub(&tuple(&[int(), bool(), char()]), &tuple(&[int(), int()])),
            Some(tuple(&[int(), int()]))
        );
        assert_eq!(
            Type::lub(&tuple(&[bool(), int()]), &tuple(&[int(), bool()])),
            Some(tuple(&[int(), int()]))
        );
        assert_eq!(
            Type::lub(&tuple(&[bool(), int()]), &tuple(&[])),
            Some(tuple(&[]))
        );
    }

    #[test]
    fn test_lub_functions() {
        let fn1_params = tuple(&[int(), bool()]);
        let fn1_ret = tuple(&[int()]);
        let fn1 = function(fn1_params.clone(), fn1_ret.clone());

        assert_eq!(Type::lub(&fn1, &fn1), Some(fn1.clone()));

        let fn2_params = tuple(&[int()]);
        let fn2 = function(fn2_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn2),
            Some(function(tuple(&[int(), bool()]), tuple(&[int()])))
        );

        let fn3_ret = tuple(&[bool()]);
        let fn3 = function(fn1_params.clone(), fn3_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn3),
            Some(function(tuple(&[int(), bool()]), tuple(&[int()])))
        );

        let fn4_ret = tuple(&[char()]);
        let fn4 = function(fn1_params.clone(), fn4_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn4),
            Some(function(tuple(&[int(), bool()]), tuple(&[int()])))
        );

        let fn5_params = tuple(&[int(), bool(), char()]);
        let fn5 = function(fn5_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::lub(&fn1, &fn5),
            Some(function(tuple(&[int(), bool(), char()]), tuple(&[int()])))
        );
    }

    #[test]
    fn test_glb() {
        assert_eq!(Type::glb(&int(), &int()), Some(int()));
        assert_eq!(Type::glb(&int(), &bool()), Some(bool()));
        assert_eq!(Type::glb(&bool(), &int()), Some(bool()));
        assert_eq!(Type::glb(&bool(), &bool()), Some(bool()));
        assert_eq!(Type::glb(&char(), &int()), Some(char()));
        assert_eq!(Type::glb(&char(), &bool()), Some(nothing()));
        assert_eq!(Type::glb(&char(), &char()), Some(char()));
        assert_eq!(Type::glb(&nothing(), &int()), Some(nothing()));
        assert_eq!(Type::glb(&nothing(), &bool()), Some(nothing()));
        assert_eq!(Type::glb(&nothing(), &char()), Some(nothing()));
        assert_eq!(Type::glb(&any(), &int()), Some(int()));
        assert_eq!(Type::glb(&truthy(), &bool()), Some(bool()));
        assert_eq!(Type::glb(&truthy(), &pointer(int())), Some(pointer(int())));
        assert_eq!(
            Type::glb(&pointer(bool()), &pointer(int())),
            Some(pointer(bool()))
        );
        assert_eq!(Type::glb(&pointer(pointer(any())), &bool()), None);
    }

    #[test]
    fn test_glb_tuples() {
        assert_eq!(
            Type::glb(&tuple(&[bool(), pointer(int())]), &tuple(&[bool()])),
            Some(tuple(&[bool(), pointer(int())]))
        );
        assert_eq!(
            Type::glb(&tuple(&[bool()]), &tuple(&[bool(), int()])),
            Some(tuple(&[bool(), int()]))
        );
        assert_eq!(
            Type::glb(&tuple(&[int(), bool()]), &tuple(&[int(), int()])),
            Some(tuple(&[int(), bool()]))
        );
        assert_eq!(
            Type::glb(&tuple(&[]), &tuple(&[bool(), int()])),
            Some(tuple(&[bool(), int()]))
        );
        assert_eq!(
            Type::glb(
                &tuple(&[int(), int(), bool()]),
                &tuple(&[int(), bool(), char()])
            ),
            Some(tuple(&[int(), bool(), nothing()]))
        );
        assert_eq!(
            Type::glb(&tuple(&[bool(),]), &tuple(&[char(), int()])),
            Some(tuple(&[nothing(), int()]))
        );
    }

    #[test]
    fn test_glb_functions() {
        let fn1_params = tuple(&[int(), bool()]); // Changed args to params
        let fn1_ret = tuple(&[int()]);
        let fn1 = function(fn1_params.clone(), fn1_ret.clone());
        assert_eq!(Type::glb(&fn1, &fn1), Some(fn1.clone()));

        let fn2_params = tuple(&[int()]); // Changed args to params
        let fn2 = function(fn2_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::glb(&fn1, &fn2),
            Some(function(tuple(&[int()]), tuple(&[int()])))
        );

        let fn3_params = tuple(&[int(), char()]); // Changed args to params
        let fn3 = function(fn3_params.clone(), fn1_ret.clone());
        assert_eq!(
            Type::glb(&fn1, &fn3),
            Some(function(tuple(&[int(), truthy()]), tuple(&[int()])))
        );

        let fn4_ret = tuple(&[char()]);
        let fn4 = function(fn1_params.clone(), fn4_ret.clone());
        assert_eq!(
            Type::glb(&fn1, &fn4),
            Some(function(tuple(&[int(), bool()]), tuple(&[char()])))
        );
    }
}
