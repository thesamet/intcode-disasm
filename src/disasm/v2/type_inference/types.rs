use std::{
    fmt::{self, Display},
    sync::atomic::AtomicUsize,
};

use itertools::Itertools;

use crate::disasm::v2::ssa_form::{SsaOperand, SsaOperandKind, SsaOriginInfo, SsaVar};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VariableKind {
    SsaVar(SsaVar),
    TypeVar(usize),
    Const {
        value: i128,
        origin_info: SsaOriginInfo,
    },
}

impl VariableKind {
    pub fn origin_info(&self) -> Option<SsaOriginInfo> {
        match self {
            VariableKind::SsaVar(var) => Some(var.origin_info),
            VariableKind::Const { origin_info, .. } => Some(*origin_info),
            VariableKind::TypeVar(_) => None,
        }
    }
}

impl Display for VariableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VariableKind::SsaVar(var) => write!(f, "{}", var),
            VariableKind::TypeVar(id) => write!(f, "T{}", id),
            VariableKind::Const { value, .. } => write!(f, "{}", value),
        }
    }
}

/// Represents a type in the type system
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    Nothing,
    Int,
    Bool,
    Char,
    Pointer(Box<Type>),
    Function { args: Box<Type>, returns: Box<Type> }, //Both types are always tuples.
    Variable(VariableKind),
    Tuple(Vec<Type>),
    Truthy, // a marker type for truthy types
    Any,
    Conflict, // Represents a type that was conflicted, but hopefully it will not be needed.
}

static NEXT_VAR_ID: AtomicUsize = AtomicUsize::new(1);

impl Type {
    /// Returns true if this type is a subtype of the other type.
    ///
    /// In our type system, a type is a subtype of itself, and Char and Bool are subtypes of Int.
    pub fn is_subtype_of(&self, other: &Type) -> bool {
        assert!(self.is_var_free());
        assert!(other.is_var_free());
        match (self, other) {
            // A type is always a subtype of itself
            (a, b) if a == b => true,
            (_, Type::Any) => true,
            (Type::Nothing, _) => true,
            (Type::Char, Type::Int) => true,
            (Type::Bool, Type::Int) => true,
            (Type::Pointer(_), Type::Int) => true,
            (Type::Pointer(_), Type::Truthy) => true,
            (Type::Function { .. }, Type::Truthy) => true,
            (Type::Int, Type::Truthy) => true,
            (Type::Bool, Type::Truthy) => true,
            (Type::Tuple(ts1), Type::Tuple(ts2)) => {
                if ts1.len() != ts2.len() {
                    return false;
                }
                for (t1, t2) in ts1.iter().zip(ts2.iter()) {
                    if !t1.is_subtype_of(t2) {
                        return false;
                    }
                }
                true
            }
            (Type::Pointer(a), Type::Pointer(b)) => a.is_subtype_of(b),
            // Function pointer subtyping: contravariant args, covariant returns
            (
                Type::Function {
                    args: args1,
                    returns: returns1,
                },
                Type::Function {
                    args: args2,
                    returns: returns2,
                },
            ) => args2.is_subtype_of(args1),
            (Type::Function { .. }, Type::Int) => true,
            (_, Type::Variable(_)) => unreachable!(),
            (Type::Variable(_), _) => unreachable!(),
            _ => false,
        }
    }

    pub fn from_ssavar(var: &SsaVar) -> Type {
        Type::Variable(VariableKind::SsaVar(*var))
    }

    pub fn from_ssaoperand(ssa_op: &SsaOperand) -> Type {
        match ssa_op.kind {
            SsaOperandKind::Constant(val) => Type::Variable(VariableKind::Const {
                value: val,
                origin_info: ssa_op.origin_info,
            }),
            SsaOperandKind::Variable(ref var) => Type::from_ssavar(var),
        }
    }

    pub fn as_ssavar(&self) -> Option<&SsaVar> {
        match self {
            Type::Variable(VariableKind::SsaVar(var)) => Some(var),
            _ => None,
        }
    }

    pub fn as_variable(&self) -> Option<&VariableKind> {
        match self {
            Type::Variable(var) => Some(var),
            _ => None,
        }
    }

    pub fn as_const(&self) -> Option<&i128> {
        match self {
            Type::Variable(VariableKind::Const { value, .. }) => Some(value),
            _ => None,
        }
    }

    pub fn is_strict_subtype_of(&self, other: &Type) -> bool {
        self != other && self.is_subtype_of(other)
    }

    fn get_types_recursive(&self) -> Vec<Type> {
        match self {
            Type::Any => vec![],
            Type::Nothing => vec![],
            Type::Int => vec![],
            Type::Bool => vec![],
            Type::Char => vec![],
            Type::Pointer(x) => x.get_types_recursive(),
            Type::Variable(_) => vec![self.clone()],
            Type::Tuple(x) => x.iter().flat_map(|x| x.get_types_recursive()).collect(),
            Type::Function { args, returns } => args
                .get_types_recursive()
                .into_iter()
                .chain(returns.get_types_recursive().into_iter())
                .collect(),
            Type::Truthy => vec![],
            Type::Conflict => vec![],
        }
    }

    pub fn is_var_free(&self) -> bool {
        self.get_types_recursive().is_empty()
    }

    pub fn new_var() -> Type {
        let id = NEXT_VAR_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Type::Variable(VariableKind::TypeVar(id))
    }

    pub fn function_pointer(args: Type, returns: Type) -> Type {
        Type::Pointer(Box::new(Type::Function {
            args: Box::new(args),
            returns: Box::new(returns),
        }))
    }

    pub fn function_pointer_types(args: &[Type], returns: &[Type]) -> Type {
        let args = Type::Tuple(args.to_vec());
        let returns = Type::Tuple(returns.to_vec());
        Type::function_pointer(args, returns)
    }

    pub fn is_function_pointer(&self) -> bool {
        match self {
            Type::Pointer(p) => {
                let Type::Function { .. } = p.as_ref() else {
                    return false;
                };
                true
            }
            _ => false,
        }
    }

    pub fn pointer(typ: Type) -> Type {
        Type::Pointer(Box::new(typ))
    }

    pub fn as_tuple(&self) -> Option<&Vec<Type>> {
        match self {
            Type::Tuple(ts) => Some(ts),
            _ => None,
        }
    }

    pub fn callable() -> Type {
        Type::function_pointer(Type::Nothing, Type::Any)
    }
}

pub fn is_concrete_type(typ: &Type) -> bool {
    match typ {
        Type::Int | Type::Bool | Type::Char => true,
        Type::Function { args, returns } => {
            (is_concrete_type(args) || **args == Type::Nothing)
                && (is_concrete_type(returns) || **returns == Type::Any)
        }
        Type::Tuple(x) => x.iter().all(is_concrete_type),
        Type::Pointer(p) => is_concrete_type(p),
        Type::Truthy => false,
        Type::Conflict => false,
        Type::Any => false,
        Type::Nothing => false,
        Type::Variable(_) => false,
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Nothing => write!(f, "nothing"),
            Type::Any => write!(f, "any"),
            Type::Int => write!(f, "int"),
            Type::Bool => write!(f, "bool"),
            Type::Char => write!(f, "char"),
            Type::Pointer(t) => write!(f, "Pointer({})", t),
            Type::Tuple(v) => write!(f, "({})", v.iter().map(|t| format!("{}", t)).join(", ")),
            Type::Variable(VariableKind::TypeVar(id)) => write!(f, "T{}", id),
            Type::Variable(VariableKind::SsaVar(var)) => write!(f, "{}", var),
            Type::Variable(VariableKind::Const { value, .. }) => write!(f, "{}", value),
            Type::Truthy => write!(f, "Truthy"),
            Type::Function { args, returns } => {
                write!(f, "fn(")?;
                write!(f, "{}", args)?;
                write!(f, ") -> ")?;
                write!(f, "{}", returns)?;
                Ok(())
            }
            Type::Conflict => write!(f, "CONFLICT"),
        }
    }
}

/// Returns the most specific type that is a supertype of both types (Least Upper Bound).
/// Used for reconciling types during unification when subtyping is involved.
/// Returns None if the types are incompatible.
pub fn lub(a: &Type, b: &Type) -> Option<Type> {
    assert!(a.is_var_free());
    assert!(b.is_var_free());
    if a == b {
        Some(a.clone())
    } else if a.is_subtype_of(b) {
        Some(b.clone()) // b is the supertype
    } else if b.is_subtype_of(a) {
        Some(a.clone()) // a is the supertype
    } else {
        match (a, b) {
            (Type::Pointer(a), Type::Pointer(b)) => lub(a, b).map(Type::pointer),
            (Type::Bool, Type::Char) | (Type::Char, Type::Bool) => Some(Type::Truthy),
            (Type::Bool, Type::Pointer(_)) => Some(Type::Truthy),
            _ => None,
        }
    }
}

/// Returns the most specific common type (Greatest Lower Bound, conceptually).
/// If one is a subtype of the other, returns the subtype.
/// Returns None if they are incompatible or unrelated.
pub fn glb(a: &Type, b: &Type) -> Option<Type> {
    assert!(a.is_var_free());
    assert!(b.is_var_free());

    if a == b || a.is_subtype_of(b) {
        Some(a.clone())
    } else if b.is_subtype_of(a) {
        Some(b.clone()) // b is the subtype (more specific)
    } else {
        match (a, b) {
            (Type::Pointer(a), Type::Pointer(b)) => glb(a, b).map(Type::pointer),
            (Type::Bool, Type::Char) | (Type::Char, Type::Bool) => Some(Type::Nothing),
            (Type::Bool, Type::Pointer(_)) => Some(Type::Nothing),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lub() {
        assert_eq!(lub(&Type::Int, &Type::Int), Some(Type::Int));
        assert_eq!(lub(&Type::Int, &Type::Bool), Some(Type::Int));
        assert_eq!(lub(&Type::Bool, &Type::Int), Some(Type::Int));
        assert_eq!(lub(&Type::Bool, &Type::Bool), Some(Type::Bool));
        assert_eq!(lub(&Type::Char, &Type::Int), Some(Type::Int));
        assert_eq!(lub(&Type::Char, &Type::Bool), Some(Type::Truthy));
        assert_eq!(lub(&Type::Char, &Type::Char), Some(Type::Char));
        assert_eq!(lub(&Type::Nothing, &Type::Int), Some(Type::Int));
        assert_eq!(lub(&Type::Nothing, &Type::Bool), Some(Type::Bool));
        assert_eq!(lub(&Type::Nothing, &Type::Char), Some(Type::Char));
        assert_eq!(lub(&Type::Any, &Type::Int), Some(Type::Any));
        assert_eq!(lub(&Type::Truthy, &Type::Bool), Some(Type::Truthy));
        assert_eq!(
            lub(&Type::Truthy, &Type::pointer(Type::Int)),
            Some(Type::Truthy)
        );
        assert_eq!(
            lub(&Type::pointer(Type::Bool), &Type::pointer(Type::Int)),
            Some(Type::pointer(Type::Int))
        );
    }

    #[test]
    fn test_glb() {
        assert_eq!(glb(&Type::Int, &Type::Int), Some(Type::Int));
        assert_eq!(glb(&Type::Int, &Type::Bool), Some(Type::Bool));
        assert_eq!(glb(&Type::Bool, &Type::Int), Some(Type::Bool));
        assert_eq!(glb(&Type::Bool, &Type::Bool), Some(Type::Bool));
        assert_eq!(glb(&Type::Char, &Type::Int), Some(Type::Char));
        assert_eq!(glb(&Type::Char, &Type::Bool), Some(Type::Nothing));
        assert_eq!(glb(&Type::Char, &Type::Char), Some(Type::Char));
        assert_eq!(glb(&Type::Nothing, &Type::Int), Some(Type::Nothing));
        assert_eq!(glb(&Type::Nothing, &Type::Bool), Some(Type::Nothing));
        assert_eq!(glb(&Type::Nothing, &Type::Char), Some(Type::Nothing));
        assert_eq!(glb(&Type::Any, &Type::Int), Some(Type::Int));
        assert_eq!(glb(&Type::Truthy, &Type::Bool), Some(Type::Bool));
        assert_eq!(
            glb(&Type::Truthy, &Type::pointer(Type::Int)),
            Some(Type::pointer(Type::Int))
        );
        assert_eq!(
            glb(&Type::pointer(Type::Bool), &Type::pointer(Type::Int)),
            Some(Type::pointer(Type::Bool))
        );
    }
}
