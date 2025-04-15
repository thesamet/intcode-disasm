use std::fmt;

use itertools::Itertools;

use crate::disasm::v2::ssa_form::SsaVar;

/// Represents a type in the type system
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    Nothing,
    Int,
    Bool,
    Char,
    Pointer(Box<Type>),
    Function { args: Box<Type>, returns: Box<Type> }, // Both types are always tuples.
    SsaVar(SsaVar),
    Variable(usize),
    Tuple(Vec<Type>),
    Truthy, // a marker type for truthy types
    Any,
    Conflict, // Represents a type that was conflicted, but hopefully it will not be needed.
}

impl Type {
    /// Returns true if this type is a subtype of the other type.
    ///
    /// In our type system, a type is a subtype of itself, and Char and Bool are subtypes of Int.
    pub fn is_subtype_of(&self, other: &Type) -> bool {
        match (self, other) {
            // A type is always a subtype of itself
            (a, b) if a == b => true,
            (Type::Nothing, _) => true,
            (_, Type::Any) => true,
            (Type::Char, Type::Int) => true,
            (Type::Bool, Type::Int) => true,
            (Type::Pointer(_), Type::Int) => true,
            (Type::Pointer(_), Type::Truthy) => true,
            (Type::Function { .. }, Type::Truthy) => true,
            (Type::Int, Type::Truthy) => true,
            (Type::Bool, Type::Truthy) => true,
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
            ) => {
                /*
                if args1.len() != args2.len() || returns1.len() != returns2.len() {
                    return false;
                }
                // Check args (contravariant): arg2 must be subtype of arg1
                let args_compatible = args1
                    .iter()
                    .zip(args2.iter())
                    .all(|(a1, a2)| a2.is_subtype_of(a1));
                // Check returns (covariant): return1 must be subtype of return2
                let returns_compatible = returns1
                    .iter()
                    .zip(returns2.iter())
                    .all(|(r1, r2)| r1.is_subtype_of(r2));

                args_compatible && returns_compatible
                */
                true
            }
            (Type::Function { .. }, Type::Int) => true,
            _ => false,
        }
    }

    pub fn is_strict_subtype_of(&self, other: &Type) -> bool {
        self != other && self.is_subtype_of(other)
    }

    fn get_types_recursive(&self) -> Vec<Type> {
        match self {
            Type::SsaVar(var) => vec![Type::SsaVar(*var)],
            Type::Any => vec![],
            Type::Nothing => vec![],
            Type::Int => vec![],
            Type::Bool => vec![],
            Type::Char => vec![],
            Type::Pointer(x) => x.get_types_recursive(),
            Type::Variable(_) => vec![],
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
}

pub fn is_concrete_type(typ: &Type) -> bool {
    match typ {
        Type::Int | Type::Bool | Type::Char => true,
        Type::Function { args, returns } => {
            args.get_types_recursive().iter().all(is_concrete_type)
                && returns.get_types_recursive().iter().all(is_concrete_type)
        }
        Type::Tuple(x) => x.iter().all(is_concrete_type),
        Type::Pointer(p) => is_concrete_type(p),
        Type::Truthy => false,
        Type::SsaVar(_) => false,
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
            Type::Variable(id) => write!(f, "T{}", id),
            Type::Truthy => write!(f, "Truthy"),
            Type::Function { args, returns } => {
                write!(f, "fn(")?;
                write!(f, "{}", args)?;
                write!(f, ") -> ")?;
                write!(f, "{}", returns)?;
                Ok(())
            }
            Type::SsaVar(t) => write!(f, "{}", t),
            Type::Conflict => write!(f, "CONFLICT"),
        }
    }
}

/// Returns the most specific type that is a supertype of both types (Least Upper Bound).
/// Used for reconciling types during unification when subtyping is involved.
/// Returns None if the types are incompatible.
pub fn lub(a: &Type, b: &Type) -> Option<Type> {
    if a == b {
        Some(a.clone())
    } else if a.is_subtype_of(b) {
        Some(b.clone()) // b is the supertype
    } else if b.is_subtype_of(a) {
        Some(a.clone()) // a is the supertype
    } else {
        None
    }
}

/// Returns the most specific common type (Greatest Lower Bound, conceptually).
/// If one is a subtype of the other, returns the subtype.
/// Returns None if they are incompatible or unrelated.
pub fn glb(a: &Type, b: &Type) -> Option<Type> {
    if a == b || a.is_subtype_of(b) {
        Some(a.clone())
    } else if b.is_subtype_of(a) {
        Some(b.clone()) // b is the subtype (more specific)
    } else {
        None
    }
}
