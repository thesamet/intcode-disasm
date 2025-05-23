use std::fmt;

use super::types::Type;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeInterval {
    Bounds {
        lower_bound: Type,
        upper_bound: Type,
    },
    Converged(Type),
}

impl TypeInterval {
    /// Creates a new interval with given bounds
    #[deprecated(note = "Use bounds() or singleton() factory methods instead")]
    pub fn new(lower: Type, upper: Type) -> Self {
        debug_assert!(
            lower.is_subtype_of(&upper),
            "Invalid interval: {} is not a subtype of {}",
            lower, upper
        );
        TypeInterval::Bounds {
            lower_bound: lower,
            upper_bound: upper,
        }
    }
    
    /// Creates an interval with the given bounds
    pub fn bounds(lower: Type, upper: Type) -> Self {
        debug_assert!(
            lower.is_subtype_of(&upper),
            "Invalid interval: {} is not a subtype of {}",
            lower, upper
        );
        TypeInterval::Bounds {
            lower_bound: lower,
            upper_bound: upper,
        }
    }
    
    /// Creates a singleton interval (converged to a single type)
    pub fn singleton(t: Type) -> Self {
        TypeInterval::Converged(t)
    }
    
    /// Creates an unknown interval (Nothing to Any)
    pub fn unknown() -> Self {
        TypeInterval::Bounds {
            lower_bound: Type::Nothing,
            upper_bound: Type::Any,
        }
    }
    
    /// Gets the lower bound of the interval
    pub fn lower(&self) -> &Type {
        match self {
            TypeInterval::Bounds { lower_bound, .. } => lower_bound,
            TypeInterval::Converged(t) => t,
        }
    }
    
    /// Gets the upper bound of the interval
    pub fn upper(&self) -> &Type {
        match self {
            TypeInterval::Bounds { upper_bound, .. } => upper_bound,
            TypeInterval::Converged(t) => t,
        }
    }
    
    /// Returns true if this is a singleton interval (converged)
    pub fn is_singleton(&self) -> bool {
        matches!(self, TypeInterval::Converged(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_singleton_bounds() {
        let interval = TypeInterval::singleton(Type::Int);
        assert_eq!(interval.lower(), &Type::Int);
        assert_eq!(interval.upper(), &Type::Int);
        assert!(interval.is_singleton());
    }

    #[test]
    fn test_bounds_interval() {
        let interval = TypeInterval::bounds(Type::Nothing, Type::Int);
        assert_eq!(interval.lower(), &Type::Nothing);
        assert_eq!(interval.upper(), &Type::Int);
        assert!(!interval.is_singleton());
    }

    #[test]
    fn test_unknown_interval() {
        let interval = TypeInterval::unknown();
        assert_eq!(interval.lower(), &Type::Nothing);
        assert_eq!(interval.upper(), &Type::Any);
        assert!(!interval.is_singleton());
    }

    #[test]
    #[should_panic]
    fn test_invalid_bounds_panic() {
        TypeInterval::bounds(Type::Int, Type::Nothing);
    }
}