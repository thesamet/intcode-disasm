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
    
    /// Compute the greatest lower bound (intersection) of two intervals
    pub fn glb(&self, other: &TypeInterval) -> TypeInterval {
        // TODO: validity check - ensure result lower bound is subtype of upper bound
        let lower = Type::glb(self.lower(), other.lower());
        let upper = Type::glb(self.upper(), other.upper());
        
        // If both intervals are singletons and result is also a singleton, preserve that
        if self.is_singleton() && other.is_singleton() && lower == upper {
            TypeInterval::Converged(lower)
        } else {
            TypeInterval::Bounds {
                lower_bound: lower,
                upper_bound: upper,
            }
        }
    }
    
    /// Compute the least upper bound (union) of two intervals
    pub fn lub(&self, other: &TypeInterval) -> TypeInterval {
        // TODO: validity check - ensure result lower bound is subtype of upper bound
        let lower = Type::lub(self.lower(), other.lower());
        let upper = Type::lub(self.upper(), other.upper());
        
        // If both intervals are singletons and result is also a singleton, preserve that
        if self.is_singleton() && other.is_singleton() && lower == upper {
            TypeInterval::Converged(lower)
        } else {
            TypeInterval::Bounds {
                lower_bound: lower,
                upper_bound: upper,
            }
        }
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

    #[test]
    fn test_glb_intervals() {
        let interval1 = TypeInterval::bounds(Type::Nothing, Type::Int);
        let interval2 = TypeInterval::bounds(Type::Char, Type::Truthy);
        
        let result = interval1.glb(&interval2);
        // GLB(Nothing, Char) = Nothing, GLB(Int, Truthy) = Int
        assert_eq!(result.lower(), &Type::Nothing);
        assert_eq!(result.upper(), &Type::Int);
    }

    #[test]
    fn test_lub_intervals() {
        let interval1 = TypeInterval::bounds(Type::Nothing, Type::Int);
        let interval2 = TypeInterval::bounds(Type::Char, Type::Truthy);
        
        let result = interval1.lub(&interval2);
        // LUB(Nothing, Char) = Char, LUB(Int, Truthy) = Truthy  
        assert_eq!(result.lower(), &Type::Char);
        assert_eq!(result.upper(), &Type::Truthy);
    }

    #[test]
    fn test_singleton_interval_operations() {
        let int_interval = TypeInterval::singleton(Type::Int);
        let bool_interval = TypeInterval::singleton(Type::Bool);
        
        let glb_result = int_interval.glb(&bool_interval);
        // GLB(Int, Bool) should be Bool since Bool <: Int
        assert_eq!(glb_result.lower(), &Type::Bool);
        assert_eq!(glb_result.upper(), &Type::Bool);
        assert!(glb_result.is_singleton());
        
        let lub_result = int_interval.lub(&bool_interval);
        // LUB(Int, Bool) should be Int since Bool <: Int
        assert_eq!(lub_result.lower(), &Type::Int);
        assert_eq!(lub_result.upper(), &Type::Int);
        assert!(lub_result.is_singleton());
    }

    #[test]
    fn test_disjoint_interval_operations() {
        let char_interval = TypeInterval::singleton(Type::Char);
        let pointer_interval = TypeInterval::singleton(Type::Pointer(Box::new(Type::Int)));
        
        let glb_result = char_interval.glb(&pointer_interval);
        // GLB(Char, Pointer(Int)) should be Nothing (they're disjoint)
        assert_eq!(glb_result.lower(), &Type::Nothing);
        assert_eq!(glb_result.upper(), &Type::Nothing);
        assert!(glb_result.is_singleton());
        
        let lub_result = char_interval.lub(&pointer_interval);
        // LUB(Char, Pointer(Int)) = Int (since both are subtypes of Int)
        assert_eq!(lub_result.lower(), &Type::Int);
        assert_eq!(lub_result.upper(), &Type::Int);
        assert!(lub_result.is_singleton());
    }
}