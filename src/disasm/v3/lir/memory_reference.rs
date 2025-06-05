use castaway::LifetimeFree;

use super::expression::Expression; // Use LIR Expression
use crate::disasm::v3::id_types::PointerId;
// Keep Display if needed for MemoryReference

/// Represents a reference to a memory location that can be read from or written to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemoryReference {
    /// Represents a fixed memory location outside the stack and code segments.
    Global(usize),
    /// Stack-relative memory location with specific semantics:
    /// - Positive values (R+n): Outgoing parameters to called functions or return values
    /// - Zero (R+0): Return address for function calls
    /// - Negative values (R-n): Local variables, incoming parameters, or return values
    StackRelative(i128),
    /// Represents a pointer to a point in memory.
    Pointer(PointerId),
    /// Dereference of a pointer expression.
    Deref(Box<Expression<MemoryReference>>),
}

unsafe impl LifetimeFree for MemoryReference {}

impl<'a> From<&'a MemoryReference> for MemoryReference {
    fn from(value: &'a MemoryReference) -> Self {
        value.clone()
    }
}

/// A trait for types that can be converted to a MemoryReference.
///
/// This trait provides utility methods for querying properties of memory references,
/// with implementations for any type that can be converted to a MemoryReference.
pub trait MemoryReferenceInfo<'a> {
    /// Converts this value to a MemoryReference.
    ///
    /// This is the core method that must be implemented by all types
    /// implementing this trait.
    fn to_memory_reference(&'a self) -> MemoryReference;

    /// Extracts the global address if this is a global memory reference.
    ///
    /// # Returns
    /// - `Some(usize)` containing the global address if this is a global reference
    /// - `None` if this is not a global reference
    fn as_global(&'a self) -> Option<usize> {
        match self.to_memory_reference() {
            MemoryReference::Global(g) => Some(g),
            _ => None,
        }
    }

    /// Checks if this reference is a global memory reference.
    ///
    /// # Returns
    /// `true` if this is a global memory reference, `false` otherwise
    fn is_global(&'a self) -> bool {
        self.as_global().is_some()
    }

    /// Extracts the offset if this is a stack-relative memory reference.
    ///
    /// # Returns
    /// - `Some(i128)` containing the stack offset if this is a stack-relative reference
    /// - `None` if this is not a stack-relative reference
    fn as_stack_relative(&'a self) -> Option<i128> {
        match self.to_memory_reference() {
            MemoryReference::StackRelative(n) => Some(n),
            _ => None,
        }
    }

    /// Checks if this reference is a stack-relative memory reference.
    ///
    /// # Returns
    /// `true` if this is a stack-relative memory reference, `false` otherwise
    fn is_stack_relative(&'a self) -> bool {
        self.as_stack_relative().is_some()
    }

    /// Extracts the expression if this is a dereferenced pointer.
    ///
    /// # Returns
    /// - `Some(Expression<MemoryReference>)` containing the dereferenced expression
    /// - `None` if this is not a dereferenced pointer
    fn as_deref(&'a self) -> Option<Expression<MemoryReference>> {
        match self.to_memory_reference() {
            MemoryReference::Deref(e) => Some(*e),
            _ => None,
        }
    }

    /// Checks if this reference is a dereferenced pointer.
    ///
    /// # Returns
    /// `true` if this is a dereferenced pointer, `false` otherwise
    fn is_deref(&'a self) -> bool {
        self.as_deref().is_some()
    }

    /// Extracts the pointer ID if this is a direct pointer reference.
    ///
    /// # Returns
    /// - `Some(PointerId)` containing the pointer identifier
    /// - `None` if this is not a direct pointer reference
    fn as_pointer(&'a self) -> Option<PointerId> {
        match self.to_memory_reference() {
            MemoryReference::Pointer(p) => Some(p),
            _ => None,
        }
    }

    /// Checks if this reference is a direct pointer.
    ///
    /// # Returns
    /// `true` if this is a direct pointer reference, `false` otherwise
    fn is_pointer(&'a self) -> bool {
        self.as_pointer().is_some()
    }

    /// Checks if this reference is an outgoing parameter (positive stack offset).
    ///
    /// Outgoing parameters are represented by positive stack-relative offsets.
    ///
    /// # Returns
    /// `true` if this is a stack-relative reference with positive offset, `false` otherwise
    fn is_outgoing_parameter(&'a self) -> bool {
        self.as_stack_relative().map(|n| n > 0).unwrap_or(false)
    }

    /// Checks if this reference is a local variable or incoming parameter (negative stack offset).
    ///
    /// Local variables and incoming parameters are represented by negative stack-relative offsets.
    ///
    /// # Returns
    /// `true` if this is a stack-relative reference with negative offset, `false` otherwise
    fn is_local_or_parameter(&'a self) -> bool {
        self.as_stack_relative().map(|n| n < 0).unwrap_or(false)
    }
}

/// This implementation allows the MemoryReferenceInfo trait to be used with
/// any type that can be converted into a MemoryReference, including both
/// owned and borrowed values. This provides flexibility when working with
/// different representations of memory references.
impl<'a, T: 'a> MemoryReferenceInfo<'a> for T
where
    &'a T: Into<MemoryReference>,
{
    fn to_memory_reference(&'a self) -> MemoryReference {
        self.into()
    }
}

/// A trait for types that can extract read addresses from themselves.
///
/// This trait is crucial for data flow analysis, as it allows us to identify all memory
/// locations that are read when a value is used, including indirect reads through pointers.
///
/// For example, when writing to a dereferenced pointer (`*ptr = value`), we need to recognize
/// that `ptr` itself is being read to determine the target address. This trait provides a
/// standardized way to extract such read operations across different memory reference types.
pub trait ReadExpressionExtractor
where
    Self: Sized,
{
    fn extract_read_expressions(&self) -> Option<&Expression<Self>>;

    /// Extracts all memory references that are read when this value is used.
    ///
    /// This method is particularly important for:
    /// 1. Dereferenced pointers, where the pointer expression must be read
    /// 2. Complex memory addressing expressions that involve multiple reads
    ///
    /// # Returns
    /// A vector of references to all memory locations that are read when this value is used.
    fn extract_read_addresses(&self) -> Vec<&Self>
    where
        Self: Sized,
    {
        self.extract_read_expressions()
            .map(|expr| expr.collect_read_addresses())
            .unwrap_or_default()
    }
}

impl ReadExpressionExtractor for MemoryReference {
    fn extract_read_expressions(&self) -> Option<&Expression<MemoryReference>> {
        match self {
            // When dereferencing a pointer, we need to read the pointer expression
            MemoryReference::Deref(expr) => Some(expr),
            // Other memory reference types don't involve indirect reads
            MemoryReference::Global(_) => None,
            MemoryReference::StackRelative(_) => None,
            MemoryReference::Pointer(_) => None,
        }
    }
}
