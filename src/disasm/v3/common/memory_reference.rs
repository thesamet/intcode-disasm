use crate::disasm::v3::id_types::PointerId;

use super::Expression;
use std::fmt::Display;

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
    fn to_memory_reference(&'a self) -> MemoryReference;

    /// Extracts the global address if this is a global memory reference.
    fn as_global(&'a self) -> Option<usize> {
        match self.to_memory_reference() {
            MemoryReference::Global(g) => Some(g),
            _ => None,
        }
    }

    /// Checks if this reference is a global memory reference.
    fn is_global(&'a self) -> bool {
        self.as_global().is_some()
    }

    /// Extracts the offset if this is a stack-relative memory reference.
    fn as_stack_relative(&'a self) -> Option<i128> {
        match self.to_memory_reference() {
            MemoryReference::StackRelative(n) => Some(n),
            _ => None,
        }
    }

    /// Checks if this reference is a stack-relative memory reference.
    fn is_stack_relative(&'a self) -> bool {
        self.as_stack_relative().is_some()
    }

    /// Extracts the expression if this is a dereferenced pointer.
    fn as_deref(&'a self) -> Option<Expression<MemoryReference>> {
        match self.to_memory_reference() {
            MemoryReference::Deref(e) => Some(*e),
            _ => None,
        }
    }

    /// Checks if this reference is a dereferenced pointer.
    fn is_deref(&'a self) -> bool {
        self.as_deref().is_some()
    }

    /// Extracts the pointer ID if this is a direct pointer reference.
    fn as_pointer(&'a self) -> Option<PointerId> {
        match self.to_memory_reference() {
            MemoryReference::Pointer(p) => Some(p),
            _ => None,
        }
    }

    /// Checks if this reference is a direct pointer.
    fn is_pointer(&'a self) -> bool {
        self.as_pointer().is_some()
    }

    /// Checks if this reference is an outgoing parameter (positive stack offset).
    fn is_outgoing_parameter(&'a self) -> bool {
        self.as_stack_relative().map(|n| n > 0).unwrap_or(false)
    }

    /// Checks if this reference is a local variable or incoming parameter (negative stack offset).
    fn is_local_or_parameter(&'a self) -> bool {
        self.as_stack_relative().map(|n| n < 0).unwrap_or(false)
    }
}

/// This implementation allows the MemoryReferenceInfo trait to be used with
/// any type that can be converted into a MemoryReference, including both
/// owned and borrowed values.
impl<'a, T: 'a> MemoryReferenceInfo<'a> for T
where
    &'a T: Into<MemoryReference>,
{
    fn to_memory_reference(&'a self) -> MemoryReference {
        self.into()
    }
}

/// A trait for types that can extract read addresses from themselves.
pub trait ReadAddressExtractor {
    /// Extracts all memory references that are read when this value is used.
    fn extract_read_addresses(&self) -> Vec<&Self>;
}

impl ReadAddressExtractor for MemoryReference {
    fn extract_read_addresses(&self) -> Vec<&Self> {
        match self {
            // When dereferencing a pointer, we need to read the pointer expression
            MemoryReference::Deref(expr) => expr.collect_read_addresses(),
            // Other memory reference types don't involve indirect reads
            MemoryReference::Global(_) => Vec::new(),
            MemoryReference::StackRelative(_) => Vec::new(),
            MemoryReference::Pointer(_) => Vec::new(),
        }
    }
}
