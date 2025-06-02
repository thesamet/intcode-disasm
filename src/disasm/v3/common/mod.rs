// pub mod expression; // Moved to lir
pub mod function_call;
// pub mod memory_reference; // Moved to lir
pub mod formatting;
pub mod span;
pub mod view;

// pub use expression::{BinaryOperator, Expression, UnaryOperator}; // Moved to lir
pub use function_call::FunctionCall; // Keep FunctionCall/Info here for now
                                     // pub use memory_reference::{MemoryReference, MemoryReferenceInfo, ReadAddressExtractor}; // Moved to lir
pub use span::Span;

/// Computes a fixed point of a function by repeatedly applying the function until it returns `None`.
///
/// This function iteratively applies the given function `update_fn` to a value, then to the result,
/// and so on, until the function returns `None`. The last value before `None` is returned as the fixed point.
///
/// # Arguments
///
/// * `value` - The initial value to start iteration from
/// * `update_fn` - A function that takes a reference to a value and returns a new value or `None` to terminate
///
/// # Returns
///
/// The fixed point of the function, which is the last value produced before the function returns `None`.
pub fn fixed_point<T, F>(value: T, update_fn: F) -> T
where
    F: FnMut(&T) -> Option<T>,
{
    std::iter::successors(Some(value), update_fn)
        .last()
        .unwrap()
}

/// Repeatedly applies a mutating function to a value until the function returns `false`.
///
/// This function iteratively applies the given function `update_fn` to a mutable reference of the value
/// until the function returns `false`, indicating that the fixed point has been reached.
///
/// # Arguments
///
/// * `value` - The mutable reference to the value being updated
/// * `update_fn` - A function that takes a mutable reference to a value, updates it, and returns
///   `true` if further updates are needed or `false` if the fixed point is reached
///
pub fn fixed_point_mut<T, F>(mut value: T, mut update_fn: F) -> T
where
    F: FnMut(&mut T) -> bool,
{
    while update_fn(&mut value) {}
    value
}
