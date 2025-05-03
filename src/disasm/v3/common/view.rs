/// Trait for view types that provide read-only access to model components
pub trait ModelView<T> {
    /// Get a reference to the underlying data
    fn data(&self) -> &T;
}
