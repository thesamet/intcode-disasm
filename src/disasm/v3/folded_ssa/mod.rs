// Manages the "Folded SSA" representation, where expressions are richer
// and temporaries are often eliminated.

pub mod builder;
pub mod result;
// Potentially a module for FoldedSsaBlock if it grows complex,
// but for now, it's in result.rs.
// pub mod block;

pub use builder::FoldedSsaBuilder;
pub use result::FoldedSsaResult;
// pub use block::FoldedSsaBlock; // If FoldedSsaBlock moves to its own file

#[cfg(test)]
mod tests;
