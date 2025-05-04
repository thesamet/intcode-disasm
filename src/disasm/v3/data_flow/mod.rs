pub mod block; // Make public
pub mod result; // Make public
pub mod analyzer; // Make public

pub use block::{DataFlowBlock, Definition, OriginationPoint};
pub use result::DataFlowResult;
pub use analyzer::DataFlowAnalyzer;

#[cfg(test)]
mod tests;
