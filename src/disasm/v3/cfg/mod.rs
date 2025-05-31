mod block;
mod builder;
mod function;
mod result;
#[cfg(test)]
mod tests;

pub use block::Block;
pub use block::BlockView;
pub use block::NextKind;
pub use block::PredecessorKind;
pub use builder::ControlFlowGraphBuilder;
pub use function::Function;
pub use function::FunctionView;
pub use result::ControlFlowGraphResult;
