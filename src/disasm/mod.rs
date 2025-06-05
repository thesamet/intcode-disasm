pub mod hlr;
pub mod parser;
pub mod repl;
pub mod v2;
pub mod v3;
mod visitor;

mod symbol_renaming;
#[cfg(test)]
mod test_utils;

pub use symbol_renaming::SymbolRenaming;
use thiserror::Error;

pub use visitor::{PathVisitable, PathVisitor};

/// Represents errors that can occur during disassembly operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("Analysis failed: {0}")]
    AnalysisFailure(String),
}
