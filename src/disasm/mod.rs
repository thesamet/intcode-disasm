pub mod hlr;
pub mod parser;
pub mod repl;
pub mod v2;
pub mod v3;

mod symbol_renaming;
#[cfg(test)]
mod test_utils;

pub use symbol_renaming::SymbolRenaming;
pub use symbol_renaming::UserDefs;
use thiserror::Error;

/// Represents errors that can occur during disassembly operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("Analysis failed: {0}")]
    AnalysisFailure(String),
}
