use crate::disasm::v3::ssa::result::SsaResult;

/// The overall result of the "Folded SSA" pipeline phase.
/// This phase transforms SSA instructions to have richer expressions by folding temporaries.
/// The result is still structurally an `SsaResult`, but the content of `SsaBlock`s
/// (specifically instructions and potentially phi functions) reflects the folded state.
#[derive(Debug, Clone)]
pub struct FoldedSsaResult(pub SsaResult);

impl FoldedSsaResult {
    /// Creates a new `FoldedSsaResult` by wrapping an `SsaResult`.
    pub fn new(ssa_result: SsaResult) -> Self {
        Self(ssa_result)
    }

    /// Provides access to the inner `SsaResult`.
    pub fn inner(&self) -> &SsaResult {
        &self.0
    }

    /// Provides mutable access to the inner `SsaResult`.
    pub fn inner_mut(&mut self) -> &mut SsaResult {
        &mut self.0
    }
}

// By wrapping SsaResult, Model<FoldedSsaComplete> can delegate HasSsaResult
// calls to the inner SsaResult, allowing existing SSA pretty-printers to work.
