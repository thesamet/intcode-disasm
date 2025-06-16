// Test utilities for the disassembler crate

use crate::disasm::{symbol_renaming::UserDefs, v3::model::HlrConstructionComplete};

use super::{
    parser,
    v3::{
        analysis,
        cfg::FunctionView,
        model::{
            ControlFlowGraphComplete, DataFlowComplete, FoldedSsaComplete,
            FunctionCallAnalysisComplete, HasControlFlowGraphResult, ImageScannerComplete, Model,
            ModelState, SsaComplete, TypeInferenceComplete, VariableMergerComplete,
        },
        FunctionId,
    },
    Error,
};
pub fn init_logging() {
    use std::io::Write;
    let _ = env_logger::builder()
        .format(|buf, record| writeln!(buf, "{}: {}", record.level(), record.args()))
        .is_test(true)
        .try_init();
}

/// A unified test context that supports v3 model system at different phases of analysis.
///
/// This struct provides a consistent interface for tests to create models at specific
/// phases of the analysis pipeline.
pub struct TestContext<S: ModelState> {
    pub model: Model<S>,
}

impl<S: ModelState> TestContext<S> {
    /// Gets the main function view (function with ID 0) if available on this model state
    pub fn main_function(&self) -> FunctionView<S>
    where
        S: HasControlFlowGraphResult,
    {
        self.model.function(&FunctionId::new(0))
    }
}

pub trait TestContextBuilder<S: ModelState> {
    fn test_context_with_user_defs(asm: &str, user_defs: UserDefs)
        -> Result<TestContext<S>, Error>;

    fn test_context(asm: &str) -> Result<TestContext<S>, Error> {
        Self::test_context_with_user_defs(asm, UserDefs::new())
    }
}

impl TestContextBuilder<ImageScannerComplete> for ImageScannerComplete {
    fn test_context_with_user_defs(
        asm: &str,
        _user_defs: UserDefs,
    ) -> Result<TestContext<ImageScannerComplete>, Error> {
        init_logging();
        let binary = parser::compile(asm);
        let model = analysis::binary_to_scanned_image(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<ControlFlowGraphComplete> for ControlFlowGraphComplete {
    fn test_context_with_user_defs(
        asm: &str,
        _user_defs: UserDefs,
    ) -> Result<TestContext<ControlFlowGraphComplete>, Error> {
        init_logging();
        let binary = parser::compile(asm);
        let model = analysis::binary_to_cfg(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<DataFlowComplete> for DataFlowComplete {
    fn test_context_with_user_defs(
        asm: &str,
        _user_defs: UserDefs,
    ) -> Result<TestContext<DataFlowComplete>, Error> {
        init_logging();
        let binary = parser::compile(asm);
        let model = analysis::binary_to_data_flow(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<SsaComplete> for SsaComplete {
    fn test_context_with_user_defs(
        asm: &str,
        _user_defs: UserDefs,
    ) -> Result<TestContext<SsaComplete>, Error> {
        init_logging();
        let binary = parser::compile(asm);
        let model = analysis::binary_to_ssa(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<FunctionCallAnalysisComplete> for FunctionCallAnalysisComplete {
    fn test_context_with_user_defs(
        asm: &str,
        _user_defs: UserDefs,
    ) -> Result<TestContext<FunctionCallAnalysisComplete>, Error> {
        init_logging();
        let binary = parser::compile(asm);
        let model = analysis::binary_to_function_calls(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<FoldedSsaComplete> for FoldedSsaComplete {
    fn test_context_with_user_defs(
        asm: &str,
        _user_defs: UserDefs,
    ) -> Result<TestContext<FoldedSsaComplete>, Error> {
        init_logging();
        let binary = parser::compile(asm);
        let model = analysis::binary_to_folded_ssa(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<TypeInferenceComplete> for TypeInferenceComplete {
    fn test_context_with_user_defs(
        asm: &str,
        user_defs: UserDefs,
    ) -> Result<TestContext<TypeInferenceComplete>, Error> {
        init_logging();
        let binary = parser::compile(asm);
        let model = analysis::binary_to_type_inference(binary, user_defs)?;

        Ok(TestContext { model })
    }
}

impl TestContextBuilder<VariableMergerComplete> for VariableMergerComplete {
    fn test_context_with_user_defs(
        asm: &str,
        user_defs: UserDefs,
    ) -> Result<TestContext<VariableMergerComplete>, Error> {
        init_logging();
        let binary = parser::compile(asm);
        let model = analysis::binary_to_variable_merger(binary, user_defs)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<HlrConstructionComplete> for HlrConstructionComplete {
    fn test_context_with_user_defs(
        asm: &str,
        user_defs: UserDefs,
    ) -> Result<TestContext<HlrConstructionComplete>, Error> {
        init_logging();
        let binary = parser::compile(asm);
        let model = analysis::binary_to_hlr(binary, user_defs)?;
        Ok(TestContext { model })
    }
}
