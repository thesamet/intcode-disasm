// Test utilities for the disassembler crate

use super::{
    parser,
    v3::{
        analysis,
        control_flow::FunctionView,
        model::{
            ControlFlowGraphComplete, DataFlowComplete, FoldedSsaComplete,
            FunctionCallAnalysisComplete, HasControlFlowGraphResult, ImageScannerComplete, Model,
            ModelState, SsaComplete,
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
    fn test_context(asm: &str) -> Result<TestContext<S>, Error>;
}

impl TestContextBuilder<ImageScannerComplete> for ImageScannerComplete {
    fn test_context(asm: &str) -> Result<TestContext<ImageScannerComplete>, Error> {
        let binary = parser::compile(asm);
        let model = analysis::binary_to_scanned_image(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<ControlFlowGraphComplete> for ControlFlowGraphComplete {
    fn test_context(asm: &str) -> Result<TestContext<ControlFlowGraphComplete>, Error> {
        let binary = parser::compile(asm);
        let model = analysis::binary_to_cfg(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<DataFlowComplete> for DataFlowComplete {
    fn test_context(asm: &str) -> Result<TestContext<DataFlowComplete>, Error> {
        let binary = parser::compile(asm);
        let model = analysis::binary_to_data_flow(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<SsaComplete> for SsaComplete {
    fn test_context(asm: &str) -> Result<TestContext<SsaComplete>, Error> {
        let binary = parser::compile(asm);
        let model = analysis::binary_to_ssa(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<FunctionCallAnalysisComplete> for FunctionCallAnalysisComplete {
    fn test_context(asm: &str) -> Result<TestContext<FunctionCallAnalysisComplete>, Error> {
        let binary = parser::compile(asm);
        let model = analysis::binary_to_function_calls(binary)?;
        Ok(TestContext { model })
    }
}

impl TestContextBuilder<FoldedSsaComplete> for FoldedSsaComplete {
    fn test_context(asm: &str) -> Result<TestContext<FoldedSsaComplete>, Error> {
        let binary = parser::compile(asm);
        let model = analysis::binary_to_folded_ssa(binary)?;
        Ok(TestContext { model })
    }
}
