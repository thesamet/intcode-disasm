// Test utilities for the disassembler crate

use super::{
    parser,
    v3::{
        analysis,
        control_flow::FunctionView,
        model::{
            ControlFlowGraphComplete, DataFlowComplete, FunctionCallAnalysisComplete,
            HasControlFlowGraphResult, HasInputBinary, ImageScannerComplete, InitialState, Model,
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

    /// Get a reference to the model's raw binary image
    pub fn image(&self) -> &Vec<i128>
    where
        S: HasInputBinary,
    {
        self.model.image()
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

pub mod assertions {
    use super::*;

    /// Assert that a model has a function with the given ID
    pub fn assert_has_function<S: ModelState + HasControlFlowGraphResult>(
        ctx: &TestContext<S>,
        function_id: FunctionId,
    ) {
        assert!(
            ctx.model.has_function(&function_id),
            "Model should have function with ID {}",
            function_id
        );
    }

    /// Assert that a model has a specific number of functions
    pub fn assert_function_count<S: ModelState + HasControlFlowGraphResult>(
        ctx: &TestContext<S>,
        expected_count: usize,
    ) {
        let actual_count = ctx.model.functions().count();
        assert_eq!(
            actual_count, expected_count,
            "Expected {} functions, got {}",
            expected_count, actual_count
        );
    }
}
