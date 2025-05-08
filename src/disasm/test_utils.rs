// Test utilities for the disassembler crate
pub(crate) use crate::disasm::{
    parser,
    v3::{
        analysis,
        control_flow::FunctionView,
        model::{
            ControlFlowGraphComplete, DataFlowComplete, FunctionCallAnalysisComplete,
            HasControlFlowGraphResult, ImageScannerComplete, InitialState, Model, ModelState,
            SsaComplete,
        },
        FunctionId,
    },
    Error,
};

use super::v3::model::HasInputBinary;

/// Initialize logging for tests
#[cfg(test)]
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
#[cfg(test)]
pub struct TestContext<S: ModelState> {
    pub model: Model<S>,
}

#[cfg(test)]
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

    /// Create a TestContext with image scanning completed
    pub fn with_image_scanning(asm: &str) -> Result<TestContext<ImageScannerComplete>, Error> {
        let binary = parser::compile(asm);
        Ok(TestContext {
            model: analysis::binary_to_scanned_image(binary)?,
        })
    }

    /// Create a TestContext with control flow analysis completed
    pub fn with_control_flow(asm: &str) -> Result<TestContext<ControlFlowGraphComplete>, Error> {
        Self::with_image_scanning(asm)?.with_control_flow_analysis()
    }

    /// Create a TestContext with data flow analysis completed
    pub fn with_data_flow(asm: &str) -> Result<TestContext<DataFlowComplete>, Error> {
        Self::with_control_flow(asm)?.with_data_flow_analysis()
    }

    /// Create a TestContext with SSA form
    pub fn with_ssa(asm: &str) -> Result<TestContext<SsaComplete>, Error> {
        Self::with_data_flow(asm)?.with_ssa_conversion()
    }
}

#[cfg(test)]
impl TestContext<FunctionCallAnalysisComplete> {
    /// Create a TestContext with function call analysis completed
    pub fn with_function_calls(asm: &str) -> Result<Self, Error> {
        Self::with_ssa(asm)?.with_function_call_analysis()
    }

    /// Create a TestContext with all analyses completed
    pub fn with_full_analysis(
        asm: &str,
    ) -> Result<TestContext<FunctionCallAnalysisComplete>, Error> {
        Self::with_function_calls(asm)
    }
}

#[cfg(test)]
impl TestContext<InitialState> {
    /// Creates a new TestContext with just the binary input
    pub fn new(asm: &str) -> Self {
        init_logging();
        let binary = parser::compile(asm);
        Self {
            model: Model::from_binary(binary),
        }
    }
}

#[cfg(test)]
impl TestContext<ImageScannerComplete> {
    /// Creates a new TestContext with image scanning completed
    pub fn new(asm: &str) -> Result<Self, Error> {
        init_logging();
        let binary = parser::compile(asm);
        Ok(Self {
            model: analysis::binary_to_scanned_image(binary)?,
        })
    }

    /// Progress to control flow graph phase
    pub fn with_control_flow_analysis(
        self,
    ) -> Result<TestContext<ControlFlowGraphComplete>, Error> {
        let binary = self.model.image().clone();
        Ok(TestContext {
            model: analysis::binary_to_cfg(binary)?,
        })
    }
}

#[cfg(test)]
impl TestContext<ControlFlowGraphComplete> {
    /// Creates a new TestContext with control flow analysis completed
    pub fn new(asm: &str) -> Result<Self, Error> {
        init_logging();
        let binary = parser::compile(asm);
        Ok(Self {
            model: analysis::binary_to_cfg(binary)?,
        })
    }

    /// Progress to data flow analysis phase
    pub fn with_data_flow_analysis(self) -> Result<TestContext<DataFlowComplete>, Error> {
        let binary = self.model.image().clone();
        Ok(TestContext {
            model: analysis::binary_to_data_flow(binary)?,
        })
    }
}

#[cfg(test)]
impl TestContext<DataFlowComplete> {
    /// Creates a new TestContext with data flow analysis completed
    pub fn new(asm: &str) -> Result<Self, Error> {
        init_logging();
        let binary = parser::compile(asm);
        Ok(Self {
            model: analysis::binary_to_data_flow(binary)?,
        })
    }

    /// Progress to SSA conversion phase
    pub fn with_ssa_conversion(self) -> Result<TestContext<SsaComplete>, Error> {
        let binary = self.model.image().clone();
        Ok(TestContext {
            model: analysis::binary_to_ssa(binary)?,
        })
    }
}

#[cfg(test)]
impl TestContext<SsaComplete> {
    /// Creates a new TestContext with SSA form
    pub fn new(asm: &str) -> Result<Self, Error> {
        init_logging();
        let binary = parser::compile(asm);
        Ok(Self {
            model: analysis::binary_to_ssa(binary)?,
        })
    }

    /// Progress to function call analysis phase
    pub fn with_function_call_analysis(
        self,
    ) -> Result<TestContext<FunctionCallAnalysisComplete>, Error> {
        let binary = self.model.image().clone();
        Ok(TestContext {
            model: analysis::binary_to_function_calls(binary)?,
        })
    }
}

#[cfg(test)]
impl TestContext<FunctionCallAnalysisComplete> {
    /// Creates a new TestContext with function call analysis completed
    pub fn new(asm: &str) -> Result<Self, Error> {
        init_logging();
        let binary = parser::compile(asm);
        Ok(Self {
            model: analysis::binary_to_function_calls(binary)?,
        })
    }
}

/// Test assertions and utilities for expected analysis results
#[cfg(test)]
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
