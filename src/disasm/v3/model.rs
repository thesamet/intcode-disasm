use std::collections::HashMap;
use std::marker::PhantomData;

use crate::disasm::v3::control_flow::{ControlFlowGraphResult, Function};
use crate::disasm::v3::data_flow::DataFlowResult;
use crate::disasm::v3::function_call::FunctionCallAnalysisResult;
use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v3::image_scanner::ImageScannerResult;
use crate::disasm::v3::ssa::SsaResult;

// --- State Types ---
pub trait ModelState {}

pub struct InitialState {}
pub struct ImageScannerComplete {}
pub struct ControlFlowGraphComplete {}
pub struct DataFlowComplete {}
pub struct SsaComplete {}
pub struct FunctionCallComplete {}

impl ModelState for InitialState {}
impl ModelState for ImageScannerComplete {}
impl ModelState for ControlFlowGraphComplete {}
impl ModelState for DataFlowComplete {}
impl ModelState for SsaComplete {}
impl ModelState for FunctionCallComplete {}

// Implement capability traits for appropriate states
impl HasImageScannerResult for ImageScannerComplete {}
impl HasImageScannerResult for ControlFlowGraphComplete {}
impl HasImageScannerResult for DataFlowComplete {}
impl HasImageScannerResult for SsaComplete {}
impl HasImageScannerResult for FunctionCallComplete {}

impl HasControlFlowGraphResult for ControlFlowGraphComplete {}
impl HasControlFlowGraphResult for DataFlowComplete {}
impl HasControlFlowGraphResult for SsaComplete {}
impl HasControlFlowGraphResult for FunctionCallComplete {}

impl HasDataFlowResult for DataFlowComplete {}
impl HasDataFlowResult for SsaComplete {}
impl HasDataFlowResult for FunctionCallComplete {}

impl HasSsaResult for SsaComplete {}
impl HasSsaResult for FunctionCallComplete {}
impl HasFunctionCallAnalysisResult for FunctionCallComplete {}

macro_rules! make_model {
    ($model:ident, $state:ident, { $($field:ty),* }) => {
        paste::paste! {
            #[derive(Clone, Debug)] // Added Debug
            pub struct $model<S: $state> {
                pub $([<$field:snake:lower>]: Option<$field>,)*
                marker: std::marker::PhantomData<S>,
            }
            impl<S: $state> $model<S> {
                pub fn new() -> Self {
                    Self {
                        $([<$field:snake:lower>]: None,)*
                        marker: std::marker::PhantomData,
                    }
                }
                $(
                let $field = update_fields_helper!(
                                    $model,
                                    $field,           // Pass the type of the outer field
                                    { $($field),* }   // Pass the full list of all field types
                                );
                )*;

                // Define with_ methods for each field
            }
            // Define Has traits for each field
            $(
                pub trait [<Has $field>]: ModelState {}
            )*
            $(
            impl<S: $state> $model<S>
            where
                S: [<Has $field>]
            {
                pub fn [<$field:snake:lower>](&self) -> &$field {
                    self.[<$field:snake:lower>].as_ref().unwrap()
                }

            })*
        }
    }
}

// Remove unused macro

macro_rules! add_block_view_when {
    ($result_type:ident, $result_var:ident) => {
        paste::paste! {
            add_block_view_when!($result_type, $result_var, [<$result_type Block>]);
        }
    };
    ($result_type:ident, $result_var:ident, $block_type:ty) => {
        paste::paste! {
            impl<'a, S: crate::disasm::v3::model::ModelState> crate::disasm::v3::control_flow::BlockView<'a, S>
            where
                S: crate::disasm::v3::model::[<Has $result_type Result>],
            {
                pub fn $result_var(&self) -> &$block_type {
                    self.model
                        .[<$result_type:snake:lower _result>]()
                        .blocks
                        .get(&self.block_id())
                        .unwrap_or_else(|| {
                            panic!(
                                "Could not find {} information for block {}",
                                stringify!($result_var),
                                self.block_id()
                            )
                        })
                }
            }
        }
    };
}
pub(crate) use add_block_view_when;

// Define Has traits for each field type
pub trait HasImageScannerResult: ModelState {}
pub trait HasControlFlowGraphResult: ModelState {}
pub trait HasDataFlowResult: ModelState {}
pub trait HasSsaResult: ModelState {}
pub trait HasFunctionCallAnalysisResult: ModelState {}

// Implement traits for appropriate state types
impl HasImageScannerResult for ImageScannerComplete {}
impl HasImageScannerResult for ControlFlowGraphComplete {}
impl HasImageScannerResult for DataFlowComplete {}
impl HasImageScannerResult for SsaComplete {}
impl HasImageScannerResult for FunctionCallComplete {}

impl HasControlFlowGraphResult for ControlFlowGraphComplete {}
impl HasControlFlowGraphResult for DataFlowComplete {}
impl HasControlFlowGraphResult for SsaComplete {}
impl HasControlFlowGraphResult for FunctionCallComplete {}

impl HasDataFlowResult for DataFlowComplete {}
impl HasDataFlowResult for SsaComplete {}
impl HasDataFlowResult for FunctionCallComplete {}

impl HasSsaResult for SsaComplete {}
impl HasSsaResult for FunctionCallComplete {}
impl HasFunctionCallAnalysisResult for FunctionCallComplete {}

// Define the Model struct
#[derive(Clone, Debug)]
pub struct Model<S: ModelState> {
    pub image_scanner_result: Option<ImageScannerResult>,
    pub control_flow_graph_result: Option<ControlFlowGraphResult>,
    pub data_flow_result: Option<DataFlowResult>,
    pub ssa_result: Option<SsaResult>,
    pub function_call_analysis_result: Option<FunctionCallAnalysisResult>,
    marker: std::marker::PhantomData<S>,
}

impl<S: ModelState> Model<S> {
    pub fn new() -> Self {
        Self {
            image_scanner_result: None,
            control_flow_graph_result: None,
            data_flow_result: None,
            ssa_result: None,
            function_call_analysis_result: None,
            marker: std::marker::PhantomData,
        }
    }
    
    // Define with_ methods for each field
    pub fn with_image_scanner_result(mut self, value: ImageScannerResult) -> Self {
        self.image_scanner_result = Some(value);
        self
    }
    
    pub fn with_control_flow_graph_result(mut self, value: ControlFlowGraphResult) -> Self {
        self.control_flow_graph_result = Some(value);
        self
    }
    
    pub fn with_data_flow_result(mut self, value: DataFlowResult) -> Self {
        self.data_flow_result = Some(value);
        self
    }
    
    pub fn with_ssa_result(mut self, value: SsaResult) -> Self {
        self.ssa_result = Some(value);
        self
    }
    
    pub fn with_function_call_analysis_result(mut self, value: FunctionCallAnalysisResult) -> Self {
        self.function_call_analysis_result = Some(value);
        self
    }
}

// Implement accessor methods for each field based on capability traits
impl<S: ModelState> Model<S>
where
    S: HasImageScannerResult
{
    pub fn image_scanner_result(&self) -> &ImageScannerResult {
        self.image_scanner_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S>
where
    S: HasControlFlowGraphResult
{
    pub fn control_flow_graph_result(&self) -> &ControlFlowGraphResult {
        self.control_flow_graph_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S>
where
    S: HasDataFlowResult
{
    pub fn data_flow_result(&self) -> &DataFlowResult {
        self.data_flow_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S>
where
    S: HasSsaResult
{
    pub fn ssa_result(&self) -> &SsaResult {
        self.ssa_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S>
where
    S: HasFunctionCallAnalysisResult
{
    pub fn function_call_analysis_result(&self) -> &FunctionCallAnalysisResult {
        self.function_call_analysis_result.as_ref().unwrap()
    }
}

#[cfg(test)]
mod tests {

    use crate::disasm::{
        v2::{
            instructions::{Instruction, InstructionNode},
            ssa_form::VersionRegistry,
        },
        v3::{
            common::CallSiteInfo, data_flow::DataFlowBlock, function_call::result::CalleeInfo,
            lir::MemoryReference, ssa::SsaBlock, Block, InstructionId, NextKind, Span,
        },
    };

    use super::*;

    // Helper function to create common test data
    // Helper functions for creating test data for different model stages

    fn create_test_ids() -> (FunctionId, BlockId) {
        let function_id = FunctionId::from(0);
        let block_id = BlockId::from(0);
        (function_id, block_id)
    }

    fn create_image_scanner_data() -> ImageScannerResult {
        ImageScannerResult::default()
    }

    fn create_block(function_id: FunctionId, block_id: BlockId) -> Block {
        Block {
            id: block_id,
            containing_function_id: function_id,
            span: Span { start: 0, end: 10 },
            low_instructions: vec![InstructionNode {
                id: InstructionId::fresh(),
                kind: Instruction::Halt,
            }],
            next: NextKind::Halt,
            predecessors: vec![],
        }
    }

    fn create_cfg_data(function_id: FunctionId, block_id: BlockId) -> ControlFlowGraphResult {
        let mut function_map = HashMap::new();
        let mut blocks = HashMap::new();
        blocks.insert(block_id, create_block(function_id, block_id));

        function_map.insert(
            function_id,
            Function::new(function_id, block_id, 8, Some(block_id), blocks),
        );

        ControlFlowGraphResult::new(function_map)
    }

    fn create_data_flow_data(block_id: BlockId) -> DataFlowResult {
        let mut data_flow_blocks = HashMap::new();
        let mut gen = HashMap::new();
        gen.insert(
            MemoryReference::Global(123),
            (InstructionId::fresh(), MemoryReference::Global(0)),
        );

        data_flow_blocks.insert(block_id, DataFlowBlock::default());

        DataFlowResult {
            blocks: data_flow_blocks,
        }
    }

    fn create_ssa_data(block_id: BlockId, function_id: FunctionId) -> SsaResult {
        let mut ssa_blocks = HashMap::new();
        ssa_blocks.insert(
            block_id,
            SsaBlock {
                original_id: block_id,
                phi_functions: vec![],
                instructions: vec![InstructionNode {
                    id: InstructionId::fresh(),
                    kind: Instruction::Halt,
                }],
                start_state: VersionRegistry::new(function_id),
                end_state: VersionRegistry::new(function_id),
                next: NextKind::Halt,
                predecessors: vec![],
            },
        );

        SsaResult { blocks: ssa_blocks }
    }

    fn create_function_call_data(
        function_id: FunctionId,
        block_id: BlockId,
    ) -> FunctionCallAnalysisResult {
        let mut function_call_functions = HashMap::new();
        function_call_functions.insert(function_id, CalleeInfo::default());

        let mut function_call_blocks = HashMap::new();
        function_call_blocks.insert(block_id, CallSiteInfo::default());

        FunctionCallAnalysisResult {
            functions: function_call_functions,
            blocks: function_call_blocks,
        }
    }

    // Main function to create test data for all states
    fn create_test_data() -> (
        FunctionId,
        BlockId,
        ImageScannerResult,
        ControlFlowGraphResult,
        DataFlowResult,
        SsaResult,
        FunctionCallAnalysisResult,
    ) {
        let (function_id, block_id) = create_test_ids();
        let image_scanner_data = create_image_scanner_data();
        let cfg_data = create_cfg_data(function_id, block_id);
        let data_flow_data = create_data_flow_data(block_id);
        let ssa_data = create_ssa_data(block_id, function_id);
        let function_call_data = create_function_call_data(function_id, block_id);

        (
            function_id,
            block_id,
            image_scanner_data,
            cfg_data,
            data_flow_data,
            ssa_data,
            function_call_data,
        )
    }

    // Helper to create a model with ImageScannerComplete state
    fn create_image_scanner_model(
        image_scanner_data: &ImageScannerResult,
    ) -> Model<ImageScannerComplete> {
        Model::<ImageScannerComplete> {
            image_scanner_result: Some(image_scanner_data.clone()),
            control_flow_graph_result: None,
            data_flow_result: None,
            ssa_result: None,
            function_call_analysis_result: None,
            marker: PhantomData,
        }
    }

    // Helper to create a model with ControlFlowGraphComplete state
    fn create_cfg_model(
        image_scanner_data: &ImageScannerResult,
        cfg_data: &ControlFlowGraphResult,
    ) -> Model<ControlFlowGraphComplete> {
        Model::<ControlFlowGraphComplete> {
            image_scanner_result: Some(image_scanner_data.clone()),
            control_flow_graph_result: Some(cfg_data.clone()),
            data_flow_result: None,
            ssa_result: None,
            function_call_analysis_result: None,
            marker: PhantomData,
        }
    }

    // Helper to create a model with DataFlowComplete state
    fn create_data_flow_model(
        image_scanner_data: &ImageScannerResult,
        cfg_data: &ControlFlowGraphResult,
        data_flow_data: &DataFlowResult,
    ) -> Model<DataFlowComplete> {
        Model::<DataFlowComplete> {
            image_scanner_result: Some(image_scanner_data.clone()),
            control_flow_graph_result: Some(cfg_data.clone()),
            data_flow_result: Some(data_flow_data.clone()),
            ssa_result: None,
            function_call_analysis_result: None,
            marker: PhantomData,
        }
    }

    // Helper to create a model with SsaComplete state
    fn create_ssa_model(
        image_scanner_data: &ImageScannerResult,
        cfg_data: &ControlFlowGraphResult,
        data_flow_data: &DataFlowResult,
        ssa_data: &SsaResult,
    ) -> Model<SsaComplete> {
        Model::<SsaComplete> {
            image_scanner_result: Some(image_scanner_data.clone()),
            control_flow_graph_result: Some(cfg_data.clone()),
            data_flow_result: Some(data_flow_data.clone()),
            ssa_result: Some(ssa_data.clone()),
            function_call_analysis_result: None,
            marker: PhantomData,
        }
    }

    // Helper to create a model with FunctionCallComplete state
    fn create_function_call_model(
        image_scanner_data: &ImageScannerResult,
        cfg_data: &ControlFlowGraphResult,
        data_flow_data: &DataFlowResult,
        ssa_data: &SsaResult,
        function_call_data: &FunctionCallAnalysisResult,
    ) -> Model<FunctionCallComplete> {
        Model::<FunctionCallComplete> {
            image_scanner_result: Some(image_scanner_data.clone()),
            control_flow_graph_result: Some(cfg_data.clone()),
            data_flow_result: Some(data_flow_data.clone()),
            ssa_result: Some(ssa_data.clone()),
            function_call_analysis_result: Some(function_call_data.clone()),
            marker: PhantomData,
        }
    }

    #[test]
    fn test_image_scanner_complete_state() {
        let (_, _, image_scanner_data, _, _, _, _) = create_test_data();
        let model = create_image_scanner_model(&image_scanner_data);

        let scanner_result = model.image_scanner_result();
        assert_eq!(scanner_result.recognized_functions.len(), 0);
        assert_eq!(scanner_result.data_segments.len(), 0);
    }

    #[test]
    fn test_control_flow_graph_complete_state() {
        let (function_id, block_id, image_scanner_data, cfg_data, _, _, _) = create_test_data();
        let model = create_cfg_model(&image_scanner_data, &cfg_data);

        // Test function and block access
        let function_view = model.function(&function_id);
        let block_view = function_view.block(&block_id);

        assert_eq!(block_view.block_id(), block_id);
        assert_eq!(function_view.function_id(), function_id);
        assert_eq!(function_view.stack_size(), 8);
        assert_eq!(function_view.return_block(), Some(block_id));

        // Test block details
        assert_eq!(block_view.low_instructions().len(), 1);
        assert!(matches!(block_view.next(), NextKind::Halt));
    }

    #[test]
    fn test_data_flow_complete_state() {
        let (function_id, block_id, image_scanner_data, cfg_data, data_flow_data, _, _) =
            create_test_data();
        let model = create_data_flow_model(&image_scanner_data, &cfg_data, &data_flow_data);

        // Test data flow access
        let function_view = model.function(&function_id);
        let block_view = function_view.block(&block_id);
        let data_flow = block_view.data_flow();

        assert_eq!(data_flow.live_in.len(), 0);
        assert!(!data_flow.writes_above_r);
    }

    #[test]
    fn test_ssa_complete_state() {
        let (function_id, block_id, image_scanner_data, cfg_data, data_flow_data, ssa_data, _) =
            create_test_data();
        let model = create_ssa_model(&image_scanner_data, &cfg_data, &data_flow_data, &ssa_data);

        // Test SSA access
        let function_view = model.function(&function_id);
        let block_view = function_view.block(&block_id);
        let ssa_info = block_view.ssa();
        let data_flow = block_view.data_flow();

        assert_eq!(ssa_info.phi_functions.len(), 0);
        assert_eq!(ssa_info.instructions.len(), 1);
        assert!(matches!(ssa_info.next, NextKind::Halt));
        assert_eq!(data_flow.defs_in.len(), 0); // Empty in the ssa block's data_flow_block
    }

    #[test]
    fn test_function_call_complete_state() {
        let (
            function_id,
            block_id,
            image_scanner_data,
            cfg_data,
            data_flow_data,
            ssa_data,
            function_call_data,
        ) = create_test_data();

        let model = create_function_call_model(
            &image_scanner_data,
            &cfg_data,
            &data_flow_data,
            &ssa_data,
            &function_call_data,
        );

        // Test call site info access
        let function_view = model.function(&function_id);
        let block_view = function_view.block(&block_id);
        let call_site_info = block_view.call_site_info();

        assert_eq!(call_site_info.return_values_accessed.len(), 0);

        // Test callee info access
        let callee_info = function_view.callee_info();
        assert_eq!(callee_info.parameter_entry_vars.len(), 0);
        assert_eq!(callee_info.return_writes.len(), 0);
    }
}
