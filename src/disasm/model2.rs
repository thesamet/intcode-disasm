use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use super::{
    v2::{
        self,
        control_flow::{FunctionCall, NextKind, PredecessorKind},
        data_flow::{BlockDataFlow, Definition, OriginationPoint},
        instructions::{InstructionId, InstructionNode, MemoryReference},
        listeners::{
            function_call_analyzer::{CallSiteInfo, CalleeInfo},
            image_scanner::ImageScannerResult,
        },
        model::FunctionId,
        native::NativeInstruction,
        ssa_form::{PhiFunction, SsaMemoryReference, VersionRegistry},
        BlockId,
    },
    v3::Span,
};

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

/// A block in the control flow graph
#[derive(Clone, Debug)]
pub struct Block {
    pub id: BlockId,
    // To which function does this block belong?
    pub containing_function_id: FunctionId,
    pub span: Span,
    pub native_instructions: Vec<NativeInstruction>,
    pub low_instructions: Vec<InstructionNode<MemoryReference>>,

    // CFG Information (added by ControlFlowGraphBuilder)
    pub next: NextKind<MemoryReference>,
    pub predecessors: Vec<PredecessorKind<MemoryReference>>,
}

#[derive(Clone, Debug)]
pub struct Function {
    pub function_id: FunctionId,
    pub entry_block: BlockId,
    pub stack_size: usize,

    // The block containing the R -= N; goto [R] sequence.
    // Function may not have a return block. For example, if it reaches the end of the image, is a loop, or it halts.
    pub return_block: Option<BlockId>,
    blocks: HashMap<BlockId, Block>,
}

struct FunctionView<'a, S: ModelState> {
    model: &'a Model<S>,
    function: &'a Function,
}

impl<'a, S: ModelState> FunctionView<'a, S> {
    fn new(model: &'a Model<S>, function: &'a Function) -> Self {
        Self { model, function }
    }

    fn function_id(&self) -> FunctionId {
        self.function.function_id
    }

    fn entry_block(&self) -> BlockId {
        self.function.entry_block
    }

    fn stack_size(&self) -> usize {
        self.function.stack_size
    }

    fn all_block_ids(&self) -> impl Iterator<Item = &BlockId> {
        self.function.blocks.keys()
    }

    fn return_block(&self) -> Option<BlockId> {
        self.function.return_block
    }

    fn block(&self, block_id: &BlockId) -> BlockView<S> {
        let block = self
            .function
            .blocks
            .get(block_id)
            .unwrap_or_else(|| panic!("Could not find {block_id} in {}", self.function_id()));
        BlockView::new(self.model, block)
    }
}

impl<'a, S: ModelState> FunctionView<'a, S>
where
    S: HasFunctionCallAnalysisResult,
{
    fn callee_info(&self) -> &CalleeInfo {
        self.model
            .function_call_analysis_result()
            .functions
            .get(&self.function_id())
            .unwrap_or_else(|| {
                panic!(
                    "Could not find callee info for function {}",
                    self.function_id()
                )
            })
    }
}

macro_rules! make_model {
    ($model:ident, $state:ident, { $($field:ty),* }) => {
        paste::paste! {
            #[derive(Clone)]
            pub struct $model<S: $state> {
                $([<$field:snake:lower>]: Option<$field>,)*
                pub marker: std::marker::PhantomData<S>,
            }

            $(
              pub trait [<Has $field>] {}
            )*

            $(
            impl<S: $state> $model<S>
            where
                S: [<Has $field>]
            {
                fn [<$field:snake:lower>](&self) -> &$field {
                    self.[<$field:snake:lower>].as_ref().unwrap()
                }
            })*
        }
    }
}

macro_rules! add_block_view_when {
    ($result_type:ident, $result_var:ident) => {
        paste::paste! {
            add_block_view_when!($result_type, $result_var, [<$result_type Block>]);
        }
    };
    ($result_type:ident, $result_var:ident, $block_type:ty) => {
        paste::paste! {
            impl<'a, S: ModelState> BlockView<'a, S>
            where
                S: [<Has $result_type Result>],
            {
                fn $result_var(&self) -> &$block_type {
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

add_block_view_when!(DataFlow, data_flow);
add_block_view_when!(Ssa, ssa);
add_block_view_when!(FunctionCallAnalysis, call_site_info, CallSiteInfo);

#[derive(Clone, Debug)]
pub struct DataFlowResult {
    blocks: HashMap<BlockId, DataFlowBlock>,
}

make_model!(Model, ModelState, {
    ImageScannerResult,
    ControlFlowGraphResult,
    DataFlowResult,
    SsaResult,
    FunctionCallAnalysisResult
});
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

impl<S: ModelState> Model<S>
where
    S: HasControlFlowGraphResult,
{
    fn function(&self, function_id: &FunctionId) -> FunctionView<'_, S> {
        FunctionView::new(
            self,
            self.control_flow_graph_result()
                .functions
                .get(function_id)
                .unwrap(),
        )
    }
}

impl<S: ModelState> Model<S> {
    pub fn new() -> Model<InitialState> {
        Model {
            image_scanner_result: None,
            control_flow_graph_result: None,
            data_flow_result: None,
            ssa_result: None,
            function_call_analysis_result: None,
            marker: PhantomData,
        }
    }
}

pub struct BlockView<'a, S: ModelState> {
    block: &'a Block,
    model: &'a Model<S>,
}

impl<'a, S: ModelState> BlockView<'a, S> {
    fn new(model: &'a Model<S>, block: &'a Block) -> Self {
        Self { model, block }
    }

    pub fn block_id(&self) -> BlockId {
        self.block.id
    }

    pub fn containing_function_id(&self) -> FunctionId {
        self.block.containing_function_id
    }

    pub fn span(&self) -> &Span {
        &self.block.span
    }

    pub fn native_instructions(&self) -> &[NativeInstruction] {
        &self.block.native_instructions
    }

    pub fn low_instructions(&self) -> &[InstructionNode<MemoryReference>] {
        &self.block.low_instructions
    }

    pub fn next(&self) -> &NextKind<MemoryReference> {
        &self.block.next
    }

    pub fn predecessors(&self) -> &[PredecessorKind<MemoryReference>] {
        &self.block.predecessors
    }
}

// --- Analysis Results ---

#[derive(Clone, Debug)]
pub struct ControlFlowGraphResult {
    functions: HashMap<FunctionId, Function>,
}

#[derive(Clone, Debug)]
pub struct SsaResult {
    blocks: HashMap<BlockId, SsaBlock>,
}

#[derive(Clone, Debug)]
pub struct FunctionCallAnalysisResult {
    functions: HashMap<FunctionId, CalleeInfo>,
    blocks: HashMap<BlockId, CallSiteInfo>,
}

// --- Specialized Blocks ---

#[derive(Clone, Debug, Default)]
pub struct DataFlowBlock {
    /// **Reaching Definitions (IN):** The set of definitions that might reach the entry point of this block.
    defs_in: HashSet<Definition>,

    /// **Reaching Definitions (OUT):** The set of definitions that might reach the exit point(s) of this block.
    defs_out: HashSet<Definition>,

    /// **Live Variables (IN):** The set of Operands whose current value may be used later in any execution path
    /// starting from the entry of this block. Each operand is associated with the points that it is read.
    live_in: HashMap<MemoryReference, HashSet<OriginationPoint>>,

    /// **Live Variables (OUT):** The set of Operands whose current value may be used later in any execution path
    /// starting from the exit(s) of this block.
    live_out: HashMap<MemoryReference, HashSet<OriginationPoint>>,

    /// **Generated Definitions (GEN):** Maps Operands defined within this block to the ID of the *last*
    /// instruction within the block that defines them. Definitions here "kill" definitions from `defs_in`.
    /// Key: The `OperandKind` representing the location being defined.
    /// Value: The `InstructionId` of the defining instruction.
    gen: HashMap<MemoryReference, (InstructionId, MemoryReference)>,

    /// **Used Before Defined (USE):** Maps operand read within this block *before*
    /// they are possibly written to (defined) within the same block, to the ID of the *first* instruction
    /// performing such a read.
    use_before_def: HashMap<MemoryReference, InstructionId>,

    // Instructions in this block that write to [R+n] and thus invalidate all incoming function return values.
    writes_above_r: bool,

    // Function calls for which their return values reach the entry point of this block. This means that this block
    // is either a function return block, or has a predecessor that calls a function and no code in between writes
    // to positive r values.
    function_returns_in: HashSet<FunctionCall<MemoryReference>>,

    // Function call returns that might reach the exit point of this block.
    // This reset to an empty set if the function writes to any positive relative offsets.
    // The value is not affected if this block calls a function - it is added to the function's return block
    // function_returns_in
    function_returns_out: HashSet<FunctionCall<MemoryReference>>,

    // Set only on nodes which have next == NextKind::FunctionCall, and provides information on this callsite.
    call_site_info: Option<CallSiteInfo>,
}

/// Represents a basic block in SSA form
#[derive(Debug, Clone)]
pub struct SsaBlock {
    /// Original block ID
    original_id: BlockId,
    /// Phi functions at the start of this block
    phi_functions: Vec<PhiFunction>,
    // Instructions in SSA form
    instructions: Vec<InstructionNode<SsaMemoryReference>>,
    // Start state: the state of all versioned variables at the start of this block
    start_state: VersionRegistry, // Track only versioned variables
    /// End state: the state of all versioned variables at the end of this block
    end_state: VersionRegistry, // Track only versioned variables
    /// Control flow information using SSA operands
    next: NextKind<SsaMemoryReference>,
    predecessors: Vec<PredecessorKind<SsaMemoryReference>>,
    data_flow_block: DataFlowBlock,
}

// --- Test Function ---

#[cfg(test)]
mod tests {
    use v2::{instructions::Expression, native::NativeInstructionId};

    use super::*;

    // Helper function to create common test data
    // Helper functions for creating test data for different model stages

    fn create_test_ids() -> (FunctionId, BlockId) {
        let function_id = FunctionId::from(0);
        let block_id = BlockId::from(0);
        (function_id, block_id)
    }

    fn create_image_scanner_data() -> ImageScannerResult {
        ImageScannerResult {
            recognized_functions: vec![],
            data_segments: vec![],
        }
    }

    fn create_block(function_id: FunctionId, block_id: BlockId) -> Block {
        Block {
            id: block_id,
            containing_function_id: function_id,
            span: Span { start: 0, end: 10 },
            native_instructions: vec![],
            low_instructions: vec![InstructionNode {
                id: InstructionId::fresh(),
                kind: v2::instructions::Instruction::Halt,
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
            Function {
                function_id,
                entry_block: block_id,
                stack_size: 8,
                return_block: Some(block_id),
                blocks,
            },
        );

        ControlFlowGraphResult {
            functions: function_map,
        }
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
                    kind: v2::instructions::Instruction::Halt,
                }],
                start_state: VersionRegistry::new(function_id),
                end_state: VersionRegistry::new(function_id),
                next: NextKind::Halt,
                predecessors: vec![],
                data_flow_block: DataFlowBlock {
                    defs_in: HashSet::new(),
                    defs_out: HashSet::new(),
                    live_in: HashMap::new(),
                    live_out: HashMap::new(),
                    gen: HashMap::new(),
                    use_before_def: HashMap::new(),
                    writes_above_r: false,
                    function_returns_in: HashSet::new(),
                    function_returns_out: HashSet::new(),
                    call_site_info: None,
                },
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
        function_call_blocks.insert(
            block_id,
            CallSiteInfo {
                calling_block_id: block_id,
                calling_function_id: function_id,
                target_function_id: Some(function_id),
                target_address_var: None,
                argument_writes: HashMap::new(),
                return_reads: HashMap::new(),
                return_block_id: block_id,
                parameter_map: HashMap::new(),
                return_map: HashMap::new(),
            },
        );

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
        assert_eq!(block_view.native_instructions().len(), 0);
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

        assert_eq!(call_site_info.calling_block_id, block_id);
        assert_eq!(call_site_info.calling_function_id, function_id);
        assert_eq!(call_site_info.target_function_id, Some(function_id));

        // Test callee info access
        let callee_info = function_view.callee_info();
        assert_eq!(callee_info.parameter_entry_vars.len(), 0);
        assert_eq!(callee_info.return_writes.len(), 0);
    }
}
