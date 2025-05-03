use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use super::v2::{
    self,
    control_flow::{FunctionCall, NextKind, PredecessorKind},
    data_flow::{BlockDataFlow, Definition, OriginationPoint},
    instructions::{InstructionId, InstructionNode, MemoryReference},
    listeners::{
        function_call_analyzer::{CallSiteInfo, CalleeInfo},
        image_scanner::ImageScannerResult,
    },
    model::{BlockId, FunctionId},
    native::NativeInstruction,
    ssa_form::{PhiFunction, SsaMemoryReference, VersionRegistry},
    Span,
};

// --- State Types ---

pub trait ModelState {}
struct InitialState {}
struct ImageScannerComplete {}
struct ControlFlowGraphComplete {}
struct DataFlowComplete {}
struct SsaComplete {}
struct FunctionCallComplete {}
impl ModelState for InitialState {}
impl ModelState for ImageScannerComplete {}
impl ModelState for ControlFlowGraphComplete {}
impl ModelState for DataFlowComplete {}
impl ModelState for SsaComplete {}
impl ModelState for FunctionCallComplete {}

/// A block in the control flow graph
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
    S: HasFunctionCallResult,
{
    fn callee_info(&self) -> &CalleeInfo {
        self.model
            .function_call_result()
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

pub struct Model<S: ModelState> {
    image_scanner_result: Option<ImageScannerResult>,
    control_flow_graph_result: Option<ControlFlowGraphResult>,
    data_flow_result: Option<DataFlowResult>,
    ssa_result: Option<SsaResult>,
    function_call_result: Option<FunctionCallAnalysisResult>,
    marker: PhantomData<S>,
}

pub trait HasImageScannerResult {}
impl HasImageScannerResult for ControlFlowGraphComplete {}
impl HasImageScannerResult for DataFlowComplete {}
impl HasImageScannerResult for SsaComplete {}
impl HasImageScannerResult for FunctionCallComplete {}

pub trait HasControlFlowGraphResult {}
impl HasControlFlowGraphResult for ControlFlowGraphComplete {}
impl HasControlFlowGraphResult for DataFlowComplete {}
impl HasControlFlowGraphResult for SsaComplete {}
impl HasControlFlowGraphResult for FunctionCallComplete {}

pub trait HasDataFlowResult {}
impl HasDataFlowResult for DataFlowComplete {}
impl HasDataFlowResult for SsaComplete {}
impl HasDataFlowResult for FunctionCallComplete {}

pub trait HasSsaResult {}
impl HasSsaResult for SsaComplete {}
impl HasSsaResult for FunctionCallComplete {}

pub trait HasFunctionCallResult {}
impl HasFunctionCallResult for FunctionCallComplete {}

impl<S: ModelState> Model<S>
where
    S: HasImageScannerResult,
{
    fn image_scanner_result(&self) -> &ImageScannerResult {
        self.image_scanner_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S>
where
    S: HasControlFlowGraphResult,
{
    fn control_flow_graph_result(&self) -> &ControlFlowGraphResult {
        self.control_flow_graph_result.as_ref().unwrap()
    }

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

impl<S: ModelState> Model<S>
where
    S: HasDataFlowResult,
{
    fn data_flow_result(&self) -> &DataFlowResult {
        self.data_flow_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S>
where
    S: HasSsaResult,
{
    fn ssa_result(&self) -> &SsaResult {
        self.ssa_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S>
where
    S: HasFunctionCallResult,
{
    fn function_call_result(&self) -> &FunctionCallAnalysisResult {
        self.function_call_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S> {
    pub fn new() -> Model<InitialState> {
        Model {
            image_scanner_result: None,
            control_flow_graph_result: None,
            data_flow_result: None,
            ssa_result: None,
            function_call_result: None,
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

impl<'a, S: ModelState> BlockView<'a, S>
where
    S: HasDataFlowResult,
{
    fn data_flow(&self) -> &DataFlowBlock {
        self.model
            .data_flow_result()
            .blocks
            .get(&self.block_id())
            .unwrap_or_else(|| {
                panic!(
                    "Could not find data flow information for block {}",
                    self.block_id()
                )
            })
    }
}

impl<'a, S: ModelState> BlockView<'a, S>
where
    S: HasSsaResult,
{
    fn ssa(&self) -> &SsaBlock {
        self.model
            .ssa_result()
            .blocks
            .get(&self.block_id())
            .unwrap_or_else(|| {
                panic!(
                    "Could not find ssa information for block {}",
                    self.block_id()
                )
            })
    }
}

impl<'a, S: ModelState> BlockView<'a, S>
where
    S: HasFunctionCallResult,
{
    fn call_site_info(&self) -> Option<&CallSiteInfo> {
        self.model
            .function_call_result()
            .blocks
            .get(&self.block_id())
    }
}

// --- Analysis Results ---

pub struct ControlFlowGraphResult {
    functions: HashMap<FunctionId, Function>,
}

pub struct DataFlowResult {
    blocks: HashMap<BlockId, DataFlowBlock>,
}

pub struct SsaResult {
    blocks: HashMap<BlockId, SsaBlock>,
}

pub struct FunctionCallAnalysisResult {
    functions: HashMap<FunctionId, CalleeInfo>,
    blocks: HashMap<BlockId, CallSiteInfo>,
}

// --- Specialized Blocks ---

#[derive(Clone, Debug)]
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
    use super::*;

    #[test]
    fn test1() {
        let model1 = Model::<ImageScannerComplete>::new();
        let model2 = Model::<ImageScannerComplete> {
            image_scanner_result: Some(ImageScannerResult {
                recognized_functions: vec![],
                data_segments: vec![],
            }),
            control_flow_graph_result: None,
            data_flow_result: None,
            ssa_result: None,
            function_call_result: None,
            marker: PhantomData,
        };
        let t = model2.image_scanner_result;
        let model3 = Model::<ControlFlowGraphComplete> {
            image_scanner_result: Some(ImageScannerResult {
                recognized_functions: vec![],
                data_segments: vec![],
            }),
            control_flow_graph_result: Some(ControlFlowGraphResult {
                functions: HashMap::new(),
            }),
            data_flow_result: None,
            ssa_result: None,
            function_call_result: None,
            marker: PhantomData,
        };
        model3.image_scanner_result();
        let function_view = model3.function(&FunctionId::from(0));
        let m = function_view.block(&BlockId::from(0));
        assert!(m.block_id() == BlockId::from(0));

        let model4 = Model::<DataFlowComplete> {
            image_scanner_result: Some(ImageScannerResult {
                recognized_functions: vec![],
                data_segments: vec![],
            }),
            control_flow_graph_result: Some(ControlFlowGraphResult {
                functions: HashMap::new(),
            }),
            data_flow_result: Some(DataFlowResult {
                blocks: HashMap::new(),
            }),
            ssa_result: None,
            function_call_result: None,
            marker: PhantomData,
        };

        model4.image_scanner_result();
        let function_view = model4.function(&FunctionId::from(0));
        let block_data_flow = model4.data_flow_result();
        let m = function_view.function_id();
        let t = function_view.block(&BlockId::from(0));
        let live_in = &t.data_flow().live_in;

        let model5 = Model::<SsaComplete> {
            image_scanner_result: Some(ImageScannerResult {
                recognized_functions: vec![],
                data_segments: vec![],
            }),
            control_flow_graph_result: Some(ControlFlowGraphResult {
                functions: HashMap::new(),
            }),
            data_flow_result: Some(DataFlowResult {
                blocks: HashMap::new(),
            }),
            ssa_result: Some(SsaResult {
                blocks: HashMap::new(),
            }),
            function_call_result: None,
            marker: PhantomData,
        };
        let p = &model5.image_scanner_result().data_segments;
        let q = &model5
            .function(&FunctionId::from(0))
            .block(&BlockId::from(0))
            .ssa();
        let d = &model5
            .function(&FunctionId::from(0))
            .block(&BlockId::from(0))
            .data_flow();

        let model6 = Model::<FunctionCallComplete> {
            image_scanner_result: Some(ImageScannerResult {
                recognized_functions: vec![],
                data_segments: vec![],
            }),
            control_flow_graph_result: Some(ControlFlowGraphResult {
                functions: HashMap::new(),
            }),
            data_flow_result: Some(DataFlowResult {
                blocks: HashMap::new(),
            }),
            ssa_result: Some(SsaResult {
                blocks: HashMap::new(),
            }),
            function_call_result: Some(FunctionCallAnalysisResult {
                functions: HashMap::new(),
                blocks: HashMap::new(),
            }),
            marker: PhantomData,
        };
        let csi = &model6
            .function(&FunctionId::from(0))
            .block(&BlockId::from(0))
            .call_site_info();
        let callee_info = &model6.function(&FunctionId::from(0)).callee_info();
    }
}
