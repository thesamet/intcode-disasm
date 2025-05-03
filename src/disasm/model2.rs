use std::collections::{HashMap, HashSet};

use derive_more::AsRef;

use super::v2::{
    self,
    control_flow::{FunctionCall, NextKind, PredecessorKind},
    data_flow::{CallSiteInfo, Definition, OriginationPoint},
    instructions::{InstructionId, InstructionNode, MemoryReference},
    listeners::{function_call_analyzer::CalleeInfo, image_scanner::ImageScannerResult},
    model::{BlockId, FunctionId},
    native::NativeInstruction,
    ssa_form::{PhiFunction, SsaFunction, SsaMemoryReference, VersionRegistry},
    Span,
};

// --- Model States ---

trait ModelState {
    type ModelType;
    type BlockType;
    type FunctionType;
}

struct InitialState;
impl ModelState for InitialState {
    type ModelType = ();
    type BlockType = ();
    type FunctionType = ();
}

struct ImageScannerComplete(ImageScannerResult);
impl ModelState for ImageScannerComplete {
    type ModelType = ImageScannerResult;
    type BlockType = ();
    type FunctionType = ();
}

struct ControlFlowGraphComplete(ControlFlowGraphResult);
impl ModelState for ControlFlowGraphComplete {
    type ModelType = ControlFlowGraphResult;
    type BlockType = ();
    type FunctionType = ();
}

struct DataFlowComplete(DataFlowResult);
impl ModelState for DataFlowComplete {
    type ModelType = DataFlowResult;
    type BlockType = DataFlowBlock;
    type FunctionType = ();
}

struct SsaConversionComplete(SsaResult);
impl ModelState for SsaConversionComplete {
    type ModelType = SsaResult;
    type BlockType = SsaBlock;
    type FunctionType = ();
}

struct FunctionCallAnalysisComplete(FunctionCallAnalysisResult);
impl ModelState for FunctionCallAnalysisComplete {
    type ModelType = FunctionCallAnalysisResult;
    type BlockType = v2::listeners::function_call_analyzer::CallSiteInfo;
    type FunctionType = CalleeInfo;
}

// --- Core Data Structures ---

/// A block in the control flow graph
pub struct Block<S: ModelState> {
    pub id: BlockId,
    // To which function does this block belong?
    pub containing_function_id: FunctionId,
    pub span: Span,
    pub native_instructions: Vec<NativeInstruction>,
    pub low_instructions: Vec<InstructionNode<MemoryReference>>,

    // CFG Information (added by ControlFlowGraphBuilder)
    pub next: NextKind<MemoryReference>,
    pub predecessors: Vec<PredecessorKind<MemoryReference>>,
    data: S::BlockType,
}

struct Function<S: ModelState> {
    function_id: FunctionId,
    entry_block: BlockId,
    stack_size: usize,
    all_block_ids: Vec<BlockId>, // list of blocks in this function

    // The block containing the R -= N; goto [R] sequence.
    // Function may not have a return block. For example, if it reaches the end of the image, is a loop, or it halts.
    return_block: Option<BlockId>,

    blocks: HashMap<BlockId, Block<S>>,
    state_data: S::FunctionType,
}

struct Model<S: ModelState> {
    data: S::ModelType,
}

// --- Extensions and Traits ---

trait ImageScannerResultExtension {
    fn image_data(&self) -> &ImageScannerResult;
}

trait HasFunctions<S: ModelState> {
    fn functions(&self, function_id: &FunctionId) -> &Function<S>;
}

pub trait DataFlowBlockExtension {
    fn data_flow(&self) -> &DataFlowBlock;
}

pub trait SsaBlockExtension<S: ModelState> {
    fn ssa(&self) -> &SsaBlock;
}

pub trait CallSiteBlockExtension<S: ModelState> {
    fn call_site_info(&self) -> &v2::listeners::function_call_analyzer::CallSiteInfo;
}

pub trait FunctionCallAnalysisFunctionExtension<S: ModelState> {
    fn callee_info(&self) -> &CalleeInfo;
}

// --- Implementations ---

impl<S: ModelState> Function<S> {
    fn blocks(&self, block_id: &BlockId) -> &Block<S> {
        self.blocks.get(block_id).unwrap()
    }
}

impl<S: ModelState> DataFlowBlockExtension for Block<S>
where
    S::BlockType: AsRef<DataFlowBlock>,
{
    fn data_flow(&self) -> &DataFlowBlock {
        self.data.as_ref()
    }
}

impl<S: ModelState> SsaBlockExtension<S> for Block<S>
where
    S::BlockType: AsRef<SsaBlock>,
{
    fn ssa(&self) -> &SsaBlock {
        self.data.as_ref()
    }
}

impl<S: ModelState> CallSiteBlockExtension<S> for Block<S>
where
    S::BlockType: AsRef<v2::listeners::function_call_analyzer::CallSiteInfo>,
{
    fn call_site_info(&self) -> &v2::listeners::function_call_analyzer::CallSiteInfo {
        self.data.as_ref()
    }
}

impl AsRef<ImageScannerResult> for ImageScannerResult {
    fn as_ref(&self) -> &ImageScannerResult {
        self
    }
}

impl<S: ModelState> ImageScannerResultExtension for Model<S>
where
    S::ModelType: AsRef<ImageScannerResult>,
{
    fn image_data(&self) -> &ImageScannerResult {
        self.data.as_ref()
    }
}

impl<S: ModelState> HasFunctions<S> for Model<S>
where
    S::ModelType: AsRef<HashMap<FunctionId, Function<S>>>,
{
    fn functions(&self, function_id: &FunctionId) -> &Function<S> {
        self.data.as_ref().get(function_id).unwrap()
    }
}

impl<S: ModelState> FunctionCallAnalysisFunctionExtension<S> for Function<S>
where
    S::FunctionType: AsRef<CalleeInfo>,
{
    fn callee_info(&self) -> &CalleeInfo {
        self.state_data.as_ref()
    }
}

impl AsRef<DataFlowBlock> for DataFlowBlock {
    fn as_ref(&self) -> &DataFlowBlock {
        self
    }
}

impl AsRef<ControlFlowGraphResult> for ControlFlowGraphResult {
    fn as_ref(&self) -> &ControlFlowGraphResult {
        self
    }
}

impl AsRef<SsaBlock> for SsaBlock {
    fn as_ref(&self) -> &SsaBlock {
        self
    }
}

impl AsRef<DataFlowResult> for DataFlowResult {
    fn as_ref(&self) -> &DataFlowResult {
        self
    }
}

impl AsRef<SsaResult> for SsaResult {
    fn as_ref(&self) -> &SsaResult {
        self
    }
}

impl AsRef<CallSiteInfo> for CallSiteInfo {
    fn as_ref(&self) -> &CallSiteInfo {
        self
    }
}

impl AsRef<CalleeInfo> for CalleeInfo {
    fn as_ref(&self) -> &CalleeInfo {
        self
    }
}

// --- Analysis Results ---

#[derive(AsRef)]
pub struct ControlFlowGraphResult {
    #[as_ref]
    image_scanner_result: ImageScannerResult,
    #[as_ref]
    functions: HashMap<FunctionId, Function<ControlFlowGraphComplete>>,
}

#[derive(AsRef)]
pub struct DataFlowResult {
    #[as_ref]
    image_scanner_result: ImageScannerResult,
    #[as_ref]
    functions: HashMap<FunctionId, Function<DataFlowComplete>>,
}

impl DataFlowResult {
    fn new(
        image_scanner_result: ImageScannerResult,
        functions: HashMap<FunctionId, Function<DataFlowComplete>>,
    ) -> Self {
        Self {
            image_scanner_result,
            functions,
        }
    }
}

#[derive(AsRef)]
pub struct SsaResult {
    #[as_ref]
    image_scanner_result: ImageScannerResult,
    #[as_ref]
    pub functions: HashMap<FunctionId, Function<SsaConversionComplete>>,
}

#[derive(AsRef)]
pub struct FunctionCallAnalysisResult {
    #[as_ref]
    image_scanner_result: ImageScannerResult,
    #[as_ref]
    pub functions: HashMap<FunctionId, Function<FunctionCallAnalysisComplete>>,
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
}

/// Represents a basic block in SSA form
#[derive(Debug, Clone, AsRef)]
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
    #[as_ref]
    data_flow_block: DataFlowBlock,
}

// --- Test Function ---

fn test1() {
    let model1 = Model::<InitialState> { data: () };
    let model2 = Model::<ImageScannerComplete> {
        data: ImageScannerResult {
            recognized_functions: vec![],
            data_segments: vec![],
        },
    };
    model2.image_data();
    let model3 = Model::<ControlFlowGraphComplete> {
        data: ControlFlowGraphResult {
            image_scanner_result: ImageScannerResult {
                recognized_functions: vec![],
                data_segments: vec![],
            },
            functions: HashMap::new(),
        },
    };
    model3.image_data();
    let m = model3
        .functions(&FunctionId::from(0))
        .blocks(&BlockId::from(0))
        .containing_function_id;
    let model4 = Model::<DataFlowComplete> {
        data: DataFlowResult {
            image_scanner_result: ImageScannerResult {
                recognized_functions: vec![],
                data_segments: vec![],
            },
            functions: HashMap::from_iter([(
                FunctionId::from(0),
                Function {
                    function_id: FunctionId::from(0),
                    entry_block: BlockId::from(0),
                    stack_size: 0,
                    all_block_ids: vec![],
                    return_block: None,
                    blocks: HashMap::new(),
                    state_data: (),
                },
            )]),
        },
    };

    model4.image_data();
    let m = model4
        .functions(&FunctionId::from(0))
        .blocks(&BlockId::from(0))
        .containing_function_id;
    let z = model4
        .functions(&FunctionId::from(0))
        .blocks(&BlockId::from(0))
        .data_flow();

    let model5 = Model::<SsaConversionComplete> {
        data: SsaResult {
            image_scanner_result: ImageScannerResult {
                recognized_functions: vec![],
                data_segments: vec![],
            },
            functions: HashMap::new(),
        },
    };
    let p = &model5.image_data().data_segments;
    let q = &model5
        .functions(&FunctionId::from(0))
        .blocks(&BlockId::from(0))
        .ssa();
    let d = &model5
        .functions(&FunctionId::from(0))
        .blocks(&BlockId::from(0))
        .data_flow();

    let model6 = Model::<FunctionCallAnalysisComplete> {
        data: FunctionCallAnalysisResult {
            image_scanner_result: ImageScannerResult {
                recognized_functions: vec![],
                data_segments: vec![],
            },
            functions: HashMap::new(),
        },
    };
    let csi = &model6
        .functions(&FunctionId::from(0))
        .blocks(&BlockId::from(0))
        .call_site_info();
    let callee_info = &model6.functions(&FunctionId::from(0)).callee_info();
}
