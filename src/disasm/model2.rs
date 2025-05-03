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
    ssa_form::{PhiFunction, SsaMemoryReference, VersionRegistry},
    Span,
};

// --- State Types ---

/// Defines the family of types associated with a particular analysis state
pub trait StateTypes {
    /// The type containing model-level data for this state
    type ModelData;

    /// The type containing block-level data for this state
    type BlockData;

    /// The type containing function-level data for this state
    type FunctionData;
}

/// A marker trait for model states
pub trait ModelState: StateTypes {}

// Define concrete state types
pub struct InitialTypes;
impl StateTypes for InitialTypes {
    type ModelData = ();
    type BlockData = ();
    type FunctionData = ();
}
impl ModelState for InitialTypes {}

pub struct ImageScannerTypes;
impl StateTypes for ImageScannerTypes {
    type ModelData = ImageScannerResult;
    type BlockData = ();
    type FunctionData = ();
}
impl ModelState for ImageScannerTypes {}

pub struct ControlFlowTypes;
impl StateTypes for ControlFlowTypes {
    type ModelData = ControlFlowGraphResult;
    type BlockData = ();
    type FunctionData = ();
}
impl ModelState for ControlFlowTypes {}

pub struct DataFlowTypes;
impl StateTypes for DataFlowTypes {
    type ModelData = DataFlowResult;
    type BlockData = DataFlowBlock;
    type FunctionData = ();
}
impl ModelState for DataFlowTypes {}

pub struct SsaTypes;
impl StateTypes for SsaTypes {
    type ModelData = SsaResult;
    type BlockData = SsaBlock;
    type FunctionData = ();
}
impl ModelState for SsaTypes {}

pub struct FunctionCallTypes;
impl StateTypes for FunctionCallTypes {
    type ModelData = FunctionCallAnalysisResult;
    type BlockData = v2::listeners::function_call_analyzer::CallSiteInfo;
    type FunctionData = CalleeInfo;
}
impl ModelState for FunctionCallTypes {}

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
    data: S::BlockData,
}

pub struct Function<S: ModelState> {
    pub function_id: FunctionId,
    pub entry_block: BlockId,
    pub stack_size: usize,
    pub all_block_ids: Vec<BlockId>, // list of blocks in this function

    // The block containing the R -= N; goto [R] sequence.
    // Function may not have a return block. For example, if it reaches the end of the image, is a loop, or it halts.
    pub return_block: Option<BlockId>,

    blocks: HashMap<BlockId, Block<S>>,
    state_data: S::FunctionData,
}

struct Model<S: ModelState> {
    data: S::ModelData,
}

// --- Extensions and Traits ---

pub trait ImageDataAccess<S: ModelState> {
    fn image_data(&self) -> &ImageScannerResult;
}

pub trait HasFunctions<S: ModelState> {
    fn functions(&self, function_id: &FunctionId) -> &Function<S>;
}

pub trait DataFlowAccess {
    fn data_flow(&self) -> &DataFlowBlock;
}

pub trait SsaAccess {
    fn ssa(&self) -> &SsaBlock;
}

pub trait CallSiteAccess {
    fn call_site_info(&self) -> &v2::listeners::function_call_analyzer::CallSiteInfo;
}

pub trait CalleeAccess {
    fn callee_info(&self) -> &CalleeInfo;
}

// --- Implementations ---

impl<S: ModelState> Function<S> {
    fn blocks(&self, block_id: &BlockId) -> &Block<S> {
        self.blocks.get(block_id).unwrap()
    }
}

impl<S: ModelState> DataFlowAccess for Block<S>
where
    S::BlockData: AsRef<DataFlowBlock>,
{
    fn data_flow(&self) -> &DataFlowBlock {
        self.data.as_ref()
    }
}

impl<S: ModelState> SsaAccess for Block<S>
where
    S::BlockData: AsRef<SsaBlock>,
{
    fn ssa(&self) -> &SsaBlock {
        self.data.as_ref()
    }
}

impl<S: ModelState> CallSiteAccess for Block<S>
where
    S::BlockData: AsRef<v2::listeners::function_call_analyzer::CallSiteInfo>,
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

impl<S: ModelState> ImageDataAccess<S> for Model<S>
where
    S::ModelData: AsRef<ImageScannerResult>,
{
    fn image_data(&self) -> &ImageScannerResult {
        self.data.as_ref()
    }
}

impl<S: ModelState> HasFunctions<S> for Model<S>
where
    S::ModelData: AsRef<HashMap<FunctionId, Function<S>>>,
{
    fn functions(&self, function_id: &FunctionId) -> &Function<S> {
        self.data.as_ref().get(function_id).unwrap()
    }
}

impl<S: ModelState> CalleeAccess for Function<S>
where
    S::FunctionData: AsRef<CalleeInfo>,
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
    functions: HashMap<FunctionId, Function<ControlFlowTypes>>,
}

#[derive(AsRef)]
pub struct DataFlowResult {
    #[as_ref]
    image_scanner_result: ImageScannerResult,
    #[as_ref]
    functions: HashMap<FunctionId, Function<DataFlowTypes>>,
}

impl DataFlowResult {
    fn new(
        image_scanner_result: ImageScannerResult,
        functions: HashMap<FunctionId, Function<DataFlowTypes>>,
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
    pub functions: HashMap<FunctionId, Function<SsaTypes>>,
}

#[derive(AsRef)]
pub struct FunctionCallAnalysisResult {
    #[as_ref]
    image_scanner_result: ImageScannerResult,
    #[as_ref]
    pub functions: HashMap<FunctionId, Function<FunctionCallTypes>>,
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
    let model1 = Model::<InitialTypes> { data: () };
    let model2 = Model::<ImageScannerTypes> {
        data: ImageScannerResult {
            recognized_functions: vec![],
            data_segments: vec![],
        },
    };
    model2.image_data();
    let model3 = Model::<ControlFlowTypes> {
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
    assert!(m == FunctionId::from(0));
    let model4 = Model::<DataFlowTypes> {
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

    let model5 = Model::<SsaTypes> {
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

    let model6 = Model::<FunctionCallTypes> {
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
