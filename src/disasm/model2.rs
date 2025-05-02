use std::collections::{HashMap, HashSet};

use ambassador::{delegatable_trait, delegate_to_methods, Delegate};
use statum::{machine, state};

use super::v2::{
    control_flow::{Block, FunctionCall, NextKind, PredecessorKind},
    data_flow::{self, CallSiteInfo, Definition, OriginationPoint},
    instructions::{InstructionId, InstructionNode, MemoryReference},
    listeners::image_scanner::{ImageScannerResult, RecognizedFunction},
    model::{BlockId, Function, FunctionId},
    native::NativeInstruction,
    ssa_form::{PhiFunction, SsaInstruction, SsaMemoryReference, VersionRegistry},
    Span,
};

//
// Traits
//

// Scanner traits
trait ImageScannerResultAccess {
    fn recognized_functions(&self) -> &Vec<RecognizedFunction>;
    fn data_segments(&self) -> &Vec<Span>;
}

#[delegatable_trait]
trait FunctionAccess<FunctionType> {
    fn function(&self, function_id: &FunctionId) -> &FunctionType;
}

#[delegatable_trait]
trait BaseFunction {
    fn function_id(&self) -> FunctionId;
    fn entry_block(&self) -> BlockId;
    fn stack_size(&self) -> usize;
    fn all_block_ids(&self) -> Vec<BlockId>; // list of blocks in this function

    // The block containing the R -= N; goto [R] sequence.
    // Function may not have a return block. For example, if it reaches the end of the image, is a loop, or it halts.
    fn return_block(&self) -> Option<BlockId>;
}

trait BlockMap<BlockType> {
    fn block(&self, block_id: &BlockId) -> &BlockType;
}

#[delegatable_trait]
trait BaseBlock {
    fn id(&self) -> BlockId;
    fn containing_function_id(&self) -> FunctionId;
    fn span(&self) -> Span;
    fn native_instructions(&self) -> &Vec<NativeInstruction>;
    fn low_instructions(&self) -> &Vec<InstructionNode<MemoryReference>>;

    fn next(&self) -> NextKind<MemoryReference>;
    fn predecessors(&self) -> &Vec<PredecessorKind<MemoryReference>>;
}

trait ImagingScannerAccess {}

//
// Implementations
//

// Scanner implementations
impl ImageScannerResultAccess for ImageScannerResult {
    fn recognized_functions(&self) -> &Vec<RecognizedFunction> {
        &self.recognized_functions
    }
    fn data_segments(&self) -> &Vec<Span> {
        &self.data_segments
    }
}

// Block implementations
impl BaseBlock for Block {
    fn id(&self) -> BlockId {
        self.id
    }

    fn containing_function_id(&self) -> FunctionId {
        self.containing_function_id
    }

    fn span(&self) -> Span {
        self.span
    }

    fn native_instructions(&self) -> &Vec<NativeInstruction> {
        &self.native_instructions
    }

    fn low_instructions(&self) -> &Vec<InstructionNode<MemoryReference>> {
        &self.low_instructions
    }

    fn next(&self) -> NextKind<MemoryReference> {
        self.next.clone()
    }

    fn predecessors(&self) -> &Vec<PredecessorKind<MemoryReference>> {
        &self.predecessors
    }
}

// Function implementations
impl BaseFunction for Function {
    fn function_id(&self) -> FunctionId {
        self.function_id
    }
    fn entry_block(&self) -> BlockId {
        self.entry_block
    }
    fn stack_size(&self) -> usize {
        self.stack_size
    }
    fn all_block_ids(&self) -> Vec<BlockId> {
        self.all_block_ids.clone()
    }
    fn return_block(&self) -> Option<BlockId> {
        self.return_block
    }
}

impl BlockMap<Block> for Function {
    fn block(&self, block_id: &BlockId) -> &Block {
        self.blocks
            .get(block_id)
            .unwrap_or_else(|| panic!("Block {block_id} not found"))
    }
}

//
// Data structures
//

// Data flow structures
#[derive(Delegate)]
#[delegate(BaseBlock, target = "block")]
struct DataFlowBlock {
    block: Block,
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

trait DataFlowBlockAccess {
    fn defs_in(&self) -> &HashSet<Definition>;
    fn defs_out(&self) -> &HashSet<Definition>;
    fn live_in(&self) -> &HashMap<MemoryReference, HashSet<OriginationPoint>>;
    fn live_out(&self) -> &HashMap<MemoryReference, HashSet<OriginationPoint>>;
    fn gen(&self) -> &HashMap<MemoryReference, (InstructionId, MemoryReference)>;
    fn use_before_def(&self) -> &HashMap<MemoryReference, InstructionId>;
    fn writes_above_r(&self) -> bool;
    fn function_returns_in(&self) -> &HashSet<FunctionCall<MemoryReference>>;
    fn function_returns_out(&self) -> &HashSet<FunctionCall<MemoryReference>>;
    fn call_site_info(&self) -> &Option<CallSiteInfo>;
}

impl DataFlowBlockAccess for DataFlowBlock {
    fn defs_in(&self) -> &HashSet<Definition> {
        &self.defs_in
    }
    fn defs_out(&self) -> &HashSet<Definition> {
        &self.defs_out
    }
    fn live_in(&self) -> &HashMap<MemoryReference, HashSet<OriginationPoint>> {
        &self.live_in
    }
    fn live_out(&self) -> &HashMap<MemoryReference, HashSet<OriginationPoint>> {
        &self.live_out
    }
    fn gen(&self) -> &HashMap<MemoryReference, (InstructionId, MemoryReference)> {
        &self.gen
    }
    fn use_before_def(&self) -> &HashMap<MemoryReference, InstructionId> {
        &self.use_before_def
    }
    fn writes_above_r(&self) -> bool {
        self.writes_above_r
    }
    fn function_returns_in(&self) -> &HashSet<FunctionCall<MemoryReference>> {
        &self.function_returns_in
    }
    fn function_returns_out(&self) -> &HashSet<FunctionCall<MemoryReference>> {
        &self.function_returns_out
    }
    fn call_site_info(&self) -> &Option<CallSiteInfo> {
        &self.call_site_info
    }
}

#[derive(Delegate)]
#[delegate(BaseFunction, target = "function")]
struct DataFlowFunction {
    function: Function,
    data_flow_blocks: HashMap<BlockId, DataFlowBlock>,
}

impl BlockMap<DataFlowBlock> for DataFlowFunction {
    fn block(&self, block_id: &BlockId) -> &DataFlowBlock {
        self.data_flow_blocks
            .get(block_id)
            .unwrap_or_else(|| panic!("Block {block_id} not found"))
    }
}

// Analysis results
pub struct ControlFlowGraphResult {
    functions: HashMap<FunctionId, Function>,
}

impl FunctionAccess<Function> for ControlFlowGraphResult {
    fn function(&self, function_id: &FunctionId) -> &Function {
        self.functions
            .get(function_id)
            .or_else(|| panic!("Function {function_id} not found"))
            .unwrap()
    }
}

pub struct DataFlowResult {
    df_functions: HashMap<FunctionId, DataFlowFunction>,
}

impl DataFlowResult {
    fn new(_cfg: ControlFlowGraphResult, _df: data_flow::DataFlowResult) -> Self {
        Self {
            df_functions: HashMap::new(),
        }
    }
}

impl FunctionAccess<DataFlowFunction> for DataFlowResult {
    fn function(&self, function_id: &FunctionId) -> &DataFlowFunction {
        self.df_functions.get(function_id).unwrap()
    }
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
}

pub struct SsaResult {
    pub functions: HashMap<FunctionId, SsaFunction>,
}

impl FunctionAccess<SsaFunction> for SsaResult {
    fn function(&self, function_id: &FunctionId) -> &SsaFunction {
        self.functions
            .get(function_id)
            .unwrap_or_else(|| panic!("Function {function_id} not found"))
    }
}

trait SsaBlockAccess {
    fn original_id(&self) -> &BlockId;
    fn phi_functions(&self) -> &Vec<PhiFunction>;
    fn instructions(&self) -> &Vec<InstructionNode<SsaMemoryReference>>;
    fn start_state(&self) -> &VersionRegistry;
    fn end_state(&self) -> &VersionRegistry;
    fn next(&self) -> &NextKind<SsaMemoryReference>;
    fn predecessors(&self) -> &Vec<PredecessorKind<SsaMemoryReference>>;
}

impl SsaBlockAccess for SsaBlock {
    fn original_id(&self) -> &BlockId {
        &self.original_id
    }

    fn phi_functions(&self) -> &Vec<PhiFunction> {
        &self.phi_functions
    }

    fn instructions(&self) -> &Vec<InstructionNode<SsaMemoryReference>> {
        &self.instructions
    }

    fn start_state(&self) -> &VersionRegistry {
        &self.start_state
    }

    fn end_state(&self) -> &VersionRegistry {
        &self.end_state
    }

    fn next(&self) -> &NextKind<SsaMemoryReference> {
        &self.next
    }

    fn predecessors(&self) -> &Vec<PredecessorKind<SsaMemoryReference>> {
        &self.predecessors
    }
}

#[derive(Delegate)]
#[delegate(BaseFunction, target = "df_function")]
struct SsaFunction {
    df_function: DataFlowFunction,
    blocks: HashMap<BlockId, SsaBlock>,
}

impl BlockMap<SsaBlock> for SsaFunction {
    fn block(&self, block_id: &BlockId) -> &SsaBlock {
        self.blocks
            .get(block_id)
            .unwrap_or_else(|| panic!("Block {block_id} not found"))
    }
}

// SSA block

//
// Model and state machine
//

#[state]
pub enum ModelState {
    InitialState,
    ImageScanningComplete(ImageScannerResult),
    ControlFlowGraphComplete(ControlFlowGraphResult),
    DataFlowGraphComplete(DataFlowResult),
    SsaConversionComplete(SsaResult),
}

#[machine]
pub struct Model<S: ModelState> {}

#[delegate_to_methods]
#[delegate(FunctionAccess<Function>, target_ref = "get_state_data_unwrap")]
#[delegate(FunctionAccess<DataFlowFunction>, target_ref = "get_state_data_unwrap")]
#[delegate(FunctionAccess<SsaFunction>, target_ref = "get_state_data_unwrap")]
impl<S: ModelState> Model<S> {
    fn get_state_data_unwrap(&self) -> &S::Data {
        self.get_state_data().unwrap()
    }
}

impl<S: ModelState> ImagingScannerAccess for Model<S> {}

//
// Helper functions
//

fn check2(m: Model<ControlFlowGraphComplete>) {
    let f = m.function(&FunctionId::new(4));
    let r = f.block(&BlockId::new(4));
}

fn check3(m: Model<DataFlowGraphComplete>) {
    let t = m.function(&FunctionId::new(4));
    let r = t.block(&BlockId::new(4));
}

fn check4(m: Model<SsaConversionComplete>) {
    let t = m.function(&FunctionId::new(4));
    let r = t.block(&BlockId::new(4));
}
