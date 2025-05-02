//! Data structures for storing the results of data flow analysis (Reaching Definitions and Liveness).

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::disasm::v2::{
    model::BlockId,
    native::{NativeInstructionId, OperandKind},
};

use super::control_flow::FunctionCall;
use super::instructions::{Expression, InstructionId, MemoryReference, MemoryReferenceInfo};
use super::native::Operand;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum NativeOriginationPoint {
    Instruction(NativeInstructionId),
    FunctionInput,
    FunctionOutput,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum OriginationPoint {
    Instruction(InstructionId),
    FunctionInput,
    FunctionOutput,
}

/// Represents a specific definition site for an Operand.
/// A definition occurs when an instruction writes a value to a memory location
/// represented by the Operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NativeDefinition {
    /// The location where the definition originated from (from defs), or where it is read from for liveness.
    /// or the ID of the call instruction (`goto @func`) for return values.
    pub source: NativeOriginationPoint,
    /// The location kind (memory or register) being defined.
    pub kind: OperandKind,
    /// The ID of the block containing the defining instruction or the call.
    pub block_id: BlockId,
}

/// Represents a specific definition site for an Addressable operand.
/// A definition occurs when an instruction writes a value to a memory location
/// represented by the Operand.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Definition {
    /// The location where the definition originated from (from defs), or where it is read from for liveness.
    /// or the ID of the call instruction (`goto @func`) for return values.
    pub source: OriginationPoint,
    /// The location kind (memory or register) being defined.
    pub kind: MemoryReference,
    /// The ID of the block containing the defining instruction or the call.
    pub block_id: BlockId,
}

impl fmt::Display for Definition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Def({:?} in {} at {:?})",
            self.kind, self.block_id, self.source
        )
    }
}

impl fmt::Display for NativeDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Def({} in {} at {:?})",
            self.kind, self.block_id, self.source
        )
    }
}

/// Contains the data flow analysis results for a single basic block.
#[derive(Debug, Clone, Default)]
pub struct BlockDataFlow {
    /// **Reaching Definitions (IN):** The set of definitions that might reach the entry point of this block.
    pub defs_in: HashSet<Definition>,

    /// **Reaching Definitions (OUT):** The set of definitions that might reach the exit point(s) of this block.
    pub defs_out: HashSet<Definition>,

    /// **Live Variables (IN):** The set of Operands whose current value may be used later in any execution path
    /// starting from the entry of this block. Each operand is associated with the points that it is read.
    pub live_in: HashMap<MemoryReference, HashSet<OriginationPoint>>,

    /// **Live Variables (OUT):** The set of Operands whose current value may be used later in any execution path
    /// starting from the exit(s) of this block.
    pub live_out: HashMap<MemoryReference, HashSet<OriginationPoint>>,

    /// **Generated Definitions (GEN):** Maps Operands defined within this block to the ID of the *last*
    /// instruction within the block that defines them. Definitions here "kill" definitions from `defs_in`.
    /// Key: The `OperandKind` representing the location being defined.
    /// Value: The `InstructionId` of the defining instruction.
    pub gen: HashMap<MemoryReference, (InstructionId, MemoryReference)>,

    /// **Used Before Defined (USE):** Maps operand read within this block *before*
    /// they are possibly written to (defined) within the same block, to the ID of the *first* instruction
    /// performing such a read.
    pub use_before_def: HashMap<MemoryReference, InstructionId>,

    // Instructions in this block that write to [R+n] and thus invalidate all incoming function return values.
    pub writes_above_r: bool,

    // Function calls for which their return values reach the entry point of this block. This means that this block
    // is either a function return block, or has a predecessor that calls a function and no code in between writes
    // to positive r values.
    pub function_returns_in: HashSet<FunctionCall<MemoryReference>>,

    // Function call returns that might reach the exit point of this block.
    // This reset to an empty set if the function writes to any positive relative offsets.
    // The value is not affected if this block calls a function - it is added to the function's return block
    // function_returns_in
    pub function_returns_out: HashSet<FunctionCall<MemoryReference>>,

    // Set only on nodes which have next == NextKind::FunctionCall, and provides information on this callsite.
    pub call_site_info: Option<CallSiteInfo>,
}

/// Contains the data flow analysis results for a single basic block.
#[derive(Debug, Clone, Default)]
pub struct BlockNativeDataFlow {
    /// **Reaching Definitions (IN):** The set of definitions that might reach the entry point of this block.
    pub defs_in: HashSet<NativeDefinition>,

    /// **Reaching Definitions (OUT):** The set of definitions that might reach the exit point(s) of this block.
    pub defs_out: HashSet<NativeDefinition>,

    /// **Live Variables (IN):** The set of Operands whose current value may be used later in any execution path
    /// starting from the entry of this block. Each operand is associated with the points that it is read.
    pub live_in: HashMap<OperandKind, HashSet<NativeOriginationPoint>>,

    /// **Live Variables (OUT):** The set of Operands whose current value may be used later in any execution path
    /// starting from the exit(s) of this block.
    pub live_out: HashMap<OperandKind, HashSet<NativeOriginationPoint>>,

    /// **Generated Definitions (GEN):** Maps Operands defined within this block to the ID of the *last*
    /// instruction within the block that defines them. Definitions here "kill" definitions from `defs_in`.
    /// Key: The `OperandKind` representing the location being defined.
    /// Value: The `InstructionId` of the defining instruction.
    pub gen: HashMap<OperandKind, (NativeInstructionId, Operand)>,

    /// **Used Before Defined (USE):** Maps operand read within this block *before*
    /// they are possibly written to (defined) within the same block, to the ID of the *first* instruction
    /// performing such a read.
    pub use_before_def: HashMap<OperandKind, NativeInstructionId>,

    // Instructions in this block that write to [R+n] and thus invalidate all incoming function return values.
    pub writes_above_r: bool,

    // Set only on nodes which have next == NextKind::FunctionCall, and provides information on this callsite.
    pub call_site_info: Option<NativeCallSiteInfo>,
}

/// Contains flow data about call sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSiteInfo {
    // The set of positive offsets `n` identifying return value locations `[R+n]`
    // that are read by subsequent blocks having access to the function's return state.
    pub return_values_accessed: HashMap<i128, InstructionId>,
}

impl CallSiteInfo {
    pub fn new() -> Self {
        CallSiteInfo {
            return_values_accessed: HashMap::new(),
        }
    }
}

/// Contains flow data about call sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCallSiteInfo {
    // The set of positive offsets `n` identifying return value locations `[R+n]`
    // that are read by subsequent blocks having access to the function's return state.
    pub return_values_accessed: HashMap<i128, NativeInstructionId>,
}

impl NativeCallSiteInfo {
    pub fn new() -> Self {
        NativeCallSiteInfo {
            return_values_accessed: HashMap::new(),
        }
    }
}

impl BlockDataFlow {
    /// Creates a new, empty `BlockDataFlow` record.
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlockNativeDataFlow {
    /// Creates a new, empty `BlockDataFlow` record.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Holds the complete data flow analysis results for all analyzed blocks.
/// This structure is intended to be stored within the `ProgramModel`.
#[derive(Debug, Clone, Default)]
pub struct DataFlowResult {
    /// Maps each analyzed Block ID directly to its detailed data flow information.
    pub block_results: HashMap<BlockId, BlockNativeDataFlow>,
    pub low_block_results: HashMap<BlockId, BlockDataFlow>,
}

impl DataFlowResult {
    pub fn new() -> Self {
        Self::default()
    }
}
