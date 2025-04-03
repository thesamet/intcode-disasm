//! Data structures for storing the results of data flow analysis (Reaching Definitions and Liveness).

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::disasm::v2::{
    instructions::{InstructionId, OperandKind},
    model::BlockId,
};

/// Distinguishes the source of a definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DefinitionKind {
    /// Definition comes from a standard instruction write.
    #[default]
    InstructionWrite,
    /// Definition represents a value returned by a function call.
    FunctionReturn { function_addr: OperandKind },
    // Could add others like InitialValue, Parameter, etc. later if needed
}

/// Represents a specific definition site for an Operand.
/// A definition occurs when an instruction writes a value to a memory location
/// represented by the Operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Definition {
    /// The ID of the instruction that performs the write operation,
    /// or the ID of the call instruction (`goto @func`) for return values.
    pub instruction_id: InstructionId,
    /// The location kind (memory or register) being defined.
    pub location: OperandKind,
    /// The ID of the block containing the defining instruction or the call.
    pub block_id: BlockId,
    /// The kind of definition.
    pub kind: DefinitionKind,
}

impl fmt::Display for Definition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind_str = match self.kind {
            DefinitionKind::InstructionWrite => "".to_string(),
            DefinitionKind::FunctionReturn { function_addr } => {
                format!("(ret from func {})", function_addr)
            }
        };
        write!(
            f,
            "Def({}{} in {} at i{})",
            kind_str, self.location, self.block_id, self.instruction_id
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

    /// **Live Variables (IN):** The set of Operands whose current value might be used later in the execution path
    /// starting from the entry of this block.
    pub live_in: HashSet<OperandKind>,

    /// **Live Variables (OUT):** The set of Operands whose current value might be used later in the execution path
    /// starting from the exit(s) of this block.
    pub live_out: HashSet<OperandKind>,

    /// **Generated Definitions (GEN):** Maps Operands defined within this block to the ID of the *last*
    /// instruction within the block that defines them. Definitions here "kill" definitions from `defs_in`.
    /// Key: The `OperandKind` representing the location being defined.
    /// Value: The `InstructionId` of the defining instruction.
    pub gen: HashMap<OperandKind, InstructionId>,

    /// **Used Before Defined (USE):** The set of memory locations that are read (used) within this block *before*
    /// they are written to (defined) within the same block. These operands require a valid definition
    /// to be present in `defs_in`.
    pub use_before_def: HashSet<OperandKind>,
}

impl BlockDataFlow {
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
    pub block_results: HashMap<BlockId, BlockDataFlow>,
}

impl DataFlowResult {
    pub fn new() -> Self {
        Self::default()
    }
}
