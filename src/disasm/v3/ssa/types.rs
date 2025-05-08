use crate::disasm::v2::instructions::InstructionNode;
use crate::disasm::v3::control_flow::{NextKind, PredecessorKind};
use crate::disasm::v3::id_types::BlockId;
use crate::disasm::v3::lir::{Expression, MemoryReference, MemoryReferenceInfo};
use crate::disasm::v3::model::add_block_view_when;
use crate::disasm::v3::{FunctionId, PointerId};

use super::converter::{PhiFunction, VersionRegistry};

/// Represents a basic block in SSA form
#[derive(Debug, Clone)]
pub struct SsaBlock {
    /// Original block ID
    pub original_id: BlockId,
    /// Phi functions at the start of this block
    pub phi_functions: Vec<PhiFunction>,
    // Instructions in SSA form
    pub instructions: Vec<InstructionNode<SsaMemoryReference>>,
    // Start state: the state of all versioned variables at the start of this block
    pub start_state: VersionRegistry, // Track only versioned variables
    /// End state: the state of all versioned variables at the end of this block
    pub end_state: VersionRegistry, // Track only versioned variables
    /// Control flow information using SSA operands
    pub next: NextKind<SsaMemoryReference>,
    pub predecessors: Vec<PredecessorKind<SsaMemoryReference>>,
}
add_block_view_when!(Ssa, ssa);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum MemoryReferenceType {
    Memory(usize),
    RelativeMemory(i128),
    Pointer(PointerId),
}

impl MemoryReferenceType {
    /// Converts an `Addressable` to a `VersionedAddressableKind`.
    ///
    /// This function is used during SSA conversion to transform addressable expressions into their versioned counterparts.
    ///
    /// # Arguments
    /// * `addressable` - A reference to an `Addressable` to convert
    ///
    /// # Returns
    /// * `Some(VersionedAddressableKind)` - If the addressable is Memory, RelativeMemory, or Pointer
    /// * `None` - If the addressable is a Deref
    #[deprecated = "Use TryFrom<MemoryReference> instead"]
    pub fn try_from_memory_reference(addressable: &MemoryReference) -> Option<Self> {
        addressable.try_into().ok()
    }
}

impl TryFrom<&MemoryReference> for MemoryReferenceType {
    type Error = String;
    fn try_from(value: &MemoryReference) -> Result<Self, Self::Error> {
        match value {
            MemoryReference::Global(addr) => Ok(MemoryReferenceType::Memory(*addr)),
            MemoryReference::StackRelative(offset) => {
                Ok(MemoryReferenceType::RelativeMemory(*offset))
            }
            MemoryReference::Pointer(id) => Ok(MemoryReferenceType::Pointer(*id)),
            MemoryReference::Deref(_) => {
                Err("MemoryReferenceType::try_from_addressable: Deref not supported".to_string())
            }
        }
    }
}

impl From<MemoryReferenceType> for MemoryReference {
    fn from(value: MemoryReferenceType) -> Self {
        (&value).to_memory_reference()
    }
}

impl std::fmt::Display for MemoryReferenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryReferenceType::Memory(addr) => write!(f, "[{addr}]"),
            MemoryReferenceType::RelativeMemory(offset) if *offset == 0 => {
                write!(f, "[R]")
            }
            MemoryReferenceType::RelativeMemory(offset) if *offset > 0 => {
                write!(f, "[R+{offset}]")
            }
            MemoryReferenceType::RelativeMemory(offset) => write!(f, "[R{offset}]"),
            MemoryReferenceType::Pointer(pointer_id) => write!(f, "ptr{}", pointer_id.index()),
        }
    }
}

impl<'a> MemoryReferenceInfo<'a> for &'a MemoryReferenceType {
    fn to_memory_reference(&self) -> MemoryReference {
        match self {
            MemoryReferenceType::Memory(addr) => MemoryReference::Global(*addr),
            MemoryReferenceType::RelativeMemory(offset) => MemoryReference::StackRelative(*offset),
            MemoryReferenceType::Pointer(id) => MemoryReference::Pointer(*id),
        }
    }

    fn as_deref(&self) -> Option<Expression<MemoryReference>> {
        panic!("Programming error: MemoryReferenceType can't be a deref")
    }

    fn is_deref(&self) -> bool {
        panic!("Programming error: MemoryReferenceType can't be a deref")
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VersionedMemoryReference {
    pub kind: MemoryReferenceType,
    pub function_id: FunctionId,
    pub version: usize,
}

impl VersionedMemoryReference {
    pub fn new(kind: MemoryReferenceType, function_id: FunctionId, version: usize) -> Self {
        Self {
            kind,
            function_id,
            version,
        }
    }
}

impl AsRef<MemoryReferenceType> for VersionedMemoryReference {
    fn as_ref(&self) -> &MemoryReferenceType {
        &self.kind
    }
}

impl std::fmt::Display for VersionedMemoryReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_{}_{}", self.kind, self.function_id, self.version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SsaMemoryReference {
    Versioned(VersionedMemoryReference),
    Deref(Box<Expression<SsaMemoryReference>>),
}

impl SsaMemoryReference {
    pub fn as_versioned(&self) -> Option<&VersionedMemoryReference> {
        match self {
            SsaMemoryReference::Versioned(v) => Some(v),
            _ => None,
        }
    }
}

impl MemoryReferenceInfo<'_> for VersionedMemoryReference {
    fn to_memory_reference(&self) -> MemoryReference {
        self.kind.into()
    }
}

impl From<VersionedMemoryReference> for SsaMemoryReference {
    fn from(v: VersionedMemoryReference) -> Self {
        SsaMemoryReference::Versioned(v)
    }
}
