//! ## Static Single Assignment (SSA) Intermediate Representation Types
//!
//! This module defines the core data structures for the Static Single Assignment (SSA)
//! form of the Low-level Intermediate Representation (LIR). SSA is a property of an IR
//! where every variable is assigned exactly once, and every variable is defined before
//! it is used. Variables in the original LIR are "versioned" in SSA to achieve this.
//!
//! This transformation simplifies many kinds of data flow analyses and optimizations.
//!
//! ### Key Concepts:
//!
//! *   **Versioning:** Memory locations (globals, stack slots, pointers) from the LIR
//!     are given version numbers. Each definition of a location creates a new version.
//! *   **Phi Functions:** At points where control flow merges (e.g., after an if/else),
//!     phi functions are used to select the correct version of a variable based on
//!     which path was taken.
//! *   **`SsaMemoryReference`:** The SSA equivalent of `lir::MemoryReference`. It
//!     encapsulates either a `VersionedMemoryReference` (for specific versions of
//!     memory locations) or a `Deref` (where the inner expression uses
//!     `SsaMemoryReference`).
//! *   **`SsaBlock`:** Represents a basic block in SSA form, containing SSA instructions
//!     and phi functions.
//!
//! ### Relationship with LIR Types:
//!
//! The SSA types are derived from their LIR counterparts. The following diagram
//! illustrates the conceptual mapping:
//!
//! ```text
//! +---------------------------------+     Transformation     +-------------------------------------------+
//! |      LIR (Unversioned)          |        Process         |         SSA (Versioned)                   |
//! +---------------------------------+                        +-------------------------------------------+
//! |                                 |                        |                                           |
//! |  MemoryReference                |                        |  SsaMemoryReference                       |
//! |   - Global                      |                        |   - Versioned(VersionedMemoryReference)   |
//! |   - StackRelative               |----(1)---------------->|     - kind: MemoryReferenceType         |
//! |   - Pointer                     |     (Get base type,    |         - Memory (from Global)            |
//! |   - Deref(Expr<MemRef>)         |      add version)      |         - RelativeMemory (from StackRel)  |
//! |                                 |                        |         - Pointer (from Pointer)          |
//! |                                 |                        |       - function_id: FunctionId           |
//! |                                 |                        |       - version: usize                    |
//! |                                 |                        |   - Deref(Expr<SsaMemRef>)                |
//! +---------------------------------+                        +-------------------------------------------+
//! |                                 |                        |                                           |
//! |  Expression<MemoryReference>    |----(2)---------------->|  Expression<SsaMemoryReference>           |
//! |  (Uses MemoryReference)         |     (Map operands)     |  (Uses SsaMemoryReference)                |
//! |                                 |                        |                                           |
//! +---------------------------------+                        +-------------------------------------------+
//! |                                 |                        |                                           |
//! |  InstructionNode<MemoryReference>|----(3)---------------->|  InstructionNode<SsaMemoryReference>      |
//! |  (Contained in LIR Block)       |     (Map operands,     |  (Contained in SsaBlock)                  |
//! |                                 |      add Phi func)     |                                           |
//! +---------------------------------+                        +-------------------------------------------+
//! |                                 |                        |                                           |
//! |  (LIR Basic Block)              |                        |  SsaBlock                                 |
//! |                                 |                        |   - phi_functions: Vec<PhiFunction>       |
//! |                                 |                        |   - instructions: Vec<InstrNode<SsaMemRef>>|
//! |                                 |                        |   - start_state: VersionRegistry          |
//! |                                 |                        |   - end_state: VersionRegistry            |
//! +---------------------------------+                        +-------------------------------------------+
//!
//! Key for Transformation Steps:
//! (1) LIR MemoryReference -> SsaMemoryReference:
//!     - Non-Deref LIR MemRef -> MemoryReferenceType (via TryFrom)
//!     - MemoryReferenceType + version + func_id -> VersionedMemoryReference
//!     - VersionedMemoryReference -> SsaMemoryReference::Versioned (via From)
//!     - LIR Deref(Expr<MemRef>) -> SSA Deref(Expr<SsaMemRef>) (recursive on expression)
//! (2) Expression<MemoryReference> -> Expression<SsaMemoryReference>:
//!     - Uses Expression::map with a function to convert MemRef to SsaMemRef.
//! (3) InstructionNode<MemoryReference> -> InstructionNode<SsaMemoryReference>:
//!     - Uses InstructionNode::map_rw with functions to convert MemRef to SsaMemRef for reads/writes.
//!     - The broader SSA algorithm also inserts Phi functions into SsaBlocks.
//! ```
//!
use std::fmt::Display;

use castaway::LifetimeFree;
use either::Either;

use crate::disasm::v2::instructions::InstructionNode;
use crate::disasm::v3::common::formatting::ContextualPrettyPrint;
use crate::disasm::v3::control_flow::{NextKind, PredecessorKind};
use crate::disasm::v3::id_types::BlockId;
use crate::disasm::v3::lir::{Expression, MemoryReference, MemoryReferenceInfo};
use crate::disasm::v3::model::add_block_view_when;
use crate::disasm::v3::{FunctionId, PointerId};

use super::converter::{PhiFunction, VersionRegistry};

/// Represents a basic block in Static Single Assignment (SSA) form.
///
/// An `SsaBlock` contains instructions that operate on versioned memory references
/// (`SsaMemoryReference`). It also includes phi functions at the beginning of the
/// block to merge different versions of variables from predecessor blocks.
/// The `start_state` and `end_state` track the versions of memory locations
/// at the entry and exit of the block, respectively.
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

/// Defines the fundamental, unversioned type of a memory reference in SSA.
///
/// This enum mirrors the non-`Deref` variants of `lir::MemoryReference`.
/// It serves as the base "kind" for a `VersionedMemoryReference`, which
/// then adds versioning information.
///
/// For example, `lir::MemoryReference::Global(0x100)` would correspond
/// to `MemoryReferenceType::Memory(0x100)`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum VersionableMemoryKind {
    Memory(usize),
    RelativeMemory(i128),
    Pointer(PointerId),
}

impl VersionableMemoryKind {
    pub fn split_kind_or_deref(
        mem_ref: &MemoryReference,
    ) -> Either<VersionableMemoryKind, &Expression<MemoryReference>> {
        match mem_ref {
            MemoryReference::Global(addr) => Either::Left(VersionableMemoryKind::Memory(*addr)),
            MemoryReference::StackRelative(offset) => {
                Either::Left(VersionableMemoryKind::RelativeMemory(*offset))
            }
            MemoryReference::Pointer(id) => Either::Left(VersionableMemoryKind::Pointer(*id)),
            MemoryReference::Deref(expr) => Either::Right(expr),
        }
    }
}

impl TryFrom<&MemoryReference> for VersionableMemoryKind {
    type Error = String;
    fn try_from(value: &MemoryReference) -> Result<Self, Self::Error> {
        match Self::split_kind_or_deref(value) {
            Either::Left(kind) => Ok(kind),
            Either::Right(_) => Err(
                "MemoryReferenceType::try_from: Deref can't be converted to VersionableMemoryKind"
                    .to_string(),
            ),
        }
    }
}

impl From<VersionableMemoryKind> for MemoryReference {
    fn from(value: VersionableMemoryKind) -> Self {
        (&value).to_memory_reference()
    }
}

impl std::fmt::Display for VersionableMemoryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionableMemoryKind::Memory(addr) => write!(f, "[{addr}]"),
            VersionableMemoryKind::RelativeMemory(offset) if *offset == 0 => {
                write!(f, "[R]")
            }
            VersionableMemoryKind::RelativeMemory(offset) if *offset > 0 => {
                write!(f, "[R+{offset}]")
            }
            VersionableMemoryKind::RelativeMemory(offset) => write!(f, "[R{offset}]"),
            VersionableMemoryKind::Pointer(pointer_id) => write!(f, "ptr{}", pointer_id.index()),
        }
    }
}

impl<'a> MemoryReferenceInfo<'a> for &'a VersionableMemoryKind {
    fn to_memory_reference(&self) -> MemoryReference {
        match self {
            VersionableMemoryKind::Memory(addr) => MemoryReference::Global(*addr),
            VersionableMemoryKind::RelativeMemory(offset) => {
                MemoryReference::StackRelative(*offset)
            }
            VersionableMemoryKind::Pointer(id) => MemoryReference::Pointer(*id),
        }
    }

    fn as_deref(&self) -> Option<Expression<MemoryReference>> {
        panic!("Programming error: MemoryReferenceType can't be a deref")
    }

    fn is_deref(&self) -> bool {
        panic!("Programming error: MemoryReferenceType can't be a deref")
    }
}

/// Represents a specific version of a non-dereferenced memory location in SSA form.
///
/// This struct combines a base `MemoryReferenceType` (e.g., a global address or
/// a stack slot) with a `version` number and the `function_id` it belongs to.
/// Each time a memory location is defined (written to), it notionally gets a new,
/// unique `VersionedMemoryReference`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VersionedMemoryReference {
    /// The underlying, unversioned kind of memory location (e.g., global, stack relative).
    pub kind: VersionableMemoryKind,
    /// The ID of the function this versioned reference belongs to.
    pub function_id: FunctionId,
    /// The version number for this specific instance of the memory location.
    pub version: usize,
}

impl VersionedMemoryReference {
    pub fn new(kind: VersionableMemoryKind, function_id: FunctionId, version: usize) -> Self {
        Self {
            kind,
            function_id,
            version,
        }
    }
}

impl AsRef<VersionableMemoryKind> for VersionedMemoryReference {
    fn as_ref(&self) -> &VersionableMemoryKind {
        &self.kind
    }
}

impl std::fmt::Display for VersionedMemoryReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}_{}", self.function_id, self.kind, self.version)
    }
}

/// Represents a memory reference in SSA form, which can be either directly
/// versioned or a dereference of an SSA expression.
///
/// This is the primary type used for memory operands within SSA instructions and
/// expressions. It's the SSA equivalent of `lir::MemoryReference`.
///
/// - `Versioned(VersionedMemoryReference)`: Represents a specific version of a
///   memory location (global, stack, or pointer itself).
/// - `Deref(Box<Expression<SsaMemoryReference>>)`: Represents a memory access
///   through a pointer. The expression yielding the pointer address uses
///   `SsaMemoryReference` for its own operands.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SsaMemoryReference {
    Versioned(VersionedMemoryReference),
    Deref(Box<Expression<SsaMemoryReference>>),
}

unsafe impl LifetimeFree for SsaMemoryReference {}

impl SsaMemoryReference {
    pub fn as_versioned(&self) -> Option<&VersionedMemoryReference> {
        match self {
            SsaMemoryReference::Versioned(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_deref(&self) -> Option<&Expression<SsaMemoryReference>> {
        match self {
            SsaMemoryReference::Deref(expr) => Some(expr),
            _ => None,
        }
    }

    /// Returns an `Either` containing a reference to the inner `VersionedMemoryReference`
    /// if `self` is `Versioned`, or a reference to the inner `Expression<SsaMemoryReference>`
    /// if `self` is `Deref`.
    ///
    /// This is useful for pattern matching or destructuring the `SsaMemoryReference`
    /// without needing a full `match` statement in some contexts, providing a
    /// convenient way to handle both major variants.
    pub fn as_either(&self) -> Either<&VersionedMemoryReference, &Expression<SsaMemoryReference>> {
        match self {
            SsaMemoryReference::Versioned(v) => Either::Left(v),
            SsaMemoryReference::Deref(e) => Either::Right(e),
        }
    }
}

impl Display for SsaMemoryReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.pretty_print())
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
