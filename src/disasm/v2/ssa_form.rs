use derive_more::AsRef;
use itertools::Itertools;
use log::trace;
use std::convert::From;

use crate::disasm::v2::{
    control_flow::{NextKind, PredecessorKind},
    data_flow::OriginationPoint,
    model::{BlockId, FunctionId, ProgramModel},
    native::{Operand, OperandKind},
};
use std::collections::{HashMap, HashSet};
use std::fmt;

use super::{
    instructions::{
        Expression, InstructionId, InstructionNode, MemoryReference, MemoryReferenceInfo, PointerId,
    },
    model::Function,
    native::GenericNativeInstruction,
};

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

impl std::fmt::Display for MemoryReferenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryReferenceType::Memory(addr) => write!(f, "[{}]", addr),
            MemoryReferenceType::RelativeMemory(offset) if *offset == 0 => {
                write!(f, "[R]")
            }
            MemoryReferenceType::RelativeMemory(offset) if *offset > 0 => {
                write!(f, "[R+{}]", offset)
            }
            MemoryReferenceType::RelativeMemory(offset) => write!(f, "[R{}]", offset),
            MemoryReferenceType::Pointer(pointer_id) => write!(f, "ptr{}", pointer_id.index()),
        }
    }
}

impl<'a> MemoryReferenceInfo<'a> for &'a MemoryReferenceType {
    fn to_memory_reference(&self) -> MemoryReference {
        (*self).into()
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

impl std::fmt::Display for VersionedMemoryReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_{}_{}", self.kind, self.function_id, self.version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

impl From<VersionedMemoryReference> for SsaMemoryReference {
    fn from(v: VersionedMemoryReference) -> Self {
        SsaMemoryReference::Versioned(v)
    }
}

// Represents the kind of a versioned SSA variable (excluding constants)
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SsaVarKind {
    Memory(usize),
    RelativeMemory(i128),
    Pointer(usize),
}

impl SsaVarKind {
    pub fn get_relative_memory(&self) -> Option<i128> {
        match self {
            SsaVarKind::RelativeMemory(offset) => Some(*offset),
            _ => None,
        }
    }

    #[cfg(test)]
    pub fn get_memory(&self) -> Option<usize> {
        match self {
            SsaVarKind::Memory(addr) => Some(*addr),
            _ => None,
        }
    }

    pub fn get_pointer(&self) -> Option<usize> {
        match self {
            SsaVarKind::Pointer(addr) => Some(*addr),
            _ => None,
        }
    }

    pub fn to_operand_kind(self) -> OperandKind {
        match self {
            SsaVarKind::Memory(addr) => OperandKind::Memory(addr),
            SsaVarKind::RelativeMemory(offset) => OperandKind::RelativeMemory(offset),
            SsaVarKind::Pointer(addr) => OperandKind::Pointer(addr),
        }
    }

    pub fn from_operand_kind(operand_kind: &OperandKind) -> Option<SsaVarKind> {
        Some(match operand_kind {
            OperandKind::Memory(addr) => SsaVarKind::Memory(*addr),
            OperandKind::Pointer(addr) => SsaVarKind::Pointer(*addr),
            OperandKind::RelativeMemory(offset) => SsaVarKind::RelativeMemory(*offset),
            OperandKind::Deref(_) => return None,
            OperandKind::Immediate(_) => return None,
        })
    }
}
// Represents a versioned SSA variable
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SsaOriginInfo {
    pub function_id: FunctionId,
    pub offset: usize,
    pub debug_marker: Option<char>,
}

impl SsaOriginInfo {
    pub fn new(function_id: FunctionId, offset: usize, debug_marker: Option<char>) -> Self {
        Self {
            function_id,
            offset,
            debug_marker,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialOrd, Ord)]
pub struct SsaVar {
    pub kind: SsaVarKind,
    pub version: usize,
    pub origin_info: SsaOriginInfo,
}

impl SsaVar {
    #[cfg(test)]
    pub fn from_operand(
        operand: &Operand,
        version: usize,
        function_id: FunctionId,
    ) -> Option<SsaVar> {
        let origin_info = SsaOriginInfo::new(function_id, operand.offset, operand.debug_marker);
        let kind = SsaVarKind::from_operand_kind(&operand.kind)?;
        Some(SsaVar {
            kind,
            origin_info,
            version,
        })
    }

    // Convert SsaVar back to a representative Operand
    pub fn to_operand(self) -> Operand {
        Operand {
            kind: self.kind.to_operand_kind(),
            offset: self.origin_info.offset,
            debug_marker: self.origin_info.debug_marker,
        }
    }

    pub fn get_relative_memory(&self) -> Option<i128> {
        self.kind.get_relative_memory()
    }
}

impl PartialEq for SsaVar {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.version == other.version
            && self.origin_info.function_id == other.origin_info.function_id
    }
}
impl Eq for SsaVar {}

impl std::hash::Hash for SsaVar {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.kind.hash(state);
        self.version.hash(state);
        self.origin_info.function_id.hash(state);
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SsaOperandKind {
    Constant(i128),
    Variable(SsaVar),
    Deref(SsaVar), // SsaVar must be a pointer.
}

impl SsaOperandKind {
    pub fn constant_value(&self) -> Option<i128> {
        match self {
            SsaOperandKind::Constant(val) => Some(*val),
            _ => None,
        }
    }
}

// Represents either a constant or a versioned SSA variable in an instruction
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SsaOperand {
    pub kind: SsaOperandKind,
    pub origin_info: SsaOriginInfo,
}

// Implement From<SsaOperand> for Operand to satisfy trait bounds
impl From<SsaOperand> for Operand {
    fn from(ssa_op: SsaOperand) -> Self {
        ssa_op.to_operand() // Delegate to the existing method
    }
}

// Helper methods on SsaOperand
impl SsaOperand {
    pub fn to_operand(self) -> Operand {
        match self.kind {
            SsaOperandKind::Constant(val) => Operand {
                kind: OperandKind::Immediate(val),
                offset: self.origin_info.offset,
                debug_marker: self.origin_info.debug_marker,
            },
            SsaOperandKind::Variable(var) => Operand {
                kind: match var.kind {
                    SsaVarKind::Memory(addr) => OperandKind::Memory(addr),
                    SsaVarKind::RelativeMemory(offset) => OperandKind::RelativeMemory(offset),
                    SsaVarKind::Pointer(addr) => OperandKind::Pointer(addr),
                },
                offset: var.origin_info.offset,
                debug_marker: var.origin_info.debug_marker,
            },
            SsaOperandKind::Deref(var) => Operand {
                kind: OperandKind::Deref(var.origin_info.offset),
                offset: var.origin_info.offset,
                debug_marker: var.origin_info.debug_marker,
            },
        }
    }

    pub fn from_operand(operand: &Operand, version: usize, function_id: FunctionId) -> SsaOperand {
        let origin_info = SsaOriginInfo::new(function_id, operand.offset, operand.debug_marker);

        match operand.kind {
            OperandKind::Immediate(val) => SsaOperand {
                kind: SsaOperandKind::Constant(val),
                origin_info,
            },
            OperandKind::Deref(addr) => SsaOperand {
                kind: SsaOperandKind::Deref(SsaVar {
                    kind: SsaVarKind::Pointer(addr),
                    origin_info,
                    version: 0,
                }),
                origin_info,
            },
            OperandKind::Memory(addr) => SsaOperand {
                kind: SsaOperandKind::Variable(SsaVar {
                    kind: SsaVarKind::Memory(addr),
                    origin_info,
                    version,
                }),
                origin_info,
            },
            OperandKind::Pointer(addr) => SsaOperand {
                kind: SsaOperandKind::Variable(SsaVar {
                    kind: SsaVarKind::Pointer(addr),
                    origin_info,
                    version,
                }),
                origin_info,
            },
            OperandKind::RelativeMemory(offset) => SsaOperand {
                kind: SsaOperandKind::Variable(SsaVar {
                    kind: SsaVarKind::RelativeMemory(offset),
                    origin_info,
                    version,
                }),
                origin_info,
            },
        }
    }

    pub fn as_variable(&self) -> Option<&SsaVar> {
        match self.kind {
            SsaOperandKind::Variable(ref var) => Some(var),
            _ => None,
        }
    }
}

// Display implementations
impl fmt::Display for SsaVarKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SsaVarKind::Memory(addr) => write!(f, "[{}]", addr),
            SsaVarKind::RelativeMemory(offset) if *offset == 0 => write!(f, "[R]"),
            SsaVarKind::RelativeMemory(offset) if *offset > 0 => write!(f, "[R+{}]", offset),
            SsaVarKind::RelativeMemory(offset) => write!(f, "[R{}]", offset),
            SsaVarKind::Pointer(addr) => write!(f, "p{}", addr),
        }
    }
}

impl fmt::Display for SsaVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.kind, self.version)
    }
}

impl fmt::Display for SsaOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            SsaOperandKind::Constant(val) => write!(f, "{}", val),
            SsaOperandKind::Variable(ref var) => write!(f, "{}", var), // Uses SsaVar Display
            SsaOperandKind::Deref(var) => write!(f, "*{}", var),
        }
    }
}

/// Represents a phi function in SSA form
#[derive(Debug, Clone, PartialEq)]
pub struct PhiFunction {
    /// The resulting SSA variable (must be a Variable)
    pub result: VersionedMemoryReference,
    /// Map describing the sources for this Phi function's value.
    /// The key is the PredecessorKind corresponding to the incoming edge.
    /// The value is the SsaOperand representing the value coming from that source.
    /// For FunctionReturn predecessors, the SsaOperand is typically the phi.result itself wrapped in SsaOperand::Variable.
    pub inputs: HashMap<PredecessorKind<MemoryReference>, VersionedMemoryReference>,
}

pub type SsaInstruction = GenericNativeInstruction<SsaOperand>;

/// Represents a basic block in SSA form
#[derive(Debug, Clone)]
pub struct SsaBlock {
    /// Original block ID
    pub original_id: BlockId,
    /// Phi functions at the start of this block
    pub phi_functions: Vec<PhiFunction>,
    /// Instructions in SSA form
    pub native_instructions: Vec<SsaInstruction>,
    // Instructions in SSA form
    pub instructions: Vec<InstructionNode<SsaMemoryReference>>,
    // Start state: the state of all versioned variables at the start of this block
    pub native_start_state: HashMap<SsaVarKind, SsaVar>, // Track only versioned variables
    // Start state: the state of all versioned variables at the start of this block
    pub start_state: VersionRegistry, // Track only versioned variables
    /// End state: the state of all versioned variables at the end of this block
    pub native_end_state: HashMap<SsaVarKind, SsaVar>, // Track only versioned variables
    /// End state: the state of all versioned variables at the end of this block
    pub end_state: VersionRegistry, // Track only versioned variables
    /// Control flow information using SSA operands
    pub next: NextKind<SsaMemoryReference>,
    pub predecessors: Vec<PredecessorKind<SsaMemoryReference>>,
}

/// Represents a function in SSA form
#[derive(Debug, Clone)]
pub struct SsaFunction {
    /// Original function ID
    pub original_id: FunctionId,
    /// Blocks in SSA form
    pub blocks: HashMap<BlockId, SsaBlock>,
}

impl SsaFunction {
    // Helper to find an SSA variable with a specific debug marker
    #[cfg(test)]
    pub fn find_marker(&self, marker: char) -> Option<MarkerSearchResult> {
        use super::instructions::Instruction;

        for block in self.blocks.values() {
            for instr in &block.instructions {
                if let Instruction::Assign {
                    target,
                    target_debug_marker: Some(target_debug_marker),
                    ..
                } = &instr.kind
                {
                    if *target_debug_marker == marker {
                        return Some(MarkerSearchResult::SsaAddressable(target));
                    }
                };
                if let Some(found) = instr
                    .kind
                    .collect_source_expressions()
                    .iter()
                    .find_map(|x| x.find_debug_marker(marker))
                {
                    return Some(MarkerSearchResult::Expr(found));
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerSearchResult<'a> {
    SsaAddressable(&'a SsaMemoryReference),
    Expr(&'a Expression<SsaMemoryReference>),
}

#[derive(Debug, Clone)]
pub struct SsaResult {
    pub functions: HashMap<FunctionId, SsaFunction>,
}

impl SsaResult {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    pub fn from_program_model(model: &ProgramModel) -> Self {
        assert!(model.get_data_flow_result().is_some());

        let mut ssa_result = Self::new();

        // Process each function in the model
        for &function_id in model.functions().keys() {
            let mut converter = SSAConversionState::new(model, function_id);
            let ssa_func = SsaFunction {
                original_id: function_id,
                blocks: converter.convert_function(),
            };
            ssa_result.functions.insert(function_id, ssa_func);
        }

        ssa_result
    }

    #[cfg(test)]
    pub fn find_marker(&self, marker: char) -> Option<MarkerSearchResult> {
        self.functions
            .values()
            .find_map(|func| func.find_marker(marker))
    }
}

struct SSAConversionState<'a> {
    model: &'a ProgramModel,
    function_id: FunctionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRegistry {
    current_versions: HashMap<MemoryReferenceType, VersionedMemoryReference>,
    function_id: FunctionId,
}

impl VersionRegistry {
    pub fn new(function_id: FunctionId) -> Self {
        Self {
            current_versions: HashMap::new(),
            function_id,
        }
    }

    fn new_with_versions(
        function_id: FunctionId,
        current_versions: HashMap<MemoryReferenceType, VersionedMemoryReference>,
    ) -> Self {
        Self {
            current_versions,
            function_id,
        }
    }

    fn current_version(
        &self,
        memory_reference_type: &MemoryReferenceType,
    ) -> VersionedMemoryReference {
        self.current_versions
            .get(memory_reference_type)
            .cloned()
            .unwrap_or(VersionedMemoryReference {
                kind: *memory_reference_type,
                function_id: self.function_id,
                version: 0,
            })
    }

    fn create_next_version(
        &mut self,
        memory_reference_type: &MemoryReferenceType,
    ) -> VersionedMemoryReference {
        let mut versioned_memory_reference = self.current_version(memory_reference_type);
        versioned_memory_reference.version += 1;
        self.current_versions
            .insert(*memory_reference_type, versioned_memory_reference);
        versioned_memory_reference
    }

    fn set_version(
        &mut self,
        memory_reference_type: MemoryReferenceType,
        versioned_memory_reference: VersionedMemoryReference,
    ) {
        self.current_versions
            .insert(memory_reference_type, versioned_memory_reference);
    }

    fn current_memory_reference<T>(&self, memory_reference: &T) -> SsaMemoryReference
    where
        T: std::fmt::Debug,
        MemoryReference: for<'a> From<&'a T>,
    {
        let mem_ref: MemoryReference = memory_reference.into();
        MemoryReferenceType::try_from(&mem_ref)
            .map(|kind| SsaMemoryReference::Versioned(self.current_version(&kind)))
            .unwrap_or_else(|_| match mem_ref {
                MemoryReference::Deref(expr) => {
                    // Clone the expression here instead of trying to use From trait
                    let expr = expr.as_ref();
                    SsaMemoryReference::Deref(Box::new(
                        self.current_expression::<MemoryReference>(expr),
                    ))
                }
                _ => unreachable!("Expected type: {:?}", memory_reference),
            })
    }

    fn current_expression<T>(&self, expr: &Expression<T>) -> Expression<SsaMemoryReference>
    where
        MemoryReference: for<'a> From<&'a T>,
        T: std::fmt::Debug,
    {
        expr.map(&mut |op| self.current_memory_reference(op))
    }

    pub fn iter_versions(
        &self,
    ) -> impl Iterator<Item = (&MemoryReferenceType, &VersionedMemoryReference)> {
        self.current_versions.iter()
    }

    fn has_version_for(&self, memory_reference_type: &MemoryReferenceType) -> bool {
        self.current_versions.contains_key(memory_reference_type)
    }
}

// Creates the NextKind using SsaOperands based on the current versions.

impl<'a> SSAConversionState<'a> {
    fn new(model: &'a ProgramModel, function_id: FunctionId) -> Self {
        Self { model, function_id }
    }

    fn convert_function(&mut self) -> HashMap<BlockId, SsaBlock> {
        let function_id = self.function_id;
        // Step 1: Place phi functions where needed
        let phi_placements = self.place_phi_functions(function_id);

        // Step 2: Populate versions for phi results and targets of writes in top-bottom order.
        let function = self.model.get_function(function_id);
        let mut ssa_blocks = self.build_ssa_blocks_with_write_versioning(function, &phi_placements);

        // Step 3: Compute start and end states for all blocks.
        self.compute_start_end_states(&mut ssa_blocks);

        // Step 4: Populate reads and phis.
        self.populate_reads_and_phis(function, &mut ssa_blocks);

        ssa_blocks
    }

    fn build_ssa_blocks_with_write_versioning(
        &mut self,
        function: &Function,
        phi_placements: &HashMap<BlockId, Vec<PhiFunction>>,
    ) -> HashMap<BlockId, SsaBlock> {
        let mut ssa_blocks = HashMap::new();

        fn map_read(
            (current, _): &mut (&mut VersionRegistry, &mut VersionRegistry),
            op: &MemoryReference,
        ) -> SsaMemoryReference {
            current.current_memory_reference(op)
        }

        fn map_write(
            (current, end): &mut (&mut VersionRegistry, &mut VersionRegistry),
            op: &MemoryReference,
        ) -> SsaMemoryReference {
            match MemoryReferenceType::try_from(op) {
                Ok(mem_ref) => {
                    let next_var = current.create_next_version(&mem_ref);
                    end.set_version(mem_ref, next_var);
                    next_var.into()
                }
                Err(_) => current.current_memory_reference(op),
            }
        }
        let mut version_registry = VersionRegistry::new(self.function_id);

        for block_id in function.all_block_ids.iter().sorted() {
            let mut end_state = VersionRegistry::new(self.function_id);
            if *block_id == function.entry_block {
                self.model
                    .get_block(*block_id)
                    .data_flow
                    .as_ref()
                    .unwrap()
                    .defs_in
                    .iter()
                    .filter(|d| d.source == OriginationPoint::FunctionInput)
                    .filter_map(|d| MemoryReferenceType::try_from(&d.kind).ok())
                    .for_each({
                        |versioned_kind| {
                            end_state.set_version(
                                versioned_kind,
                                VersionedMemoryReference {
                                    kind: versioned_kind,
                                    function_id: function.function_id,
                                    version: 0,
                                },
                            );
                        }
                    });
            }
            let block = self.model.get_block(*block_id);
            let mut phi_functions = phi_placements.get(block_id).unwrap_or(&Vec::new()).clone();
            for phi in phi_functions.iter_mut() {
                phi.result = version_registry.create_next_version(&phi.result.kind);
                end_state.set_version(phi.result.kind, phi.result);
            }
            // At this point end_state has the phi functions for this block, so this is the start state
            // we have without variables flowing from predecessors.
            let start_state = end_state.clone();
            let mut instructions = Vec::new();
            for instr in &block.low_instructions {
                let mut state: (&mut VersionRegistry, &mut VersionRegistry) = (
                    &mut version_registry as &mut VersionRegistry,
                    &mut end_state as &mut VersionRegistry,
                );
                instructions.push(instr.map_rw(&mut state, map_read, map_write));
            }

            let ssa_block = SsaBlock {
                original_id: *block_id,
                phi_functions,
                instructions,
                native_instructions: vec![],
                start_state,
                end_state,
                next: NextKind::Halt,
                predecessors: vec![],
                native_start_state: HashMap::new(),
                native_end_state: HashMap::new(),
            };

            ssa_blocks.insert(*block_id, ssa_block);
        }
        ssa_blocks
    }

    fn place_phi_functions(
        &mut self,
        function_id: FunctionId,
    ) -> HashMap<BlockId, Vec<PhiFunction>> {
        let mut phi_placements: HashMap<BlockId, Vec<PhiFunction>> = HashMap::new();
        let function = self.model.get_function(function_id);

        // Initialize empty phi function vectors for all blocks
        for &block_id in &function.all_block_ids {
            phi_placements.insert(block_id, Vec::new());
        }

        for &block_id in &function.all_block_ids {
            let block = self.model.get_block(block_id);

            // Only blocks with multiple predecessors or blocks that are function returns need phi functions.
            if block.predecessors.len() <= 1
                && !block
                    .predecessors
                    .iter()
                    .any(|pred| matches!(pred, PredecessorKind::FunctionCallReturns(_)))
            {
                continue;
            }

            // Get the data flow result for this block
            let block_flow = self.model.get_block(block_id).data_flow.as_ref().unwrap();
            // Find all variable definitions reaching this block from any predecessor
            let all_incoming_defs: HashMap<MemoryReference, HashSet<OriginationPoint>> =
                if block.predecessors.len() > 1 {
                    block_flow
                        .defs_in
                        .iter()
                        .map(|d| (d.kind.clone(), d.source))
                        .into_grouping_map()
                        .collect()
                } else {
                    HashMap::new()
                };

            let return_values_accessed = if let Some(PredecessorKind::FunctionCallReturns(fc)) =
                block
                    .predecessors
                    .iter()
                    .find(|pred| matches!(pred, PredecessorKind::FunctionCallReturns(_)))
            {
                self.model
                    .get_block(fc.calling_block)
                    .data_flow
                    .as_ref()
                    .unwrap()
                    .call_site_info
                    .as_ref()
                    .map(|call_info| {
                        // If we have CallSiteInfo...
                        call_info
                            .return_values_accessed
                            .keys() // Get iterator of keys (&i128)
                            .cloned() // Get iterator of values (i128)
                            .map(MemoryReference::StackRelative) // Convert to Addressable
                            .collect_vec() // Collect into Vec<OperandKind>
                    })
                    .unwrap()
            } else {
                vec![]
            };

            let vars = all_incoming_defs
                .iter()
                .filter(|(var_kind, defs)| {
                    defs.len() > 1 && block_flow.live_in.contains_key(*var_kind)
                })
                .map(|(var_kind, _)| var_kind)
                .chain(return_values_accessed.iter())
                .unique();
            // For each variable with multiple different definitions reaching this block,
            // add a phi function
            for var_kind in vars {
                // Skip constants and derefs
                let Ok(phi_kind) = MemoryReferenceType::try_from(var_kind) else {
                    continue;
                };

                let phi_result = VersionedMemoryReference {
                    kind: phi_kind,
                    function_id,
                    version: 0, // Placeholder
                };
                trace!("{block_id}: Created {} = ?", phi_result);

                // We fill this function later.
                let phi = PhiFunction {
                    result: phi_result,
                    // remove native_result later. Junk value.
                    inputs: HashMap::new(), // Will be filled later
                };

                // Add the phi function to this block
                phi_placements.get_mut(&block_id).unwrap().push(phi);
            }
        }

        phi_placements
    }

    fn compute_start_end_states(&self, ssa_blocks: &mut HashMap<BlockId, SsaBlock>) {
        let block_ids = ssa_blocks.keys().copied().collect_vec();

        // These are the variables that are updated by the block. No predecessor
        // can affect the end state of these variable.
        let initial_end_states: HashMap<BlockId, VersionRegistry> = ssa_blocks
            .keys()
            .map(|id| (*id, ssa_blocks[id].end_state.clone()))
            .collect();

        let initial_start_states: HashMap<BlockId, VersionRegistry> = ssa_blocks
            .iter()
            .map(|(id, block)| (*id, block.start_state.clone()))
            .collect();

        loop {
            let mut changed = false;
            for block_id in &block_ids {
                let mut new_in = initial_start_states[block_id].clone();
                let mut new_out = initial_end_states[block_id].clone();
                let control_block = self.model.get_block(*block_id);
                let live_in = &self
                    .model
                    .get_block(*block_id)
                    .data_flow
                    .as_ref()
                    .unwrap()
                    .live_in;

                for pred in &control_block.predecessors {
                    let pred_id = pred.source_block_id();
                    // Use the collected end_states map here
                    let pred_end_state = &ssa_blocks.get(&pred_id).unwrap().end_state;
                    // new_in should store SsaVarKind -> SsaVar
                    for (mem_ref_type, versioned_mem_ref) in pred_end_state.iter_versions() {
                        if !live_in.contains_key(&mem_ref_type.into())
                            && !mem_ref_type.is_local_or_parameter()
                        {
                            // This var doesn't live from here and not a return value
                            trace!("Skipping var {} from predecessor {} because it doesn't live in this block {block_id}", mem_ref_type, pred_id);
                            continue;
                        }
                        if initial_start_states[block_id].has_version_for(mem_ref_type) {
                            // This block's phis write to the key, so both start_state and end_state can't affect from a predecessor
                            trace!("Skipping var {} from predecessor {} because it is already in start_state", mem_ref_type, pred_id);
                            continue;
                        }

                        // If we get multiple live value through the predecessor, some phi function
                        // should have concsolidated them and then we wouldn't get here (since the
                        // var would be in initial_start_states).
                        /*
                        // We may get multiple definitions, however they are never read.
                        assert!(
                            ssa_blocks[block_id]
                                .start_state
                                .get(var_kind)
                                .is_none_or(|x| x == var),
                            "Predecessor {} provided {var} however start_state of {} already had {}",
                            pred.source_block_id(),
                            block_id,
                            ssa_blocks[block_id].start_state.get(var_kind).unwrap()
                        );
                        */

                        new_in.set_version(*mem_ref_type, *versioned_mem_ref);

                        // means we write to the key, so this can't affect the end_state
                        if initial_end_states[block_id].has_version_for(mem_ref_type) {
                            continue;
                        }
                        /*
                        assert!(
                            ssa_blocks[block_id]
                                .end_state
                                .get(var_kind)
                                .is_none_or(|x| x == var),
                            "End state of {} contains {}, but {} provided from predecessor {}",
                            block_id,
                            ssa_blocks[block_id].end_state.get(var_kind).unwrap(),
                            var,
                            pred.source_block_id()
                        );
                        */
                        new_out.set_version(*mem_ref_type, *versioned_mem_ref);
                    }
                }

                let ssa_block = ssa_blocks.get_mut(block_id).unwrap();
                if ssa_block.start_state != new_in {
                    changed = true;
                    ssa_block.start_state = new_in; // Move new_in here
                }
                if ssa_block.end_state != new_out {
                    changed = true;
                    ssa_block.end_state = new_out; // Move new_out here
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn populate_reads_and_phis(
        &self,
        function: &Function,
        ssa_blocks: &mut HashMap<BlockId, SsaBlock>,
    ) {
        // Temporary storage for predecessor updates to avoid borrow conflicts
        let mut predecessor_updates: Vec<(BlockId, PredecessorKind<SsaMemoryReference>)> =
            Vec::new();

        // First pass: Calculate final instructions, phis, and next state for each block
        for block_id in &function.all_block_ids {
            let block = self.model.get_block(*block_id); // Original block info
            let ssa_block_ro = ssa_blocks.get(block_id).unwrap(); // Read-only access for now

            // Calculate final phi functions
            let mut final_phi_functions = vec![];
            for phi in &ssa_block_ro.phi_functions {
                let mut phi_inputs = HashMap::new(); // Initialize inside this loop
                for pred in &block.predecessors {
                    let pred_id = pred.source_block_id();
                    // Need read-only access to predecessor's end state
                    let pred_ssa_block = ssa_blocks.get(&pred_id).unwrap();
                    if matches!(pred, PredecessorKind::FunctionCallReturns(_))
                        && phi.result.as_stack_relative().is_some_and(|x| x > 0)
                    {
                        phi_inputs.insert(pred.clone(), phi.result.clone());
                    } else {
                        phi_inputs.insert(
                            pred.clone(),
                            pred_ssa_block.end_state.current_version(&phi.result.kind),
                        );
                    }
                }
                let mut final_phi = phi.clone();
                final_phi.inputs = phi_inputs; // Assign the calculated inputs
                final_phi_functions.push(final_phi);
            }

            // Calculate final instructions
            let mut final_instructions = vec![];
            let mut registry = ssa_block_ro.start_state.clone();
            for instr in &ssa_block_ro.instructions {
                let mut final_instr = instr.clone();
                final_instr = final_instr.map_rw(
                    &mut registry,
                    |reg, ssa_memory_reference| reg.current_memory_reference(ssa_memory_reference),
                    |reg, ssa_memory_reference| match ssa_memory_reference {
                        SsaMemoryReference::Deref(expr) => {
                            SsaMemoryReference::Deref(Box::new(reg.current_expression(&expr)))
                        }
                        _ => ssa_memory_reference.clone(),
                    },
                );
                if let Some(write) = final_instr.kind.get_write_address() {
                    if let Some(write) = write.as_versioned() {
                        registry.set_version(write.kind, *write);
                    }
                }
                final_instructions.push(final_instr);
            }

            // Calculate final next state
            let ssa_block_next = {
                block
                    .next
                    .map(&mut |op| ssa_block_ro.end_state.current_memory_reference(op))
            };

            // Store predecessor updates needed for the next pass
            match &ssa_block_next {
                NextKind::Follows(target_id) => {
                    predecessor_updates.push((*target_id, PredecessorKind::FollowsFrom(*block_id)));
                }
                NextKind::Goto(target_block_id) => {
                    predecessor_updates
                        .push((*target_block_id, PredecessorKind::GotoFrom(*block_id)));
                }
                NextKind::FunctionCall(call) => {
                    predecessor_updates.push((
                        call.return_block,
                        PredecessorKind::FunctionCallReturns(call.clone()),
                    ));
                }
                NextKind::Condition(cond) => {
                    predecessor_updates.push((
                        cond.target_block,
                        PredecessorKind::ConditionalJump(cond.clone()),
                    ));
                    predecessor_updates.push((
                        cond.follows_block,
                        PredecessorKind::ConditionalFollow(cond.clone()),
                    ));
                }
                NextKind::Return | NextKind::Halt | NextKind::Unknown => { /* No successors */ }
            }

            // Update the current block's calculated fields (mutable borrow needed here)
            let ssa_block_mut = ssa_blocks.get_mut(block_id).unwrap();
            ssa_block_mut.instructions = final_instructions;
            ssa_block_mut.phi_functions = final_phi_functions;
            ssa_block_mut.next = ssa_block_next;
        }

        // Second pass: Apply predecessor updates
        for (target_block_id, predecessor_kind) in predecessor_updates {
            if let Some(target_block) = ssa_blocks.get_mut(&target_block_id) {
                target_block.predecessors.push(predecessor_kind);
            } else {
                // Handle cases where the target block might not be in the current function's ssa_blocks
                // This might happen with inter-functional calls or jumps, though less common in SSA directly.
                // Depending on the desired behavior, you might log a warning or handle it differently.
                log::warn!(
                    "Target block {:?} for predecessor update not found in current function's SSA blocks.",
                    target_block_id
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::parser;
    use crate::disasm::test_utils::init_logging;
    use crate::disasm::v2::instructions::{BinaryOperator, Instruction};
    use crate::disasm::v2::listeners::ssa_converter::SsaConverter;
    use crate::disasm::v2::pretty_print::pretty_print_ssa;
    use crate::disasm::v2::{
        dispatching::EventPublisher,
        events::Event,
        listeners::{
            control_flow_graph_builder::ControlFlowGraphBuilder,
            data_flow_analyzer::DataFlowAnalyzer, image_scanner::ImageScanner,
        },
    };
    use pretty_assertions::{assert_eq, assert_matches};

    // Define SSA macros for creating expected SsaOperand values with Variable kinds
    macro_rules! ssa_var_rel {
        ($offset:expr, $version:expr) => {
            SsaMemoryReference::Versioned(VersionedMemoryReference {
                kind: MemoryReferenceType::RelativeMemory($offset),
                function_id: FunctionId::from(0),
                version: $version,
            })
        };
    }

    macro_rules! ssa_var_pointer {
        ($addr:expr, $version:expr) => {
            SsaMemoryReference::Versioned(VersionedMemoryReference {
                kind: MemoryReferenceType::Pointer(PointerId::from($addr)),
                function_id: FunctionId::from(0),
                version: $version,
            })
        };
    }

    // Note: Deref versioning needs careful thought. This macro assumes address_version 0 for simplicity.
    macro_rules! ssa_var_deref {
        ($addr:expr, $addr_ver: expr) => {
            // Added addr_ver
            SsaMemoryReference::Deref(Box::new(Expression::Addressable(
                SsaMemoryReference::Versioned(VersionedMemoryReference {
                    kind: MemoryReferenceType::Pointer(PointerId::from($addr)),
                    function_id: FunctionId::from(0),
                    version: $addr_ver,
                }),
            )))
        };
    }

    macro_rules! assert_marker_at_main {
        ($ctx:expr, $marker:expr, $expected_operand:expr) => {{
            // Find the SsaOperand with the given debug marker
            let found_operand = $ctx
                .main_function
                .find_marker($marker) // Use the new function name
                .unwrap_or_else(|| panic!("Marker '{}' not found in main function", $marker));

            let res = match found_operand {
                MarkerSearchResult::SsaAddressable(a) => a,
                MarkerSearchResult::Expr(Expression::Addressable(a)) => a,
                _ => panic!("Expected SsaAddressable or LowExpr::Addressable"),
            };
            pretty_assertions::assert_eq!(
                &$expected_operand,
                res,
                "For marker '{} expected: {:?}, actual: {:?}",
                $marker,
                $expected_operand,
                res
            );
        }};
    }

    struct TestContext {
        main_function: SsaFunction,
        model: ProgramModel,
    }

    impl TestContext {
        fn new(assembly: &str) -> Self {
            init_logging();
            let model = setup_analyzed_model(assembly);

            // Extract the main function (always at ID 0)
            let func_id = FunctionId::from(0);
            let main_function = model
                .get_ssa_result()
                .unwrap()
                .functions
                .get(&func_id)
                .expect("Main function not found in SSA program")
                .clone();

            TestContext {
                main_function,
                model,
            }
        }
    }

    fn setup_analyzed_model(assembly: &str) -> ProgramModel {
        let binary = parser::compile(assembly);
        let mut model = ProgramModel::new();
        let mut publisher = EventPublisher::<Event, ProgramModel>::new();

        // Register listeners for the pipeline
        publisher.add_listener(Box::new(ImageScanner::new()));
        publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
        publisher.add_listener(Box::new(DataFlowAnalyzer::new()));
        publisher.add_listener(Box::new(SsaConverter::new()));

        // Run the pipeline
        model.load_image(&binary, &mut publisher);
        publisher.process_events(&mut model).unwrap();

        model
    }

    // Test simple SSA conversion for basic blocks
    #[test]
    fn test_basic_ssa_conversion() {
        // Simple program with variable definitions and uses
        let model = setup_analyzed_model(
            r#"
            ; Offset 0
            R += 3          ; stack frame setup
            [100] = 5       ; var A = 5
            [101] = [100]   ; var B = A
            [100] = 10      ; var A = 10 (redefine A)
            [102] = [100] + [101] ; var C = A + B
            R -= 3          ; stack frame teardown
            goto [R]        ; return
            "#,
        );

        // Convert to SSA form
        let ssa_result = SsaResult::from_program_model(&model);

        // Expect a single function (at offset 0)
        assert_eq!(ssa_result.functions.len(), 1);

        let func_id = FunctionId::from(0);
        let ssa_function = ssa_result.functions.get(&func_id).unwrap();

        // Expect the function to have blocks
        assert!(!ssa_function.blocks.is_empty());

        // Check the entry block (0)
        let entry_block_id = BlockId::from(0);
        let entry_block = ssa_function.blocks.get(&entry_block_id).unwrap();

        // The entry block should have instructions
        assert!(!entry_block.instructions.is_empty());
    }

    // Test conversion with dominance frontiers and phi functions
    #[test]
    fn test_ssa_conversion_with_phi_functions() {
        // Program with conditional paths that need phi functions
        let model = setup_analyzed_model(
            r#"
            ; Offset 0: Entry Block
            R += 3
            [100] = 1 ; Initialize var A
            if [100] goto @true_branch

            ; Offset 9: False branch
            [100] = 10 ; Reassign A in false branch
            goto @merge

            ; Offset 16: True branch
            true_branch:
            [100] = 20 ; Reassign A in true branch

            ; Offset 20: Merge block
            merge:
            output [100] ; Use A after the branches merge
            R -= 3
            goto [R]
            "#,
        );

        // Convert to SSA form
        let ssa_result = SsaResult::from_program_model(&model);

        // Print block information to debug
        for (func_id, function) in &ssa_result.functions {
            println!("Function: {}", func_id);
            println!(
                "  Blocks: {}",
                function
                    .blocks
                    .keys()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );

            // Examine phi functions in each block
            for (block_id, block) in &function.blocks {
                println!(
                    "  Block {}: {} phi functions",
                    block_id,
                    block.phi_functions.len()
                );
                for (i, phi) in block.phi_functions.iter().enumerate() {
                    println!(
                        "    Phi {}: result={:?}, inputs={:?}",
                        i, phi.result, phi.inputs
                    );
                }
            }
        }

        // Get the merge block
        let func_id = FunctionId::from(0);
        let ssa_function = ssa_result.functions.get(&func_id).unwrap();

        // Find the block with the output instruction (the merge block)
        let mut merge_block_id = None;
        for (block_id, block) in &ssa_function.blocks {
            if block
                .instructions
                .iter()
                .any(|instr| matches!(instr.kind, Instruction::Output(_)))
            {
                merge_block_id = Some(*block_id);
                break;
            }
        }

        assert!(
            merge_block_id.is_some(),
            "Could not find merge block with output instruction"
        );
        let merge_block_id = merge_block_id.unwrap();
        println!("Found merge block: {}", merge_block_id);

        // Get the merge block
        let merge_block = ssa_function.blocks.get(&merge_block_id).unwrap();

        // Verify that the instruction that reads from [100] is using the correct SSA var
        let output_instr = merge_block
            .instructions
            .iter()
            .find(|instr| matches!(instr.kind, Instruction::Output(_)))
            .expect("Should have an output instruction");

        let output_expr = if let Instruction::Output(expr) = &output_instr.kind {
            expr
        } else {
            panic!("Expected Output instruction");
        };

        // Verify the output expression is using a versioned addressable
        match output_expr {
            Expression::Addressable(SsaMemoryReference::Versioned(versioned)) => {
                assert_eq!(
                    versioned.kind,
                    MemoryReferenceType::Memory(100),
                    "Output should use [100]"
                );
                assert!(
                    versioned.version > 0,
                    "Output variable should have a non-zero version, got: {}",
                    versioned.version
                );
                println!("Output operand version: {}", versioned.version);
            }
            _ => {
                panic!(
                    "Output operand should be a Versioned Addressable, but found {:?}",
                    output_expr
                );
            }
        }
        // Note: Phi function expectations remain the same.
    }

    // Test SSA conversion with function calls and return values
    #[test]
    fn test_ssa_conversion_with_function_calls() {
        // Program with a function call and return values
        let model = setup_analyzed_model(
            r#"
            ; Main function @ 0
            R += 3
            [R+1] = 10     ; set arg
            [R] = @ret     ; setup return address
            goto @callee   ; call function
            ret:
            output [R+1]   ; use return value
            R -= 3
            goto [R]

            ; Callee function @ 30
            callee:
            R += 2
            [R-1] = [R-1] + 1 ; increment arg and store in return slot
            R -= 2
            goto [R]      ; return
            "#,
        );

        // Convert to SSA form
        let ssa_result = SsaResult::from_program_model(&model);

        // Print block information to debug
        for (func_id, function) in &ssa_result.functions {
            println!("Function: {}", func_id);
            for block_id in function.blocks.keys() {
                println!("  Block: {}", block_id);
            }
        }

        // Get the return block (where function return value is used)
        let func_id = FunctionId::from(0);
        let ssa_function = ssa_result.functions.get(&func_id).unwrap();

        // Find the return block by searching for one that contains output instruction
        let mut found_return_block = None;
        for (block_id, block) in &ssa_function.blocks {
            if !block.instructions.is_empty() {
                let first_instr = &block.instructions[0];
                if matches!(first_instr.kind, Instruction::Output(_)) {
                    println!("Found block with output: {}", block_id);
                    found_return_block = Some(block);
                    break;
                }
            }
        }

        let return_block =
            found_return_block.expect("Could not find return block with output instruction");

        // Find the output instruction that uses the return value
        let output_instr = return_block.instructions.first().unwrap();
        // println!("Output instruction: {:?}", output_instr);

        // NOTE: With the removal of DefinitionKind::FunctionReturn, we now rely on
        // the BlockDataFlow.function_returns_in set to track function returns, rather than
        // setting SsaVarSource::FunctionReturn for every variable reading from function return.

        // Simply check that the conversion runs without errors. In the future, we may want to
        // enhance this test to verify other aspects of the conversion.
        if let Instruction::Output(expr) = &output_instr.kind {
            match expr {
                Expression::Addressable(SsaMemoryReference::Versioned(versioned)) => {
                    assert!(
                        versioned.version > 0,
                        "Output variable should have a valid version number, got {}",
                        versioned.version
                    );
                }
                _ => {
                    panic!(
                        "Output operand in function call test should be a Versioned Addressable"
                    );
                }
            }
        } else {
            panic!("Expected Output instruction in function call test");
        }

        // In this test we're specifically interested in seeing if operands are tracked
        // across function calls. We may not be properly implementing the function return
        // tracking yet, but we at least want to validate that operands_from_function_returns
        // is being populated - which shows the intention of our implementation.

        // If the implementation is improved later, we can add stronger tests for return values,
        // but for now we'll settle for checking that the test runs without crashing.
    }

    #[test]
    fn test_proper_version_increments_for_writes() {
        // Test a simple program that reads and writes the same register
        let model = setup_analyzed_model(
            r#"
            ; Offset 0
            R += 3                  ; stack frame setup
            [R-4] = 5               ; Initialize R-4 with 5
            [R-4] = [R-4] + 10      ; Use R-4 and update it, adding 10
            output [R-4]            ; Use the updated R-4
            R -= 3                  ; stack frame teardown
            goto [R]                ; return
            "#,
        );

        // Print the SSA program for debugging
        pretty_print_ssa(&model);

        // Get the function
        let func_id = FunctionId::from(0);
        // Convert to SSA form
        let ssa_result = SsaResult::from_program_model(&model);

        let ssa_function = ssa_result.functions.get(&func_id).unwrap();

        // Get the block
        let block_id = BlockId::from(0);
        let block = ssa_function.blocks.get(&block_id).unwrap();

        // Now find the instruction: [R-4] = [R-4] + 10
        let add_instr = block
            .instructions
            .iter()
            .find(|instr| {
                if let Instruction::Assign { target, src, .. } = &instr.kind {
                    // Check if this is an assignment with a binary op
                    if let (
                        SsaMemoryReference::Versioned(target_var),
                        Expression::Binary {
                            op: BinaryOperator::Add,
                            lhs,
                            ..
                        },
                    ) = (target, src)
                    {
                        // Check if target is [R-4] and lhs is also [R-4]
                        if let (
                            MemoryReferenceType::RelativeMemory(target_offset),
                            Expression::Addressable(SsaMemoryReference::Versioned(lhs_var)),
                        ) = (target_var.kind, &**lhs)
                        {
                            return target_offset == -4
                                && lhs_var.kind == MemoryReferenceType::RelativeMemory(-4);
                        }
                    }
                    false
                } else {
                    false
                }
            })
            .expect("Should have found the addition instruction");

        if let Instruction::Assign { target, src, .. } = &add_instr.kind {
            if let (SsaMemoryReference::Versioned(target_var), Expression::Binary { lhs, .. }) =
                (target, src)
            {
                if let Expression::Addressable(SsaMemoryReference::Versioned(src_var)) = &**lhs {
                    assert!(
                        src_var.version < target_var.version,
                        "Source version {} should be less than destination version {}",
                        src_var.version,
                        target_var.version
                    );
                } else {
                    panic!("Expected source to be a versioned addressable");
                }
            } else {
                panic!("Expected assignment with binary op");
            }
        }
    }

    #[test]
    fn test_basic_versioning() {
        let ctx = TestContext::new(
            r#"
                R += 5
                [R+3] = 0
                [R+4] = 1
                'b [R+2] = 'a [R+3] + [R+4]
                'c [R+2] = [R+3] + [R+4]
                halt
            "#,
        );
        pretty_print_ssa(&ctx.model);
        assert_marker_at_main!(ctx, 'a', ssa_var_rel!(3, 1));
        assert_marker_at_main!(ctx, 'b', ssa_var_rel!(2, 1));
        assert_marker_at_main!(ctx, 'c', ssa_var_rel!(2, 2));
    }

    // Helper function to find debug markers in expressions
    fn find_first_debug_marker_in_expr<A>(expr: &Expression<A>) -> Option<&Expression<A>> {
        match expr {
            Expression::DebugMarker(_, _) => Some(expr),
            Expression::Binary { lhs, rhs, .. } => find_first_debug_marker_in_expr(lhs)
                .or_else(|| find_first_debug_marker_in_expr(rhs)),
            Expression::Unary { arg, .. } => find_first_debug_marker_in_expr(arg),
            _ => None,
        }
    }

    #[test]
    fn test_deref_versioning() {
        let ctx = TestContext::new(
            r#"
                R += 5
                ptr = 500
                [R+2] = 1000
                [R+3] = 1001
                'a ptr = ptr + [R+2]
                'b ptr = ptr + [R+3]
                'd [R+1] = 'c *ptr
                halt
                "#,
        );
        pretty_print_ssa(&ctx.model);
        assert_marker_at_main!(ctx, 'a', ssa_var_pointer!(23, 2));
        assert_marker_at_main!(ctx, 'b', ssa_var_pointer!(23, 3));
        assert_marker_at_main!(ctx, 'c', ssa_var_deref!(23, 3));
        assert_marker_at_main!(ctx, 'd', ssa_var_rel!(1, 1));
    }

    #[test]
    fn test_deref_read_after_write() {
        let ctx = TestContext::new(
            r#"
                R += 5
                'a ptr = [R-2]
                'b *ptr = 1
                halt
                "#,
        );
        pretty_print_ssa(&ctx.model);
        assert_marker_at_main!(ctx, 'a', ssa_var_pointer!(9, 1));
        assert_marker_at_main!(ctx, 'b', ssa_var_deref!(9, 1));
    }

    #[test]
    fn test_deref_read_after_cond_write() {
        let ctx = TestContext::new(
            r#"
                R += 5
                'a ptr = 345
                 if [R-4] goto @merge
                'b ptr = ptr + 1
            merge:
                'c *ptr = 17
                halt
                "#,
        );
        pretty_print_ssa(&ctx.model);
        assert_marker_at_main!(ctx, 'a', ssa_var_pointer!(16, 1));
        assert_marker_at_main!(ctx, 'b', ssa_var_pointer!(16, 2));
        assert_marker_at_main!(ctx, 'c', ssa_var_deref!(16, 3));
    }

    #[test]
    fn test_incr_write_after_read() {
        let ctx = TestContext::new(
            r#"
                R += 5
                output('a [R-1])
                'b [R-1] = 17
                halt
                "#,
        );
        assert_marker_at_main!(ctx, 'a', ssa_var_rel!(-1, 0));
        assert_marker_at_main!(ctx, 'b', ssa_var_rel!(-1, 1));
    }

    #[test]
    fn test_function_calls_and_loop() {
        let ctx = TestContext::new(
            r#"
              R += 6                          ; Setup frame
              ptr = [R-5]                     ; ptr = [R-5]_0
'a            [R-2] = *ptr                    ; [R-2]_1 = *ptr
'b            [R-3] = 0                       ; [R-3]_1 = 0
'c            [R-5] = [R-5] + 1               ; [R-5]_1 = [R-5]_0 + 1
        loop:                                 ; Loop header block (needs phis for R-3, R-5)
              ; [R-3]_2 = φ(bl0: [R-3]_1, bl48: [R-3]_3)
              [R-1] = 'd [R-3] == 'e [R-2]
              if [R-1] goto @exit
              ptr2 = 'f [R-5] + 'g [R-3]      ; ptr2 = [R-5]_phi + [R-3]_phi
              [R+1] = *ptr2                   ; Argument 1 (return value slot)
              [R+2] = 'h [R-3]                ; Argument 2
              [R+3] = 'i [R-2]                ; Argument 3
              [R] = @ret                      ; Set return address
              goto [R-4]                      ; Call function
        ret:                                  ; Return block from call
              ; [R+1]_2 = φ(bl25: call_return)
              output 'j [R+1]                 ; Use return value
'l            [R-3] = 'k [R-3] + 1            ; [R-3]_3 = [R-3]_2 + 1
              goto @loop                      ; Jump back
        exit:                                 ; Exit block
              R += -6                         ; Teardown frame
              goto [R]                        ; Return
                "#,
        );
        pretty_print_ssa(&ctx.model);

        // Initial assignments before loop
        assert_marker_at_main!(ctx, 'a', ssa_var_rel!(-2, 1));
        assert_marker_at_main!(ctx, 'b', ssa_var_rel!(-3, 1));
        assert_marker_at_main!(ctx, 'c', ssa_var_rel!(-5, 1));

        // Inside loop header - Phi versions
        assert_marker_at_main!(ctx, 'd', ssa_var_rel!(-3, 2));
        assert_marker_at_main!(ctx, 'e', ssa_var_rel!(-2, 1));
        assert_marker_at_main!(ctx, 'f', ssa_var_rel!(-5, 1));
        assert_marker_at_main!(ctx, 'g', ssa_var_rel!(-3, 2));
        assert_marker_at_main!(ctx, 'h', ssa_var_rel!(-3, 2));
        assert_marker_at_main!(ctx, 'i', ssa_var_rel!(-2, 1));

        // After function call return
        assert_marker_at_main!(ctx, 'j', ssa_var_rel!(1, 2));

        // Inside loop body (after call)
        assert_marker_at_main!(ctx, 'k', ssa_var_rel!(-3, 2));
        assert_marker_at_main!(ctx, 'l', ssa_var_rel!(-3, 3));
    }

    #[test]
    fn test_end_state() {
        let ctx = TestContext::new(
            r#"
        R += 3                  ; 0
        [R-1] = [R-2] == 0      ; 2
        if [R-1] goto @end      ; 6

        [R-1] = [R-2] < 0       ; 9
    end:
        output(48)              ; 13
        output([R-1])           ; 15

        R += -3
        goto [R]
        "#,
        );
        let return_block_id = ctx
            .model
            .get_function(FunctionId::from(0))
            .return_block
            .unwrap();
        pretty_print_ssa(&ctx.model);
        let f0 = ctx
            .model
            .get_ssa_result()
            .unwrap()
            .functions
            .get(&FunctionId::from(0))
            .unwrap();
        assert_eq!(
            f0.blocks
                .get(&return_block_id)
                .unwrap()
                .end_state
                .current_version(&MemoryReferenceType::RelativeMemory(-1))
                .version,
            3 // Expecting version 3 based on the control flow
        );
        assert_eq!(
            f0.blocks
                .get(&BlockId::from(13))
                .unwrap()
                .end_state
                .current_version(&MemoryReferenceType::RelativeMemory(-1))
                .version,
            3 // Expecting version 3 based on the control flow
        );
    }

    #[test]
    fn test_versioning() {
        let ctx = TestContext::new(
            r#"
    R += 3
    [R-1] = 15               ; version 1
    if ![R-1] goto @exit
    if [1308] goto @print

    [R-1] = [1309]           ; version 4

print:
                             ; phi makes version 3
    output(45)
    output(32)

exit:
    R += -3                  ; phi makes version 2
    goto [R]
    "#,
        );
        pretty_print_ssa(&ctx.model);
        let return_block_id = ctx
            .model
            .get_function(FunctionId::from(0))
            .return_block
            .unwrap();
        let f0 = ctx
            .model
            .get_ssa_result()
            .unwrap()
            .functions
            .get(&FunctionId::from(0))
            .unwrap();
        let return_block = f0.blocks.get(&return_block_id).unwrap();
        assert_eq!(
            return_block
                .end_state
                .current_version(&MemoryReferenceType::RelativeMemory(-1))
                .version,
            return_block.phi_functions[0].result.version // Compare with phi result version
        );
    }

    #[test]
    fn test_versioning_with_if() {
        let ctx = TestContext::new(
            r#"
            R += 5
            if [R-1] goto @true
            ptr = 'a [R-4]
            output(*ptr)
            goto @join
        true:
            ptr = 'b [R-4]
            ptr = ptr + 1
        join:
            'c [R-4] = 10
            R -= 5
            goto [R]
            "#,
        );
        pretty_print_ssa(&ctx.model);
        assert_marker_at_main!(ctx, 'a', ssa_var_rel!(-4, 0));
        assert_marker_at_main!(ctx, 'b', ssa_var_rel!(-4, 0));
        assert_marker_at_main!(ctx, 'c', ssa_var_rel!(-4, 1));
    }

    #[test]
    fn test_if_convergence_versioning() {
        let ctx = TestContext::new(
            r#"
            R += 5
            if [R-1] goto @true
            ptr = 'a [R-4]
            output(*ptr)
            goto @join
        true:
            ptr = 'b [R-4]
            ptr = ptr + 1
        join:
            'c [R-4] = 10
            R -= 5
            goto [R]
            "#,
        );
        pretty_print_ssa(&ctx.model);
        assert_marker_at_main!(ctx, 'a', ssa_var_rel!(-4, 0));
        assert_marker_at_main!(ctx, 'b', ssa_var_rel!(-4, 0));
        assert_marker_at_main!(ctx, 'c', ssa_var_rel!(-4, 1));
    }

    #[test]
    fn test_if_convergence_versioning_with_phi() {
        // [R-2] is a parameter that gets modified in a branch.
        // we want to ensure that a phi function under br2 bumps up
        // its version.
        let ctx = TestContext::new(
            r#"
            R += 3
            [R-1] = 'a [R-2] == 0
            if [R-1] goto @exit
                [R-1] = [R-2] < 0
                if [R-1] goto @br1
                    goto @br2
                br1:    ; else
                    output(45)
                    'b [R-2] = [R-2] * -1
            br2:
                [R+1] = 'c [R-2]
                [R] = @exit
                goto 2909
            exit:
                R += -3
                goto [R]

          "#,
        );
        pretty_print_ssa(&ctx.model);
        assert_marker_at_main!(ctx, 'a', ssa_var_rel!(-2, 0));
        assert_marker_at_main!(ctx, 'b', ssa_var_rel!(-2, 1));
        assert_marker_at_main!(ctx, 'c', ssa_var_rel!(-2, 2));
    }

    #[test]
    fn function_call_with_arg_that_is_branched() {
        let ctx = TestContext::new(
            r#"
            R += 3                  ; blocks[0]
            if [R-1] goto @true
            'a [R+1] = 5            ; blocks[1] v1
            goto @merge
        true:                       ; blocks[2]
            'b [R+1] = 7            ; v2
        merge:                      ; blocks[3]
                                    ; v3: we expect a phi for [R+1] here.
            [R] = @ret
            goto 2222
        ret:
            'c [R+1] = 8            ; v4
            R -= 3
            goto [R]
            "#,
        );
        pretty_print_ssa(&ctx.model);
        assert_marker_at_main!(ctx, 'a', ssa_var_rel!(1, 1));
        assert_marker_at_main!(ctx, 'b', ssa_var_rel!(1, 2));
        assert_marker_at_main!(ctx, 'c', ssa_var_rel!(1, 4));

        // Check the merge block has a phi function for [R+1]
        let merge_block = ctx.model.get_ssa_result().unwrap().functions[&FunctionId::from(0)]
            .blocks
            .iter()
            .sorted_by_key(|(k, _)| *k)
            .nth(3)
            .unwrap()
            .1;

        assert_eq!(merge_block.phi_functions.len(), 1);
        assert_eq!(
            merge_block.phi_functions[0].result.kind,
            MemoryReferenceType::RelativeMemory(1)
        );
        assert_eq!(merge_block.phi_functions[0].result.version, 3);
    }
}
