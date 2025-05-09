use crate::disasm::v3::model::{DataFlowComplete, Model, SsaComplete};
use crate::disasm::Error;

/// Converts the control flow graph to SSA form
pub struct SsaConverter {
    model: Model<DataFlowComplete>,
}

impl SsaConverter {
    pub fn new(model: Model<DataFlowComplete>) -> Self {
        Self { model }
    }

    pub fn run(model: Model<DataFlowComplete>) -> Result<Model<SsaComplete>, Error> {
        let converter = Self::new(model);
        converter.convert()
    }

    fn convert(self) -> Result<Model<SsaComplete>, Error> {
        // Create the SSA result
        Ok(SsaResult::from_program_model(self.model))
    }
}

use itertools::Itertools;
use log::trace;
use std::convert::From;

use crate::disasm;
use crate::disasm::v3::control_flow::PredecessorKind::FunctionCallReturns;
use crate::disasm::v3::data_flow::OriginationPoint;
use crate::disasm::v3::ssa::types::MemoryReferenceType;
use crate::disasm::v3::ssa::{SsaMemoryReference, VersionedMemoryReference};
use crate::disasm::{
    v2::model::{BlockId, FunctionId},
    v3::{
        self,
        control_flow::FunctionView,
        lir::{Expression, MemoryReference, MemoryReferenceInfo},
    },
};

use std::collections::{HashMap, HashSet};
pub use v3::ssa::SsaBlock;

use crate::disasm::v3::lir::ReadAddressExtractor; // Import the trait
impl ReadAddressExtractor for SsaMemoryReference {
    fn extract_read_addresses(&self) -> Vec<&Self> {
        match self {
            SsaMemoryReference::Deref(expr) => expr.collect_read_addresses(),
            SsaMemoryReference::Versioned(_) => Vec::new(),
        }
    }
}

/// Represents a phi function in SSA form
#[derive(Debug, Clone, PartialEq)]
pub struct PhiFunction {
    /// The resulting SSA variable (must be a Variable)
    pub result: VersionedMemoryReference,
    /// Map describing the sources for this Phi function's value.
    /// The key is the v3 PredecessorKind corresponding to the incoming edge, but with SsaMemoryReference.
    /// The value is the VersionedMemoryReference representing the value coming from that source.
    pub inputs: HashMap<
        disasm::v3::control_flow::PredecessorKind<SsaMemoryReference>,
        VersionedMemoryReference,
    >,
}

/// Represents a function in SSA form
#[derive(Debug, Clone)]
pub struct SsaFunction {
    /// Original function ID
    pub original_id: FunctionId,
    /// Blocks in SSA form
    pub blocks: HashMap<BlockId, SsaBlock>,
}

// Removed duplicate impl block for FunctionView<SsaComplete> with find_marker

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerSearchResult<'a> {
    SsaAddressable(&'a SsaMemoryReference),
    Expr(&'a Expression<SsaMemoryReference>),
}

#[derive(Debug, Clone)]
pub struct SsaResult {
    pub functions: HashMap<FunctionId, SsaFunction>,
}

impl Default for SsaResult {
    fn default() -> Self {
        Self::new()
    }
}

impl SsaResult {
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    // Modified to accept v3 Model<DataFlowComplete>
    pub fn from_program_model(model: Model<DataFlowComplete>) -> Model<SsaComplete> {
        // let mut ssa_result = Self::new(); // Removed as SsaResult is built implicitly

        let mut blocks = HashMap::new();
        // Process each function using the v3 model's function iterator
        for (_, function_view) in model.functions() {
            // Convert v3 FunctionId to v2 FunctionId for SsaResult key and internal use
            // Assuming a simple usize conversion is okay for now.
            // TODO: Revisit ID conversions if they become more complex.

            // Pass the v3 model and the specific function view to the converter
            let mut converter = SSAConversionState::new(function_view);
            blocks.extend(converter.convert_function());
        }
        model.with_ssa_result(v3::ssa::SsaResult { blocks })
    }
}

// Modified to hold v3 model and function view
struct SSAConversionState<'a> {
    function: FunctionView<'a, DataFlowComplete>,
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

    pub fn current_version(
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

    /// Converts a MemoryReference (or similar) into an SsaMemoryReference using the *current* state.
    /// Used during the initial pass (build_ssa_blocks...).
    fn convert_to_ssa_memory_reference<T>(&self, memory_reference: &T) -> SsaMemoryReference
    where
        T: std::fmt::Debug,
        MemoryReference: for<'a> From<&'a T>, // T can be converted to MemoryReference
    {
        let mem_ref: MemoryReference = memory_reference.into();
        MemoryReferenceType::try_from(&mem_ref)
            .map(|kind| SsaMemoryReference::Versioned(self.current_version(&kind)))
            .unwrap_or_else(|_| match mem_ref {
                MemoryReference::Deref(expr) => {
                    // Recursively convert the inner expression
                    SsaMemoryReference::Deref(Box::new(
                        self.convert_to_ssa_expression::<MemoryReference>(expr.as_ref()),
                    ))
                }
                _ => unreachable!(
                    "Expected Deref or versionable type, got: {:?}",
                    memory_reference
                ),
            })
    }

    /// Converts an Expression containing MemoryReferences (or similar) into an
    /// Expression containing SsaMemoryReferences based on the current versions.
    /// Used during the initial pass (build_ssa_blocks...).
    fn convert_to_ssa_expression<T>(&self, expr: &Expression<T>) -> Expression<SsaMemoryReference>
    where
        MemoryReference: for<'a> From<&'a T>, // T can be converted to MemoryReference
        T: std::fmt::Debug,
    {
        // Map using the conversion helper
        expr.map(&mut |op| self.convert_to_ssa_memory_reference(op))
    }

    /// Resolves an existing SSA expression (Expression<SsaMemoryReference>)
    /// to use the final versions stored in this registry.
    /// Used during the second pass (populate_reads...).
    fn resolve_ssa_expression(
        &self,
        expr: &Expression<SsaMemoryReference>,
    ) -> Expression<SsaMemoryReference> {
        expr.map(&mut |op: &SsaMemoryReference| {
            // Input is already SsaMemoryReference
            match op {
                SsaMemoryReference::Versioned(v_partial) => {
                    // Check if this registry (self, the start_state) has a definition for this kind
                    if self.has_version_for(&v_partial.kind) {
                        // If yes, the version in this registry dominates. Use it.
                        self.current_version(&v_partial.kind).into()
                    } else {
                        // If no, the version already present (v_partial) is the one to keep,
                        // as it must have been defined within the current block in the first pass.
                        SsaMemoryReference::Versioned(*v_partial) // Clone v_partial
                    }
                }
                SsaMemoryReference::Deref(inner_ssa_expr) => {
                    // Recursively resolve the inner SSA expression using *this* same registry
                    // This avoids calling the conversion functions again.
                    let resolved_inner = self.resolve_ssa_expression(inner_ssa_expr.as_ref());
                    SsaMemoryReference::Deref(Box::new(resolved_inner))
                }
            }
        })
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
    // Modified constructor
    fn new(function: FunctionView<'a, DataFlowComplete>) -> Self {
        // Convert v3 FunctionId to v2 FunctionId
        Self { function }
    }

    fn convert_function(&mut self) -> HashMap<BlockId, SsaBlock> {
        // Step 1: Place phi functions where needed
        let phi_placements = self.place_phi_functions();

        // Step 2: Populate versions for phi results and targets of writes in top-bottom order.
        // Pass only phi_placements now.
        let mut ssa_blocks = self.build_ssa_blocks_with_write_versioning(&phi_placements);

        // Step 3: Compute start and end states for all blocks
        self.compute_start_end_states(&mut ssa_blocks);

        // Step 4: Populate reads and phis
        // Pass only ssa_blocks now.
        self.populate_reads_and_phis(&mut ssa_blocks);

        ssa_blocks
    }

    // Modified to remove 'function' parameter and use self.function (FunctionView)
    fn build_ssa_blocks_with_write_versioning(
        &mut self,
        phi_placements: &HashMap<BlockId, Vec<PhiFunction>>,
    ) -> HashMap<BlockId, SsaBlock> {
        let mut ssa_blocks = HashMap::new();
        // Get the v2 function ID for VersionRegistry
        let v2_function_id = FunctionId::new(self.function.function_id().index());

        // Closure uses the read-only pre-instruction state
        fn map_read(
            (pre_state, _, _): &mut (&VersionRegistry, &mut VersionRegistry, &mut VersionRegistry),
            op: &MemoryReference,
        ) -> Expression<SsaMemoryReference> {
            // Use the read-only pre_state captured before the instruction's write
            Expression::Addressable(pre_state.convert_to_ssa_memory_reference(op))
        }

        // Closure uses the mutable global ('current') and block-local ('end') states
        fn map_write(
            (_, current, end): &mut (&VersionRegistry, &mut VersionRegistry, &mut VersionRegistry),
            op: &MemoryReference,
        ) -> SsaMemoryReference {
            match MemoryReferenceType::try_from(op) {
                Ok(mem_ref) => {
                    // Assign next version in 'current' (global) registry and update 'end' (block-local) state
                    let next_var = current.create_next_version(&mem_ref); // Increments global counter, gets v_n+1
                    end.set_version(mem_ref, next_var); // Store v_n+1 in block's end state
                                                        // Return the correctly incremented version
                    next_var.into()
                }
                Err(_) => {
                    // Non-versionable writes (like Deref targets) are still converted using the mutable 'current' state
                    // This resolves the *pointer* expression based on the latest global version.
                    current.convert_to_ssa_memory_reference(op)
                }
            }
        }

        // Initialize the global version registry tracking the latest version created across all blocks/instructions
        let mut version_registry = VersionRegistry::new(v2_function_id);

        // Iterate over blocks using the FunctionView, sorted by BlockId
        for (block_id, block_view) in self.function.blocks().sorted_by_key(|(id, _)| *id) {
            // Initialize end_state for this block using the v2 function ID
            let mut end_state = VersionRegistry::new(v2_function_id);

            // Handle initial definitions for the entry block using v3 data flow info
            if block_id == self.function.entry_block() {
                block_view
                    .data_flow() // Get v3 DataFlowBlock
                    .defs_in // Access v3 defs_in
                    .iter()
                    .filter(|d| d.source == OriginationPoint::FunctionInput) // Check source
                    .filter_map(|d| MemoryReferenceType::try_from(&d.kind).ok()) // Convert v3 MemoryReference to v2 MemoryReferenceType
                    .for_each(|versioned_kind| {
                        // Set version 0 for function inputs
                        end_state.set_version(
                            versioned_kind,
                            VersionedMemoryReference {
                                kind: versioned_kind,
                                function_id: v2_function_id, // Use v2 ID
                                version: 0,
                            },
                        );
                    });
            }

            // Get phi functions placed for this block
            let mut phi_functions = phi_placements.get(&block_id).cloned().unwrap_or_default();

            // Assign versions to phi results and update the end_state
            for phi in phi_functions.iter_mut() {
                // Use the main version_registry to get the next version
                phi.result = version_registry.create_next_version(&phi.result.kind);
                // Update the block's end_state with the new phi result version
                end_state.set_version(phi.result.kind, phi.result);
            }

            // The state after phi assignments is the initial start state for this block's instructions
            let start_state = end_state.clone();

            // Convert v3 LIR instructions to v2 SSA instructions, updating versions
            let mut instructions = Vec::new();
            for instr_node in block_view.low_instructions() {
                // Use v3 low_instructions
                // Capture the read-state *before* this instruction potentially writes
                let pre_instr_state = version_registry.clone();

                // Prepare the 3-tuple state for map_rw
                let mut state = (&pre_instr_state, &mut version_registry, &mut end_state);

                // Map the v3 instruction node using the read/write mappers and the new state tuple
                // map_read will use pre_instr_state, map_write will use version_registry & end_state
                instructions.push(instr_node.flat_map_rw(&mut state, map_read, map_write));
            }

            // Create the v2 SsaBlock structure
            // Create the v2 SsaBlock structure (without native fields)
            let ssa_block = SsaBlock {
                original_id: block_id, // Remove dereference
                phi_functions,
                instructions,
                start_state,
                end_state,
                // Initialize next/predecessors, will be populated in populate_reads_and_phis
                next: disasm::v3::control_flow::NextKind::Unknown,
                predecessors: vec![],
            };

            ssa_blocks.insert(block_id, ssa_block); // Remove dereference
        }
        ssa_blocks
    }

    // Modified to use v3 data structures from self.function and self.model
    fn place_phi_functions(&mut self) -> HashMap<BlockId, Vec<PhiFunction>> {
        let mut phi_placements: HashMap<BlockId, Vec<PhiFunction>> = HashMap::new();
        // Use self.function.function_id() to get the v3 ID, then convert to v2 ID
        let function_id = FunctionId::new(self.function.function_id().index());

        // Initialize empty phi function vectors for all blocks in the current function view
        for (block_id, _) in self.function.blocks() {
            phi_placements.insert(block_id, Vec::new());
        }

        for (block_id, block_view) in self.function.blocks() {
            let predecessors = block_view.predecessors(); // v3 PredecessorKind<MemoryReference>

            // Only blocks with multiple predecessors or blocks that are function returns need phi functions.
            if predecessors.len() <= 1
                && !predecessors.iter().any(|pred| {
                    matches!(
                        pred,
                        crate::disasm::v3::control_flow::PredecessorKind::FunctionCallReturns(_)
                    )
                })
            // Use v3 type
            {
                continue;
            }

            // Get the v3 data flow result for this block
            let block_flow = block_view.data_flow(); // Directly access v3 DataFlowBlock

            // Find all variable definitions reaching this block from any predecessor
            // Note: v3 defs_in is HashSet<Definition>, where Definition contains kind and source
            let all_incoming_defs: HashMap<MemoryReference, HashSet<OriginationPoint>> =
                if predecessors.len() > 1 {
                    block_flow
                        .defs_in // Use v3 defs_in
                        .iter()
                        .map(|d| (d.kind.clone(), d.source)) // d.kind is MemoryReference
                        .into_grouping_map()
                        .collect()
                } else {
                    HashMap::new()
                };

            // Find return values accessed if this block is a return site
            let return_values_accessed: Vec<MemoryReference> = predecessors
                .iter()
                .find_map(|pred| pred.get_function_call_returns())
                .map(|fc| fc.calling_block)
                .map(|block| {
                    self.function
                        .block(&block)
                        .data_flow()
                        .return_values_accessed
                        .as_ref()
                        .unwrap()
                })
                .map(|rva| {
                    rva.keys()
                        .map(|offset| MemoryReference::StackRelative(*offset))
                        .collect_vec()
                })
                .unwrap_or_default();

            // Determine variables needing phi functions:
            // - Defined differently by multiple predecessors AND live-in
            // - OR are accessed return values from a function call
            let vars_needing_phi = all_incoming_defs
                .iter()
                .filter(|(mem_ref, def_sources)| {
                    def_sources.len() > 1 && block_flow.live_in.contains_key(*mem_ref)
                    // Use v3 live_in (HashMap<MemoryReference, _>)
                })
                .map(|(mem_ref, _)| mem_ref) // Get the MemoryReference
                .chain(return_values_accessed.iter()) // Add accessed return values
                .unique(); // Ensure each variable is considered only once

            // For each variable needing a phi function...
            for mem_ref in vars_needing_phi {
                // Try converting the v3 MemoryReference to the v2 MemoryReferenceType used for versioning
                let Ok(phi_kind) = MemoryReferenceType::try_from(mem_ref) else {
                    // Skip if it's not a type we version (e.g., Deref)
                    trace!(
                        "{}: Skipping phi for non-versionable type {:?}",
                        block_id,
                        mem_ref
                    );
                    continue;
                };

                // Create the phi result variable (using the stored v2 function ID)
                let phi_result = VersionedMemoryReference {
                    kind: phi_kind,
                    function_id, // Use the v2 function ID stored in self
                    version: 0,  // Placeholder version, will be assigned later
                };
                trace!("{}: Placing phi for {} = ?", block_id, phi_result);

                // Create the v2 PhiFunction struct (inputs map remains empty for now)
                let phi = PhiFunction {
                    result: phi_result,
                    inputs: HashMap::new(), // Will be filled in populate_reads_and_phis
                };

                // Add the phi function to this block's placement list
                phi_placements.get_mut(&block_id).unwrap().push(phi);
            }
        }

        phi_placements
    }

    // Modified to use v3 data structures from self.function
    fn compute_start_end_states(&self, ssa_blocks: &mut HashMap<BlockId, SsaBlock>) {
        let block_ids = ssa_blocks.keys().copied().collect_vec();

        // These are the variables that are updated by the block (written to or phi result). No predecessor
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
                // Get the v3 BlockView for the current block
                let block_view = self.function.block(block_id);
                let live_in = &block_view.data_flow().live_in; // v3 live_in: HashMap<MemoryReference, _>

                // Clone the initial states calculated in build_ssa_blocks_with_write_versioning
                let mut new_in = initial_start_states[block_id].clone();
                let mut new_out = initial_end_states[block_id].clone();

                // Iterate over v3 predecessors
                for pred in block_view.predecessors() {
                    let pred_id = pred.source_block_id();
                    // Get the end state from the *current* iteration's ssa_blocks map
                    let pred_end_state = &ssa_blocks.get(&pred_id).unwrap().end_state;

                    // Iterate through versions defined in the predecessor's end state
                    for (mem_ref_type, versioned_mem_ref) in pred_end_state.iter_versions() {
                        // Convert MemoryReferenceType to MemoryReference for live_in check
                        let mem_ref = mem_ref_type.to_memory_reference();

                        // Check if the variable is live at the entry of the current block
                        // AND is not already defined by a phi function in this block (checked via initial_start_states)
                        if !live_in.contains_key(&mem_ref) {
                            // This var isn't live coming into this block from this path
                            trace!("Skipping var {} from predecessor {} because it is not live-in for block {}", mem_ref_type, pred_id, block_id);
                            continue;
                        }

                        if initial_start_states[block_id].has_version_for(mem_ref_type) {
                            // This block defines this variable via a phi function,
                            // so the predecessor's version doesn't propagate directly.
                            trace!("Skipping var {} from predecessor {} because block {} defines it with a phi", mem_ref_type, pred_id, block_id);
                            continue;
                        }

                        // Propagate the version from the predecessor to the current block's start state (new_in)
                        // Note: If multiple predecessors provide a version for the *same* non-phi variable,
                        // this implies an issue earlier (data flow or phi placement).
                        // Propagate the version from the predecessor to the current block's start state (new_in)
                        // This handles the case where the variable is live-in and not defined by a phi here.
                        new_in.set_version(*mem_ref_type, *versioned_mem_ref);

                        // If the current block *doesn't* write to this variable (checked via initial_end_states),
                        // then the version also propagates to the end state (new_out).
                        if !initial_end_states[block_id].has_version_for(mem_ref_type) {
                            new_out.set_version(*mem_ref_type, *versioned_mem_ref);
                        }
                        // If the current block writes to this variable (checked via initial_end_states),
                        // the propagated version doesn't affect the end_state (new_out).
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
                        // --- REMOVED DUPLICATE CALL to new_out.set_version ---
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

    // Modified to remove 'function' parameter and use self.function (FunctionView)
    fn populate_reads_and_phis(&self, ssa_blocks: &mut HashMap<BlockId, SsaBlock>) {
        // Iterate over blocks using the FunctionView
        for (block_id, block_view) in self.function.blocks() {
            // Get the mutable SSA block we are populating
            let ssa_block = ssa_blocks.get(&block_id).unwrap(); // Need mutable borrow later

            // Clone the initial phi functions (results only) placed earlier
            let initial_phis = ssa_block.phi_functions.clone();
            let mut populated_phis = Vec::with_capacity(initial_phis.len());

            for phi in &initial_phis {
                let mut phi_inputs = HashMap::new();
                // Use v3 predecessors from the block_view
                for pred in block_view.predecessors() {
                    let pred_id = pred.source_block_id();
                    // Get the end state of the predecessor block from the ssa_blocks map
                    let pred_ssa_block = ssa_blocks.get(&pred_id).unwrap_or_else(|| {
                        panic!("Predecessor block {pred_id} not found for block {block_id}")
                    });

                    // Define the mapping closure to *convert* predecessor MemoryReferences based on its end_state
                    let mut map_mem_ref = |mem_ref: &MemoryReference| {
                        pred_ssa_block
                            .end_state
                            .convert_to_ssa_memory_reference(mem_ref)
                    };

                    // Special handling for return values from function calls
                    if matches!(
                        pred,
                        crate::disasm::v3::control_flow::PredecessorKind::FunctionCallReturns(_)
                    ) && (&phi.result.kind)
                        .as_stack_relative()
                        .is_some_and(|x| x > 0)
                    // Fixed as_stack_relative call here too
                    {
                        // For function returns, the phi result itself represents the value.
                        // Map the predecessor *before* inserting.
                        phi_inputs.insert(pred.map(&mut map_mem_ref), phi.result);
                    } else {
                        // Get the version from the predecessor's end state
                        let input_version =
                            pred_ssa_block.end_state.current_version(&phi.result.kind);
                        // Map the predecessor *before* inserting.
                        phi_inputs.insert(pred.map(&mut map_mem_ref), input_version);
                    }
                }
                // Create the final PhiFunction with populated inputs
                populated_phis.push(PhiFunction {
                    result: phi.result,
                    inputs: phi_inputs,
                });
            }

            // Now, process instructions using the computed start state to resolve reads.
            // The write targets already have their final versions from the previous step.
            let mut start_state = &ssa_block.start_state; // Use immutable borrow of the final start state
            let mut populated_instructions = Vec::with_capacity(ssa_block.instructions.len());

            for instr_node in &ssa_block.instructions {
                // Iterate over instructions with finalized writes
                // Map reads using start_state, map writes by cloning (version is already final)
                let read_mapped_instr = instr_node.map_rw(
                    &mut start_state, // Pass start_state as context
                    &mut |reg, ssa_mem_ref: &SsaMemoryReference| {
                        // reg is the start_state
                        // map_read closure: Resolve reads using the start_state (reg) or the existing version
                        match ssa_mem_ref {
                            SsaMemoryReference::Versioned(v_local) => {
                                // Check if the start state (reg) has a definition for this kind
                                if reg.has_version_for(&v_local.kind) {
                                    // If yes, the start state version dominates. Use it.
                                    reg.current_version(&v_local.kind).into()
                                } else {
                                    // If no, the version assigned in the first pass (v_local) is correct
                                    // for reads defined within the block before this read.
                                    SsaMemoryReference::Versioned(*v_local) // Clone the existing versioned ref
                                }
                            }
                            SsaMemoryReference::Deref(expr_local) => {
                                // expr_local is Box<Expression<SsaMemoryReference>>
                                // Resolve the inner expression using the start state registry (reg)
                                // This recursive call uses resolve_ssa_expression, which now has the correct logic.
                                let resolved_inner_expr =
                                    reg.resolve_ssa_expression(expr_local.as_ref());
                                SsaMemoryReference::Deref(Box::new(resolved_inner_expr))
                            }
                        }
                    },
                    &mut |_, ssa_mem_ref| ssa_mem_ref.clone(),
                );
                populated_instructions.push(read_mapped_instr);
            }

            // Map the NextKind using the final end_state of the block
            // Map the NextKind using the final end_state of the block to *convert* MemoryReferences
            let ssa_block_next = block_view.next().map(&mut |op: &MemoryReference| {
                // Use the computed end_state for the block to convert MemoryReferences
                ssa_block.end_state.convert_to_ssa_memory_reference(op)
            });

            // Update the mutable ssa_block with populated phis and instructions

            // Update predecessors of successor blocks using the v3 NextKind (ssa_block_next)
            match &ssa_block_next {
                disasm::v3::control_flow::NextKind::Follows(target_id) => {
                    if let Some(successor_block) = ssa_blocks.get_mut(target_id) {
                        successor_block.predecessors.push(
                            disasm::v3::control_flow::PredecessorKind::FollowsFrom(block_id),
                        ); // Use block_id directly
                    }
                }
                disasm::v3::control_flow::NextKind::Goto(target_block_id) => {
                    if let Some(successor_block) = ssa_blocks.get_mut(target_block_id) {
                        successor_block.predecessors.push(
                            disasm::v3::control_flow::PredecessorKind::GotoFrom(block_id),
                        ); // Use block_id directly
                    }
                }
                disasm::v3::control_flow::NextKind::FunctionCall(call) => {
                    // 'call' is already v3::FunctionCall<SsaMemoryReference>
                    if let Some(successor_block) = ssa_blocks.get_mut(&call.return_block) {
                        successor_block
                            .predecessors
                            .push(FunctionCallReturns(call.clone()));
                    }
                }
                disasm::v3::control_flow::NextKind::Condition(cond) => {
                    // 'cond' is already v3::Condition<SsaMemoryReference>
                    if let Some(target_block) = ssa_blocks.get_mut(&cond.target_block) {
                        target_block.predecessors.push(
                            disasm::v3::control_flow::PredecessorKind::ConditionalJump(
                                cond.clone(),
                            ),
                        );
                    }
                    if let Some(follows_block) = ssa_blocks.get_mut(&cond.follows_block) {
                        follows_block.predecessors.push(
                            disasm::v3::control_flow::PredecessorKind::ConditionalFollow(
                                cond.clone(),
                            ),
                        );
                    }
                }
                disasm::v3::control_flow::NextKind::Return
                | disasm::v3::control_flow::NextKind::Halt
                | disasm::v3::control_flow::NextKind::Unknown => { /* No successors */ }
            }
            // Store the final v3 NextKind in the block
            let ssa_block = ssa_blocks.get_mut(&block_id).unwrap(); // Need mutable borrow later
            ssa_block.instructions = populated_instructions;
            ssa_block.phi_functions = populated_phis;
            ssa_block.next = ssa_block_next;
        }
    }
}
