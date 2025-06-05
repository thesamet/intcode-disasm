use crate::disasm::v3::model::{DataFlowComplete, Model, SsaComplete};
use crate::disasm::v3::{InstructionId, NextKind};
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

use colored::{Color, Colorize};
use either::Either;
use itertools::Itertools;
use petgraph::algo::dominators::simple_fast;
use petgraph::visit::IntoNeighbors;
use std::convert::From;

use crate::disasm;
use crate::disasm::v3::cfg::PredecessorKind::FunctionCallReturns;
use crate::disasm::v3::data_flow::OriginationPoint;
use crate::disasm::v3::ssa::types::VersionableMemoryKind;
use crate::disasm::v3::ssa::{SsaMemoryReference, VersionedMemoryReference};
use crate::disasm::{
    v2::model::{BlockId, FunctionId},
    v3::{
        self,
        cfg::FunctionView,
        lir::{Expression, MemoryReference, MemoryReferenceInfo},
    },
};

use std::collections::{HashMap, HashSet};
pub use v3::ssa::SsaBlock;

use crate::disasm::v3::lir::ReadExpressionExtractor; // Import the trait
impl ReadExpressionExtractor for SsaMemoryReference {
    fn extract_read_expressions(&self) -> Option<&Expression<Self>> {
        match self {
            SsaMemoryReference::Deref(expr) => Some(expr),
            SsaMemoryReference::Versioned(_) => None,
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
    pub inputs:
        HashMap<disasm::v3::cfg::PredecessorKind<SsaMemoryReference>, VersionedMemoryReference>,
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

struct SSAConversionState<'a> {
    function: FunctionView<'a, DataFlowComplete>,
    assignments_to_versions: HashMap<InstructionId, VersionedMemoryReference>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VersionRegistry {
    current_versions: HashMap<VersionableMemoryKind, usize>,
    function_id: FunctionId,
}

impl VersionRegistry {
    pub fn new(function_id: FunctionId) -> Self {
        Self {
            current_versions: HashMap::new(),
            function_id,
        }
    }

    pub fn current_version(&self, memory_reference_type: &VersionableMemoryKind) -> usize {
        self.current_versions
            .get(memory_reference_type)
            .cloned()
            .unwrap_or(0)
    }

    fn create_next_version(
        &mut self,
        memory_reference_type: &VersionableMemoryKind,
    ) -> VersionedMemoryReference {
        let next_version = self.current_version(memory_reference_type) + 1;
        self.current_versions
            .insert(*memory_reference_type, next_version);
        VersionedMemoryReference {
            kind: *memory_reference_type,
            function_id: self.function_id,
            version: next_version,
        }
    }

    fn set_version(&mut self, memory_reference_type: VersionableMemoryKind, version: usize) {
        self.current_versions.insert(memory_reference_type, version);
    }

    /// Converts a MemoryReference (or similar) into an SsaMemoryReference using the *current* state.
    fn resolve_to_ssa_memory_reference<T>(
        &self,
        memory_reference: &MemoryReference,
    ) -> SsaMemoryReference
    where
        MemoryReference: for<'a> From<&'a T>, // T can be converted to MemoryReference
    {
        match VersionableMemoryKind::split_kind_or_deref(memory_reference) {
            Either::Left(kind) => {
                SsaMemoryReference::Versioned(self.resolve_to_versioned_ssa_memory_reference(&kind))
            }
            Either::Right(expr) => {
                SsaMemoryReference::Deref(Box::new(self.convert_to_ssa_expression(expr)))
            }
        }
    }

    /// Creates a VersionedMemoryReference for a given versionable kind using the current version.
    fn resolve_to_versioned_ssa_memory_reference(
        &self,
        kind: &VersionableMemoryKind,
    ) -> VersionedMemoryReference {
        VersionedMemoryReference {
            kind: *kind,
            function_id: self.function_id,
            version: self.current_version(kind),
        }
    }

    /// Converts an Expression containing MemoryReferences  into an
    /// Expression containing SsaMemoryReferences based on the current versions.
    /// Used during the initial pass (build_ssa_blocks...).
    fn convert_to_ssa_expression(
        &self,
        expr: &Expression<MemoryReference>,
    ) -> Expression<SsaMemoryReference> {
        // Map using the conversion helper
        expr.map(|op| self.resolve_to_ssa_memory_reference(op))
    }

    pub fn iter_versions(&self) -> impl Iterator<Item = (&VersionableMemoryKind, &usize)> {
        self.current_versions.iter()
    }

    pub fn iter_versioned(
        &self,
    ) -> impl Iterator<Item = (&VersionableMemoryKind, VersionedMemoryReference)> {
        self.current_versions
            .iter()
            .map(|(k, v)| (k, VersionedMemoryReference::new(*k, self.function_id, *v)))
    }

    pub fn has_version_for(&self, memory_reference_type: &VersionableMemoryKind) -> bool {
        self.current_versions.contains_key(memory_reference_type)
    }
}

impl std::fmt::Debug for VersionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VersionRegistry<")?;
        for (kind, version) in self.current_versions.iter().sorted() {
            write!(
                f,
                "{}: {}, ",
                kind.to_string().color(Color::Yellow),
                version.to_string().color(Color::Cyan)
            )?;
        }
        f.write_str(">")?;
        Ok(())
    }
}

// Creates the NextKind using SsaOperands based on the current versions.

impl<'a> SSAConversionState<'a> {
    // Modified constructor
    fn new(function: FunctionView<'a, DataFlowComplete>) -> Self {
        // Convert v3 FunctionId to v2 FunctionId
        Self {
            function,
            assignments_to_versions: HashMap::new(),
        }
    }

    fn convert_function(&mut self) -> HashMap<BlockId, SsaBlock> {
        // Step 1: Place phi functions where needed
        let phi_placements = self.place_phi_functions();

        // Step 2: Populate versions for phi results and targets of writes in top-bottom order.
        // Pass only phi_placements now.
        let mut ssa_blocks = self.compute_end_state_for_vars_assigned_in_block(&phi_placements);

        // Step 3: Compute start and end states for all blocks
        self.compute_start_end_states(&mut ssa_blocks);

        // Step 4: Populate reads and phis
        // Pass only ssa_blocks now.
        self.populate_reads_and_phis(&mut ssa_blocks);

        ssa_blocks
    }

    fn place_phi_functions(&mut self) -> HashMap<BlockId, Vec<PhiFunction>> {
        let dominators = simple_fast(&self.function, self.function.entry_block());
        let mut phi_placements: HashMap<BlockId, Vec<PhiFunction>> = HashMap::new();

        let mut dom_frontier: HashMap<BlockId, HashSet<BlockId>> = HashMap::new();
        let mut dominates: HashMap<BlockId, HashSet<BlockId>> = HashMap::new();
        for (block_id, _) in self.function.blocks() {
            for dominator in dominators.dominators(block_id).unwrap() {
                dominates.entry(dominator).or_default().insert(block_id);
            }
        }
        for (block_id, _) in self.function.blocks() {
            // n is in DF(block_id) if block_id dominates d but block_id does not
            // strictly dominate n
            if let Some(dom_set) = dominates.get(&block_id) {
                for d in dom_set {
                    for n in self.function.neighbors(*d) {
                        if !dom_set.contains(&n) || (block_id == n) {
                            dom_frontier.entry(block_id).or_default().insert(n);
                        }
                    }
                }
            }
        }
        for (block_id, block_view) in self.function.blocks() {
            let block_data_flow = self.function.block(&block_id).data_flow();
            for var in block_data_flow.gen.keys() {
                let Ok(kind) = VersionableMemoryKind::try_from(var) else {
                    continue;
                };
                for frontier in dom_frontier.get(&block_id).cloned().unwrap_or_default() {
                    if !self
                        .function
                        .block(&frontier)
                        .data_flow()
                        .live_in
                        .contains_key(var)
                    {
                        continue;
                    }
                    let c = phi_placements.entry(frontier).or_default();
                    if c.iter().any(|p| p.result.kind == kind) {
                        continue;
                    }
                    c.push(PhiFunction {
                        result: VersionedMemoryReference::new(kind, self.function.function_id(), 0),
                        inputs: HashMap::new(),
                    });
                }
            }
            // If there are return values accessed, create phi functions for them at the return block
            if let Some(ret_values) = block_data_flow.return_values_accessed.as_ref() {
                let NextKind::FunctionCall(fc) = block_view.next() else {
                    panic!("Has return_value_accessed but not a function call");
                };
                let return_block_phis = phi_placements.entry(fc.return_block).or_default();

                for mem_ref in ret_values.keys() {
                    // Handle different types of memory references
                    let kind = if let Some(offset) = mem_ref.as_stack_relative() {
                        // Stack-relative memory reference
                        VersionableMemoryKind::RelativeMemory(offset)
                    } else if let Some(addr) = mem_ref.as_global() {
                        // Global memory reference
                        VersionableMemoryKind::Memory(addr)
                    } else {
                        // Skip other types of memory references for now
                        continue;
                    };

                    // Skip if we already have a phi function for this kind
                    if return_block_phis.iter().any(|phi| phi.result.kind == kind) {
                        continue;
                    }

                    // Add a new phi function
                    return_block_phis.push(PhiFunction {
                        result: VersionedMemoryReference::new(kind, self.function.function_id(), 0),
                        inputs: HashMap::new(),
                    });
                }
            }
        }

        for (_, phis) in phi_placements.iter_mut() {
            phis.sort_by_key(|p| p.result.kind);
            phis.reverse();
        }
        /*

        for (block_id, block_view) in self.function.blocks() {
            let predecessors = block_view.predecessors(); // v3 PredecessorKind<MemoryReference>

            // Only blocks with multiple predecessors or blocks that are function returns need phi functions.
            if predecessors.len() <= 1
                && !predecessors.iter().any(|pred| {
                    matches!(
                        pred,
                        crate::disasm::v3::cfg::PredecessorKind::FunctionCallReturns(_)
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
                        .cloned()  // Clone the MemoryReference directly
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
                let Ok(phi_kind) = VersionableMemoryKind::try_from(mem_ref) else {
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
        */

        phi_placements
    }

    fn compute_end_state_for_vars_assigned_in_block(
        &mut self,
        phi_placements: &HashMap<BlockId, Vec<PhiFunction>>,
    ) -> HashMap<BlockId, SsaBlock> {
        let mut ssa_blocks = HashMap::new();

        // Initialize a version registry that tracks the highest version assigned to each versionable
        // memory kind across the entire function during this block-by-block processing pass.
        // This registry is updated every time a new version is created (for phi results or writes).
        let mut global_registry = VersionRegistry::new(self.function.function_id());

        // Iterate over blocks using the FunctionView, sorted by BlockId
        for (block_id, block_view) in self.function.blocks().sorted_by_key(|(id, _)| *id) {
            let mut end_state = VersionRegistry::new(self.function.function_id());

            // Handle initial definitions for the entry block using v3 data flow info
            if block_id == self.function.entry_block() {
                block_view
                    .data_flow() // Get v3 DataFlowBlock
                    .defs_in // Access v3 defs_in
                    .iter()
                    .filter(|d| d.source == OriginationPoint::FunctionInput) // Check source
                    .filter_map(|d| VersionableMemoryKind::try_from(&d.kind).ok())
                    .for_each(|versioned_kind| {
                        // Set version 0 for function inputs
                        end_state.set_version(versioned_kind, 0);
                    });
            }

            // Get phi functions placed for this block
            let mut phi_functions = phi_placements.get(&block_id).cloned().unwrap_or_default();

            // Assign versions to phi results and update the end_state
            for phi in phi_functions.iter_mut() {
                // Use the main version_registry to get the next version
                phi.result = global_registry.create_next_version(&phi.result.kind);
                // Update the block's end_state with the new phi result version
                end_state.set_version(phi.result.kind, phi.result.version);
            }
            // start_state is frozen after phi has been assigned. That means we have the latest
            // version for all variables that were updated by phi functions within this block.
            let start_state = end_state.clone();

            // In this initial pass, we focus solely on incrementing  versions each time           let mut instructions: Vec<InstructionNode<SsaMemoryReference>> = Vec::new();
            // we encounter a write. This determines the end_state for each block for the
            // flow computation that comes later.
            for instr_node in block_view.low_instructions() {
                let Some(write_ref) = instr_node.kind.get_write_address() else {
                    continue;
                };
                let Ok(versionable_kind) = VersionableMemoryKind::try_from(write_ref) else {
                    continue;
                };
                // When processing a write, allocate a new version and record that version in
                // assignments_to_versions. Update the version in end_state. In populate_reads_and_phis,
                // we will use this version to when creating the assignment target.
                let new_ver = global_registry.create_next_version(&versionable_kind);
                self.assignments_to_versions.insert(instr_node.id, new_ver);
                end_state.set_version(versionable_kind, new_ver.version);
            }

            let ssa_block = SsaBlock {
                original_id: block_id, // Remove dereference
                phi_functions,
                instructions: vec![],
                start_state,
                end_state,
                // Initialize next/predecessors, will be populated in populate_reads_and_phis
                next: disasm::v3::cfg::NextKind::Unknown,
                predecessors: vec![],
            };

            ssa_blocks.insert(block_id, ssa_block); // Remove dereference
        }
        ssa_blocks
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
                let ssa_block = ssa_blocks.get(block_id).unwrap();

                // Iterate over v3 predecessors
                for pred in block_view.predecessors() {
                    let pred_id = pred.source_block_id();
                    // Get the end state from the *current* iteration's ssa_blocks map
                    let pred_end_state = &ssa_blocks[&pred_id].end_state;

                    // Iterate through versions defined in the predecessor's end state
                    for (mem_ref_type, mem_ref_version) in pred_end_state.iter_versions() {
                        // Convert MemoryReferenceType to MemoryReference for live_in check
                        let mem_ref = mem_ref_type.to_memory_reference();

                        // Check if the variable is live at the entry of the current block
                        if !live_in.contains_key(&mem_ref) {
                            // This var isn't live coming into this block from this path
                            continue;
                        }

                        if ssa_block
                            .phi_functions
                            .iter()
                            .any(|phi| phi.result.kind == *mem_ref_type)
                        {
                            continue;
                        }

                        // Propagate the version from the predecessor to the current block's start state (new_in)
                        // Note: If multiple predecessors provide a version for the *same* non-phi variable,
                        // this implies an issue earlier (data flow or phi placement).
                        // Propagate the version from the predecessor to the current block's start state (new_in)
                        // This handles the case where the variable is live-in and not defined by a phi here.
                        new_in.set_version(*mem_ref_type, *mem_ref_version);

                        // If the current block *doesn't* write to this variable (checked via initial_end_states),
                        // then the version also propagates to the end state (new_out).
                        if !initial_end_states[block_id].has_version_for(mem_ref_type) {
                            new_out.set_version(*mem_ref_type, *mem_ref_version);
                        }
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
        for (block_id, block_view) in self.function.blocks().sorted_by_key(|(id, _)| *id) {
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
                            .resolve_to_ssa_memory_reference(mem_ref)
                    };

                    // Special handling for return values from function calls
                    if matches!(
                        pred,
                        crate::disasm::v3::cfg::PredecessorKind::FunctionCallReturns(_)
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
                        let input_version = pred_ssa_block
                            .end_state
                            .resolve_to_versioned_ssa_memory_reference(&phi.result.kind);
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

            // Now, process instructions starting from computed start state to resolve reads
            // and writes.
            let mut running_state = ssa_block.start_state.clone();
            let mut populated_instructions =
                Vec::with_capacity(block_view.low_instructions().len());

            for instr_node in block_view.low_instructions() {
                // Iterate over instructions, use assignments_to_versions to get the vesrions
                // determined in the first pass.
                let read_mapped_instr = instr_node.map_rw(
                    &mut running_state,
                    &mut |running_state: &mut VersionRegistry,
                          mem_ref: &MemoryReference|
                     -> SsaMemoryReference {
                        // Resolve reads using the current running_state.
                        running_state.resolve_to_ssa_memory_reference(mem_ref)
                    },
                    &mut |running_state: &mut VersionRegistry, mem_ref: &MemoryReference| {
                        match VersionableMemoryKind::split_kind_or_deref(mem_ref) {
                            Either::Left(versionable) => {
                                let next_ver = self.assignments_to_versions[&instr_node.id];
                                // Update running_state with the new version
                                running_state.set_version(versionable, next_ver.version);
                                SsaMemoryReference::Versioned(next_ver)
                            }
                            Either::Right(expr) => SsaMemoryReference::Deref(Box::new(
                                running_state.convert_to_ssa_expression(expr),
                            )),
                        }
                    },
                );
                populated_instructions.push(read_mapped_instr);
            }
            // Sanity check: we must arrive to the same end state as the original pass.
            assert_eq!(running_state, ssa_block.end_state);

            // Map the NextKind using the final end_state of the block
            // Map the NextKind using the final end_state of the block to *convert* MemoryReferences
            let ssa_block_next = block_view.next().map(&mut |op: &MemoryReference| {
                // Use the computed end_state for the block to convert MemoryReferences
                ssa_block.end_state.resolve_to_ssa_memory_reference(op)
            });

            // Update the mutable ssa_block with populated phis and instructions

            // Update predecessors of successor blocks using the v3 NextKind (ssa_block_next)
            match &ssa_block_next {
                disasm::v3::cfg::NextKind::Follows(target_id) => {
                    if let Some(successor_block) = ssa_blocks.get_mut(target_id) {
                        successor_block
                            .predecessors
                            .push(disasm::v3::cfg::PredecessorKind::FollowsFrom(block_id));
                        // Use block_id directly
                    }
                }
                disasm::v3::cfg::NextKind::Goto(target_block_id) => {
                    if let Some(successor_block) = ssa_blocks.get_mut(target_block_id) {
                        successor_block
                            .predecessors
                            .push(disasm::v3::cfg::PredecessorKind::GotoFrom(block_id));
                        // Use block_id directly
                    }
                }
                disasm::v3::cfg::NextKind::FunctionCall(call) => {
                    // 'call' is already v3::FunctionCall<SsaMemoryReference>
                    if let Some(successor_block) = ssa_blocks.get_mut(&call.return_block) {
                        successor_block
                            .predecessors
                            .push(FunctionCallReturns(call.clone()));
                    }
                }
                disasm::v3::cfg::NextKind::Condition(cond) => {
                    // 'cond' is already v3::Condition<SsaMemoryReference>
                    if let Some(target_block) = ssa_blocks.get_mut(&cond.target_block) {
                        target_block.predecessors.push(
                            disasm::v3::cfg::PredecessorKind::ConditionalJump(cond.clone()),
                        );
                    }
                    if let Some(follows_block) = ssa_blocks.get_mut(&cond.follows_block) {
                        follows_block.predecessors.push(
                            disasm::v3::cfg::PredecessorKind::ConditionalFollow(cond.clone()),
                        );
                    }
                }
                disasm::v3::cfg::NextKind::Return
                | disasm::v3::cfg::NextKind::Halt
                | disasm::v3::cfg::NextKind::Unknown => { /* No successors */ }
            }
            // Store the final v3 NextKind in the block
            let ssa_block = ssa_blocks.get_mut(&block_id).unwrap(); // Need mutable borrow later
            ssa_block.instructions = populated_instructions;
            ssa_block.phi_functions = populated_phis;
            ssa_block.next = ssa_block_next;
        }
    }
}
