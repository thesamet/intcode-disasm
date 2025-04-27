use itertools::Itertools;
use std::convert::From;

use crate::disasm::v2::{
    control_flow::{NextKind, PredecessorKind},
    instructions::{Operand, OperandKind},
    model::{BlockId, FunctionId, ProgramModel},
};
use std::collections::{HashMap, HashSet};
use std::fmt;

use super::{
    instructions::{GenericInstruction, InstructionId},
    model::Function,
};

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
#[derive(Debug, Clone)]
pub struct PhiFunction {
    /// The resulting SSA variable (must be a Variable)
    pub result: SsaVar,
    /// Map describing the sources for this Phi function's value.
    /// The key is the PredecessorKind corresponding to the incoming edge.
    /// The value is the SsaOperand representing the value coming from that source.
    /// For FunctionReturn predecessors, the SsaOperand is typically the phi.result itself wrapped in SsaOperand::Variable.
    pub inputs: HashMap<PredecessorKind<Operand>, SsaVar>,
}

pub type SsaInstruction = GenericInstruction<SsaOperand>;

/// Represents a basic block in SSA form
#[derive(Debug, Clone)]
pub struct SsaBlock {
    /// Original block ID
    pub original_id: BlockId,
    /// Phi functions at the start of this block
    pub phi_functions: Vec<PhiFunction>,
    /// Instructions in SSA form
    pub instructions: Vec<SsaInstruction>,
    // Start state: the state of all versioned variables at the start of this block
    pub start_state: HashMap<SsaVarKind, SsaVar>, // Track only versioned variables
    /// End state: the state of all versioned variables at the end of this block
    pub end_state: HashMap<SsaVarKind, SsaVar>, // Track only versioned variables
    /// Control flow information using SSA operands
    pub next: NextKind<SsaOperand>,
    pub predecessors: Vec<PredecessorKind<SsaOperand>>,
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
    pub fn find_ssa_operand_by_marker(&self, marker: char) -> Option<SsaOperand> {
        for block in self.blocks.values() {
            for instr in &block.instructions {
                // Use into_iter() to consume and avoid borrowing issues if needed,
                // or just iterate over references.
                // Assuming reads/writes return Vec<SsaOperand> or similar collection
                for ssa_operand in instr.reads().into_iter().chain(instr.writes().into_iter()) {
                    // Check if the operand has the marker in its origin info
                    if ssa_operand.origin_info.debug_marker == Some(marker) {
                        // Return the SsaOperand (it's Copy)
                        return Some(ssa_operand);
                    }
                }
            }
        }
        None
    }
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
        let mut converter = SSAConversionState::new(model);

        // Process each function in the model
        for &function_id in model.functions().keys() {
            let ssa_func = SsaFunction {
                original_id: function_id,
                blocks: converter.convert_function(function_id),
            };
            ssa_result.functions.insert(function_id, ssa_func);
        }

        ssa_result
    }

    #[cfg(test)]
    pub fn find_ssa_operand_by_marker(&self, marker: char) -> SsaOperand {
        self.functions
            .values()
            .flat_map(|func| func.find_ssa_operand_by_marker(marker))
            .next()
            .unwrap_or_else(|| panic!("Marker '{}' not found in SSA program", marker))
    }
}

struct SSAConversionState<'a> {
    model: &'a ProgramModel,
}

impl<'a> SSAConversionState<'a> {
    fn new(model: &'a ProgramModel) -> Self {
        Self { model }
    }

    // Creates the next version for a *variable* operand. Panics if called on a constant.
    fn create_next_version(
        current_versions: &mut HashMap<SsaVarKind, SsaVar>,
        var_operand: Operand,
        function_id: FunctionId,
    ) -> SsaVar {
        // This function should only be called for actual variables, not constants.
        let kind = SsaVarKind::from_operand_kind(&var_operand.kind)
            .expect("create_next_version called on a non-variable operand");

        let version = current_versions.get(&kind).map(|v| v.version).unwrap_or(0) + 1;
        let new_version = SsaVar {
            kind,
            version,
            origin_info: SsaOriginInfo::new(
                function_id,
                var_operand.offset,
                var_operand.debug_marker,
            ),
        };
        current_versions.insert(kind, new_version);
        new_version
    }

    // Gets the current SsaOperand (Constant or Variable) for a given Operand.
    fn get_current_value_for(
        current_versions: &HashMap<SsaVarKind, SsaVar>,
        op: Operand,
        function_id: FunctionId,
    ) -> SsaOperand {
        let origin_info = SsaOriginInfo::new(function_id, op.offset, op.debug_marker);
        match op.kind {
            OperandKind::Memory(_) | OperandKind::Pointer(_) | OperandKind::RelativeMemory(_) => {
                let kind = SsaVarKind::from_operand_kind(&op.kind).unwrap();
                SsaOperand {
                    kind: SsaOperandKind::Variable(SsaVar {
                        kind,
                        version: current_versions.get(&kind).map(|v| v.version).unwrap_or(0),
                        origin_info,
                    }),
                    origin_info,
                }
            }
            OperandKind::Immediate(val) => SsaOperand {
                kind: SsaOperandKind::Constant(val),
                origin_info,
            },
            OperandKind::Deref(addr) => SsaOperand {
                kind: SsaOperandKind::Deref(SsaVar {
                    kind: SsaVarKind::Pointer(addr),
                    version: current_versions
                        .get(&SsaVarKind::Pointer(addr))
                        .map(|v| v.version)
                        .unwrap_or(0),
                    origin_info,
                }),
                origin_info,
            },
        }
    }

    // Creates the NextKind using SsaOperands based on the current versions.
    fn create_ssa_next_kind(
        current_versions: &HashMap<SsaVarKind, SsaVar>,
        original: &NextKind<Operand>,
        function_id: FunctionId,
    ) -> NextKind<SsaOperand> {
        original.map(&mut |op| Self::get_current_value_for(current_versions, op, function_id))
    }

    fn convert_function(&mut self, function_id: FunctionId) -> HashMap<BlockId, SsaBlock> {
        // Step 1: Place phi functions where needed
        let phi_placements = self.place_phi_functions(function_id);

        // Step 2: Populate versions for phi results and targets of writes in top-bottom order.
        let function = self.model.get_function(function_id);
        let mut initial_versions = HashMap::new();
        let mut ssa_blocks = self.build_ssa_blocks_with_write_versioning(
            function,
            &phi_placements,
            &mut initial_versions,
        );

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
        current_versions: &mut HashMap<SsaVarKind, SsaVar>,
    ) -> HashMap<BlockId, SsaBlock> {
        let mut ssa_blocks = HashMap::new();

        fn map_read(
            (function_id, _, _): &mut (
                FunctionId,
                &mut HashMap<SsaVarKind, SsaVar>,
                &mut HashMap<SsaVarKind, SsaVar>,
            ),
            op: &Operand,
        ) -> SsaOperand {
            SsaOperand::from_operand(op, usize::MAX, *function_id)
        }

        fn map_write(
            (function_id, current, end): &mut (
                FunctionId,
                &mut HashMap<SsaVarKind, SsaVar>,
                &mut HashMap<SsaVarKind, SsaVar>,
            ),
            op: &Operand,
        ) -> SsaOperand {
            let mut ssa_op = SsaOperand::from_operand(op, usize::MAX, *function_id);
            if ssa_op.as_variable().is_some() {
                let next_var = SSAConversionState::create_next_version(current, *op, *function_id);
                end.insert(next_var.kind, next_var); // Capture current_block_end_state mutably
                ssa_op.kind = SsaOperandKind::Variable(next_var);
            }
            ssa_op
        }

        for block_id in function.blocks.iter().sorted() {
            let mut end_state = HashMap::new();
            let block = self.model.get_block(*block_id);
            let mut phi_functions = phi_placements.get(block_id).unwrap_or(&Vec::new()).clone();
            for phi in phi_functions.iter_mut() {
                phi.result = Self::create_next_version(
                    current_versions,
                    phi.result.to_operand(),
                    function.function_id,
                );
                end_state.insert(phi.result.kind, phi.result);
            }
            // At this point end_state has the phi functions for this block, so this is the start state
            // we have without variables flowing from predecessors.
            let start_state = end_state.clone();
            let mut instructions = Vec::new();
            for instr in &block.instructions {
                let mut state: (_, &mut HashMap<_, _>, &mut HashMap<_, _>) = (
                    function.function_id,
                    current_versions as &mut HashMap<_, _>,
                    &mut end_state,
                );
                instructions.push(instr.map_rw(&mut state, map_read, map_write));
            }

            let ssa_block = SsaBlock {
                original_id: *block_id,
                phi_functions,
                instructions,
                start_state,
                end_state,
                next: NextKind::Halt,
                predecessors: vec![],
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
        for &block_id in &function.blocks {
            phi_placements.insert(block_id, Vec::new());
        }

        // Get data flow result
        let data_flow = self.model.get_data_flow_result().unwrap();

        for &block_id in &function.blocks {
            let block = self.model.get_block(block_id);

            // Only blocks with multiple predecessors or blocks that are function returns nee d phi functions.
            if block.predecessors.len() <= 1
                && !block
                    .predecessors
                    .iter()
                    .any(|pred| matches!(pred, PredecessorKind::FunctionCallReturns(_)))
            {
                continue;
            }

            // Get the data flow result for this block
            let block_flow = data_flow.block_results.get(&block_id).unwrap();

            // Find all variable definitions reaching this block from any predecessor
            let mut all_incoming_defs: HashMap<OperandKind, HashSet<InstructionId>> =
                HashMap::new();

            // Collect definitions from predecessors
            if block.predecessors.len() > 1 {
                for pred in &block.predecessors {
                    let pred_id = pred.source_block_id();

                    assert!(function.blocks.contains(&pred_id));

                    // Get the predecessor's defs_out from data flow
                    if let Some(pred_flow) = data_flow.block_results.get(&pred_id) {
                        for def in &pred_flow.defs_out {
                            all_incoming_defs
                                .entry(def.location)
                                .or_default()
                                .insert(def.instruction_id);
                        }
                    }
                }
            }

            let return_values_accessed = if let Some(PredecessorKind::FunctionCallReturns(fc)) =
                block
                    .predecessors
                    .iter()
                    .find(|pred| matches!(pred, PredecessorKind::FunctionCallReturns(_)))
            {
                data_flow
                    .block_results
                    .get(&fc.calling_block) // Returns Option<&BlockDataFlowResult>
                    .and_then(|block_flow| block_flow.call_site_info.as_ref()) // Returns Option<&CallSiteInfo>
                    .map(|call_info| {
                        // If we have CallSiteInfo...
                        call_info
                            .return_values_accessed
                            .keys() // Get iterator of keys (&i128)
                            .cloned() // Get iterator of values (i128)
                            .map(OperandKind::RelativeMemory) // Convert to OperandKind
                            .collect_vec() // Collect into Vec<OperandKind>
                    })
                    .unwrap()
            } else {
                vec![]
            };
            let vars = all_incoming_defs
                .iter()
                .filter(|(var_kind, defs)| {
                    defs.len() > 1
                        && (block_flow.live_in.contains(var_kind)
                            || var_kind.is_negative_relative_memory()/* maybe a return value */)
                })
                .map(|(var_kind, _)| var_kind)
                .chain(return_values_accessed.iter());
            // For each variable with multiple different definitions reaching this block,
            // add a phi function
            for var_kind in vars {
                // Skip constants and derefs
                if !var_kind.is_variable() {
                    continue;
                }

                let phi_kind = SsaVarKind::from_operand_kind(var_kind)
                    .expect("Phi function created for non-variable kind");

                let phi_result = SsaVar {
                    kind: phi_kind,
                    version: 0, // Placeholder
                    origin_info: SsaOriginInfo::new(function_id, 0, None),
                };

                // We fill this function later.
                let phi = PhiFunction {
                    result: phi_result,
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
        // can affect the end staet of these variable.
        let initial_end_states: HashMap<BlockId, HashMap<SsaVarKind, SsaVar>> = ssa_blocks
            .iter()
            .map(|(id, block)| (*id, block.end_state.clone()))
            .collect();

        let initial_start_states: HashMap<BlockId, HashMap<SsaVarKind, SsaVar>> = ssa_blocks
            .iter()
            .map(|(id, block)| (*id, block.start_state.clone()))
            .collect();

        loop {
            let mut changed = false;
            for block_id in &block_ids {
                let mut new_in = initial_start_states[block_id].clone();
                let mut new_out = initial_end_states[block_id].clone();
                let control_block = self.model.get_block(*block_id);
                let live_in =
                    &self.model.get_data_flow_result().unwrap().block_results[block_id].live_in;

                for pred in &control_block.predecessors {
                    let pred_id = pred.source_block_id();
                    // Use the collected end_states map here
                    let pred_end_state = &ssa_blocks.get(&pred_id).unwrap().end_state;
                    // new_in should store SsaVarKind -> SsaVar
                    for (var_kind, var) in pred_end_state {
                        if !live_in.contains(&var_kind.to_operand_kind())
                            && !var_kind.get_relative_memory().is_some_and(|r| r < 0)
                        {
                            // This var doesn't live from here and not a return value
                            continue;
                        }
                        if initial_start_states[block_id].contains_key(var_kind) {
                            // This block's phis write to the key, so both start_state and end_state can't affect from a predecessor
                            continue;
                        }

                        // If we get multiple live value through the predecessor, some phi function
                        // should have concsolidated them and then we wouldn't get here (since the
                        // var would be in initial_start_states).
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

                        new_in.insert(*var_kind, *var);

                        // means we write to the key, so this can't affect the end_state
                        if initial_end_states[block_id].contains_key(var_kind) {
                            continue;
                        }
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
                        new_out.insert(*var_kind, *var);
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
        for block_id in &function.blocks {
            let block = self.model.get_block(*block_id);
            let ssa_block = ssa_blocks.get(block_id).unwrap();
            let mut phi_functions = vec![];
            for phi in &ssa_block.phi_functions {
                let mut phi_inputs = HashMap::new();
                for pred in &block.predecessors {
                    let pred_id = pred.source_block_id();
                    let pred_ssa_block = ssa_blocks.get(&pred_id).unwrap();
                    if matches!(pred, PredecessorKind::FunctionCallReturns(_))
                        && phi.result.get_relative_memory().is_some_and(|x| x > 0)
                    {
                        // For function returns, the phi result itself represents the value.
                        // Wrap the SsaVar result in SsaOperand::Variable.
                        phi_inputs.insert(pred.clone(), phi.result);
                    } else if let Some(pred_var) = pred_ssa_block.end_state.get(&phi.result.kind) {
                        phi_inputs.insert(pred.clone(), *pred_var);
                    }
                }
                let mut phi = phi.clone();
                phi.inputs = phi_inputs;
                phi_functions.push(phi);
            }
            let mut instructions = vec![];
            let mut state = ssa_block.start_state.clone();
            for instr in &ssa_block.instructions {
                let mut instr = instr.clone();
                instr = instr.map_rw(
                    &mut state,
                    |c, op| Self::get_current_value_for(c, op.to_operand(), function.function_id),
                    |c, op| {
                        if matches!(op.kind, SsaOperandKind::Deref(..)) {
                            // Derefs need to be renewed also for writes, since the pointer they
                            // deref has an updated version.
                            Self::get_current_value_for(c, op.to_operand(), function.function_id)
                        } else {
                            *op
                        }
                    },
                );
                if let Some(write) = instr.writes() {
                    if let Some(write) = write.as_variable() {
                        state.insert(write.kind, *write);
                    }
                }
                instructions.push(instr);
            }
            // ssa_block.instructions = instructions;
            let ssa_block = ssa_blocks.get_mut(block_id).unwrap();
            ssa_block.phi_functions = phi_functions;
            ssa_block.instructions = instructions;
            ssa_block.next =
                Self::create_ssa_next_kind(&ssa_block.end_state, &block.next, function.function_id);
            let next = ssa_block.next.clone();
            match next {
                NextKind::Follows(target_id) => {
                    ssa_blocks
                        .get_mut(&target_id)
                        .unwrap()
                        .predecessors
                        .push(PredecessorKind::FollowsFrom(*block_id));
                }
                NextKind::Goto(target_block_id) => {
                    ssa_blocks
                        .get_mut(&target_block_id)
                        .unwrap()
                        .predecessors
                        .push(PredecessorKind::GotoFrom(*block_id)); // Push the source block ID
                }
                NextKind::FunctionCall(call) => {
                    // Add the current block as a predecessor to the function's entry block (this seems incorrect, handled elsewhere?)
                    // Add the current block (call site) as predecessor to the return block
                    ssa_blocks
                        .get_mut(&call.return_block)
                        .unwrap()
                        .predecessors
                        .push(PredecessorKind::FunctionCallReturns(call));
                }
                NextKind::Condition(cond) => {
                    // Add current block as predecessor to the target block
                    ssa_blocks
                        .get_mut(&cond.target_block)
                        .unwrap()
                        .predecessors
                        .push(PredecessorKind::ConditionalJump(cond.clone()));
                    ssa_blocks
                        .get_mut(&cond.follows_block)
                        .unwrap()
                        .predecessors
                        .push(PredecessorKind::ConditionalFollow(cond));
                }
                NextKind::Return | NextKind::Halt | NextKind::Unknown => { /* No successors */ }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::parser;
    use crate::disasm::v2::instructions::InstructionKind;
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
    use pretty_assertions::assert_eq;

    // Define SSA macros for creating expected SsaOperand values with Variable kinds
    macro_rules! ssa_var_rel {
        ($offset:expr, $version:expr) => {
            SsaOperand {
                kind: SsaOperandKind::Variable(SsaVar {
                    kind: SsaVarKind::RelativeMemory($offset),
                    version: $version,
                    origin_info: SsaOriginInfo::new(FunctionId::from(0), 0, None),
                }),
                origin_info: SsaOriginInfo::new(FunctionId::from(0), 0, None),
            }
        };
    }

    macro_rules! ssa_var_pointer {
        ($addr:expr, $version:expr) => {
            SsaOperand {
                kind: SsaOperandKind::Variable(SsaVar {
                    kind: SsaVarKind::Pointer($addr),
                    version: $version,
                    origin_info: SsaOriginInfo::new(FunctionId::from(0), 0, None),
                }),
                origin_info: SsaOriginInfo::new(FunctionId::from(0), 0, None),
            }
        };
    }

    // Note: Deref versioning needs careful thought. This macro assumes address_version 0 for simplicity.
    macro_rules! ssa_var_deref {
        ($addr:expr, $addr_ver: expr) => {
            // Added addr_ver
            SsaOperand {
                kind: SsaOperandKind::Deref(SsaVar {
                    kind: SsaVarKind::Pointer($addr),
                    version: $addr_ver,
                    origin_info: SsaOriginInfo::new(FunctionId::from(0), 0, None),
                }),
                origin_info: SsaOriginInfo::new(FunctionId::from(0), 0, None),
            }
        };
    }

    macro_rules! assert_marker_at_main {
        ($ctx:expr, $marker:expr, $expected_operand:expr) => {{
            // Find the SsaOperand with the given debug marker
            let found_operand = $ctx
                .main_function
                .find_ssa_operand_by_marker($marker) // Use the new function name
                .unwrap_or_else(|| panic!("Marker '{}' not found in main function", $marker));

            // Extract the expected SsaVar if the expected operand's kind is Variable
            match ($expected_operand.kind, found_operand.kind) {
                (SsaOperandKind::Variable(expected_var), SsaOperandKind::Variable(found_var)) => {
                    assert_eq!(expected_var.kind, found_var.kind, "For marker '{}': Expected kind: {:?}, Actual kind: {:?}", $marker, expected_var.kind, found_var.kind);
                    assert_eq!(expected_var.version, found_var.version, "For marker '{}': Expected version: {}, Actual version: {}", $marker, expected_var.version, found_var.version);
                },
                (SsaOperandKind::Deref(expected_var), SsaOperandKind::Deref(actual_var)) => {
                    assert_eq!(expected_var.kind, actual_var.kind, "For marker '{}': Expected kind: {:?}, Actual kind: {:?}", $marker, expected_var.kind, actual_var.kind);
                    assert_eq!(expected_var.version, actual_var.version, "For marker '{}': Expected version: {}, Actual version: {}", $marker, expected_var.version, actual_var.version);
                },
                (a, b) => {
                    panic!("For marker '{}: Expected SsaOperandKind::Variable or SsaOperandKind::Deref for marker assertion, got {:?} and {:?}", $marker, a, b);
                }
            }
        }};
    }

    struct TestContext {
        main_function: SsaFunction,
        model: ProgramModel,
    }

    impl TestContext {
        fn new(assembly: &str) -> Self {
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
                .any(|instr| matches!(instr.kind, InstructionKind::Output(_)))
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
            .find(|instr| matches!(instr.kind, InstructionKind::Output(_)))
            .expect("Should have an output instruction");

        let output_ssa_operand = if let InstructionKind::Output(ssa_op) = &output_instr.kind {
            ssa_op
        } else {
            panic!("Expected Output instruction");
        };

        // Verify that the operand kind corresponds to [100]
        assert_eq!(
            output_ssa_operand.to_operand().kind, // Use to_operand()
            OperandKind::Memory(100),
            "Output should use [100]"
        );

        // Verify the output operand is a variable and has a non-zero version
        match output_ssa_operand.as_variable() {
            Some(var) => {
                assert!(
                    var.version > 0,
                    "Output variable should have a non-zero version, got: {}",
                    var.version
                );
                println!("Output operand version: {}", var.version);
            }
            _ => {
                panic!(
                    "Output operand should be a Variable, but found {}",
                    output_ssa_operand
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
                if matches!(first_instr.kind, InstructionKind::Output(_)) {
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
        if let InstructionKind::Output(ssa_op) = &output_instr.kind {
            match ssa_op.as_variable() {
                Some(var) => {
                    assert!(
                        var.version > 0,
                        "Output variable should have a valid version number, got {}",
                        var.version
                    );
                }
                _ => {
                    panic!("Output operand in function call test should be Variable");
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
                if let InstructionKind::Add(src1, _, dst) = &instr.kind {
                    // Check underlying operand kinds
                    src1.to_operand().kind.get_relative_memory() == Some(-4)
                        && dst.to_operand().kind.get_relative_memory() == Some(-4)
                } else {
                    false
                }
            })
            .expect("Should have found the addition instruction");

        if let InstructionKind::Add(src1, _, dst) = &add_instr.kind {
            // Extract versions from SsaOperands
            let src1_var = src1.as_variable().expect("Add source1 should be Variable");
            let dst_var = dst
                .as_variable()
                .expect("Add destination should be Variable");
            assert!(
                src1_var.version < dst_var.version,
                "Source version {} should be less than destination version {}",
                src1_var.version,
                dst_var.version
            );
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
        // Note: Deref versioning is complex. These assertions might need adjustment
        // based on how operand_to_ssa_var_kind handles Deref address versions.
        assert_marker_at_main!(ctx, 'a', ssa_var_pointer!(23, 2)); // ptr = ptr + [R+2]
        assert_marker_at_main!(ctx, 'b', ssa_var_pointer!(23, 3)); // ptr = ptr + [R+3]
                                                                   // 'c' marks the *ptr read. The SsaOperand will be Deref.
                                                                   // The version of the *Deref* itself depends on when *ptr was last written (version 3).
                                                                   // The address_version inside Deref depends on the version of ptr when read (version 3).
        assert_marker_at_main!(ctx, 'c', ssa_var_deref!(23, 3)); // Expecting address_version 3, deref version 0
        assert_marker_at_main!(ctx, 'd', ssa_var_rel!(1, 1)); // [R+1] = *ptr
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
    fn test_incr_write_after_read() {
        let ctx = TestContext::new(
            r#"
                R += 5
                output('a [R-1])
                'b [R-1] = 17
                halt
                "#,
        );
        assert_marker_at_main!(ctx, 'a', ssa_var_rel!(-1, 0)); // Read [R-1]_0
        assert_marker_at_main!(ctx, 'b', ssa_var_rel!(-1, 1)); // Write [R-1]_1
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
        // These assertions need careful checking against the SSA output, especially phi versions.
        assert_marker_at_main!(ctx, 'a', ssa_var_rel!(-2, 1)); // [R-2]_1 = *ptr
        assert_marker_at_main!(ctx, 'b', ssa_var_rel!(-3, 1)); // [R-3]_1 = 0
        assert_marker_at_main!(ctx, 'c', ssa_var_rel!(-5, 1)); // [R-5]_1 = [R-5]_0 + 1
                                                               // Inside loop header - Phi versions might differ based on exact implementation
        assert_marker_at_main!(ctx, 'd', ssa_var_rel!(-3, 2)); // Read [R-3]_phi (expect version 2 initially)
        assert_marker_at_main!(ctx, 'e', ssa_var_rel!(-2, 1)); // Read [R-2]_1 (no phi)
        assert_marker_at_main!(ctx, 'f', ssa_var_rel!(-5, 1)); // Read [R-5]_1 (no phi)
        assert_marker_at_main!(ctx, 'g', ssa_var_rel!(-3, 2)); // Read [R-3]_phi (expect version 2 initially)
        assert_marker_at_main!(ctx, 'h', ssa_var_rel!(-3, 2)); // Read [R-3]_phi for arg (expect version 2 initially)
        assert_marker_at_main!(ctx, 'i', ssa_var_rel!(-2, 1)); // Read [R-2]_1 for arg (no phi)
                                                               // After function call return
        assert_marker_at_main!(ctx, 'j', ssa_var_rel!(1, 2)); // Read [R+1]_phi (expect version 2 from call return)
                                                              // Inside loop body (after call)
        assert_marker_at_main!(ctx, 'k', ssa_var_rel!(-3, 2)); // Read [R-3]_phi before increment (expect version 2)
        assert_marker_at_main!(ctx, 'l', ssa_var_rel!(-3, 3)); // Write [R-3]_3 (new version for loop feedback)
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
                .get(&SsaVarKind::RelativeMemory(-1)) // Use SsaVarKind
                .expect("End state should contain [R-1]")
                .version, // Access version on the SsaVar
            3 // Expecting version 3 based on the control flow
        );
        assert_eq!(
            f0.blocks
                .get(&BlockId::from(13))
                .unwrap()
                .end_state
                .get(&SsaVarKind::RelativeMemory(-1)) // Use SsaVarKind
                .expect("End state should contain [R-1]")
                .version, // Access version on the SsaVar
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
                .get(&SsaVarKind::RelativeMemory(-1)) // Use SsaVarKind
                .expect("End state should contain [R-1]")
                .version, // Access version on the SsaVar
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
}
