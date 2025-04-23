use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use disjoint_set::{DisjointSet, SetId};
use itertools::Itertools;

use crate::disasm::v2::model::FunctionId;
use crate::disasm::v2::ssa_form::SsaFunction;
use crate::disasm::{
    v2::{
        dispatching::{EventCollector, EventListener},
        events::Event,
        id_types::define_id_type,
        instructions::{GenericInstruction, InstructionKind},
        model::{BlockId, ProgramModel},
        ssa_form::{SsaBlock, SsaOperand, SsaVar, SsaVarKind},
        type_inference::{
            types::{Type, VariableKind},
            visuals::TraceColors,
        },
    },
    Error,
};

mod disjoint_set;

define_id_type!(ClusterId);

/// A Variable cluster represents different versions of the same variable across a program
#[derive(Debug, Clone)]
pub struct VariableCluster {
    /// Unique identifier for this cluster
    pub id: ClusterId,

    /// Low-level representable name for this cluster
    pub cluster_name: String,

    /// All SSA variables that are part of this cluster
    pub ssa_variables: HashSet<SsaVar>,
    /// The inferred type of this cluster
    pub inferred_type: Type,
}

#[derive(Debug, Clone)]
pub struct VariableMergerResult {
    /// Collection of all clusters
    pub clusters: HashMap<ClusterId, VariableCluster>,

    pub variable_to_cluster: HashMap<SsaVar, ClusterId>,
}

/// Analyzes SSA form to create variable clusters that merge different versions of the same variable
pub struct VariableMerger<'a> {
    model: &'a ProgramModel,
    /// Maps SSA variable to the cluster it belongs to
    variable_to_cluster: HashMap<SsaVar, ClusterId>,
    /// Collection of all clusters
    clusters: HashMap<ClusterId, VariableCluster>,
    /// Next available cluster ID
    next_cluster_id: usize,

    function_state: HashMap<FunctionId, FunctionVarNamingState>,
}

struct FunctionVarNamingState {
    next_input: usize,
    next_output: usize,
    next_pointer: usize,
    next_function: usize,
    next_local: usize,
}

impl FunctionVarNamingState {
    fn new() -> FunctionVarNamingState {
        FunctionVarNamingState {
            next_input: 1,
            next_output: 1,
            next_pointer: 1,
            next_function: 1,
            next_local: 1,
        }
    }
}

impl<'a> VariableMerger<'a> {
    /// Creates a new VariableclusterAnalyzer
    pub fn new(model: &'a ProgramModel) -> VariableMerger<'a> {
        VariableMerger {
            variable_to_cluster: HashMap::new(),
            clusters: HashMap::new(),
            function_state: HashMap::new(),
            next_cluster_id: 0,
            model,
        }
    }

    fn build_clusters(&mut self) -> Result<(), Error> {
        let mut ds: DisjointSet<SsaVar> = DisjointSet::new();
        let mut globals = HashMap::new();
        let ssa_result = self.model.get_ssa_result().unwrap();
        // Process all functions
        for function in ssa_result.functions.values() {
            // Initialize clusters based on Phi nodes
            Self::initialize_clusters_from_phi_nodes(&function.blocks, &mut ds);

            // Merge clusters based on data flow
            Self::merge_clusters_based_on_data_flow(&self.model, function, &mut ds, &mut globals);
        }
        let mut processed_sets = HashSet::new();
        loop {
            let mut changed = false;
            for (set_id, vars) in ds
                .iter()
                .sorted_by_key(|(_, v)| v.iter().min().unwrap().version)
            {
                if processed_sets.contains(set_id) {
                    continue;
                }
                let name = self.generate_cluster_name(set_id, vars, &globals);
                if name.is_none() {
                    continue;
                }
                let name = name.unwrap();
                let c = VariableCluster {
                    id: self.next_id(),
                    cluster_name: name,
                    ssa_variables: vars.clone(),
                    inferred_type: self.infer_type(vars),
                };
                let id = c.id;
                self.clusters.insert(c.id, c);
                self.variable_to_cluster
                    .extend(vars.iter().map(|v| (v.clone(), id)));
                processed_sets.insert(*set_id);
                changed = true;
            }
            if !changed {
                break;
            }
        }
        Ok(())
    }

    /// Generate a new unique cluster ID
    fn next_id(&mut self) -> ClusterId {
        let id = self.next_cluster_id;
        self.next_cluster_id += 1;
        ClusterId::from(id)
    }

    fn are_same_location(var1: &SsaVar, var2: &SsaVar) -> bool {
        match var1.kind {
            SsaVarKind::RelativeMemory(_) | SsaVarKind::Memory(_) | SsaVarKind::Pointer(_) => {
                var1.kind == var2.kind
            }
        }
    }

    fn related_from_instruction<'b>(
        model: &ProgramModel,
        function_id: FunctionId,
        instruction: &'b GenericInstruction<SsaOperand>,
    ) -> Option<(&'b SsaVar, &'b SsaVar)> {
        match &instruction.kind {
            InstructionKind::Add(a, b, c) => {
                match (a.as_variable(), b.as_variable(), c.as_variable()) {
                    (Some(a), _, Some(c)) if Self::are_same_location(a, c) => Some((a, c)),
                    (_, Some(b), Some(c)) if Self::are_same_location(b, c) => Some((b, c)),
                    _ => None,
                }
            }
            InstructionKind::Mul(a, b, c) => {
                match (a.as_variable(), b.as_variable(), c.as_variable()) {
                    (Some(a), Some(b), Some(c))
                        if Self::are_same_location(a, c) && !Self::are_same_location(b, c) =>
                    {
                        Some((a, c))
                    }
                    (Some(a), Some(b), Some(c))
                        if Self::are_same_location(b, c) && !Self::are_same_location(a, c) =>
                    {
                        Some((b, c))
                    }
                    _ => None,
                }
            }
            InstructionKind::Assign(a, b) => a
                .as_variable()
                .zip(b.as_variable())
                .filter(|(a, _)| a.get_relative_memory() != Some(0))
                .filter(|(a, b)| Self::are_related(model, function_id, a, b)),
            _ => None,
        }
    }

    /// Initialize clusters based on phi nodes, which show where variables merge
    fn initialize_clusters_from_phi_nodes(
        blocks: &HashMap<BlockId, SsaBlock>,
        ds: &mut DisjointSet<SsaVar>,
    ) {
        // Process each block
        for block in blocks.values() {
            // Process phi functions
            for phi in &block.phi_functions {
                let target = &phi.result;
                let mut set_id = ds.insert(*target);

                // Add input to the same cluster
                for input in phi.inputs.values() {
                    set_id = ds.insert_join(&set_id, *input);
                }
            }
        }
    }

    /// Merge clusters based on data flow relationships
    fn merge_clusters_based_on_data_flow(
        model: &ProgramModel,
        function: &SsaFunction,
        ds: &mut DisjointSet<SsaVar>,
        globals: &mut HashMap<usize, SetId>,
    ) {
        let mut insert_var = |ds: &mut DisjointSet<SsaVar>, v: &SsaOperand| {
            let Some(v) = v.as_variable() else {
                return;
            };
            if v.get_relative_memory() == Some(0) {
                return;
            }
            if let Some(addr) = Self::global_memory(model, v) {
                if let Some(set_id) = globals.get(&addr) {
                    globals.insert(addr, ds.insert_join(&set_id, *v));
                } else {
                    globals.insert(addr, ds.insert(*v));
                }
            }
            ds.insert(*v);
        };

        let blocks = model
            .get_ssa_result()
            .unwrap()
            .functions
            .get(&function.original_id)
            .unwrap()
            .blocks
            .clone();
        // Process each block to find data flow relationships
        for block in blocks.values() {
            for instr in &block.instructions {
                for i in instr.reads() {
                    insert_var(ds, &i);
                }
                if let Some(v) = instr.writes() {
                    insert_var(ds, &v);
                }
                if let Some((v1, v2)) =
                    Self::related_from_instruction(model, function.original_id, instr)
                {
                    ds.join(*v1, *v2);
                    println!("Related: {} and {}", v1, v2);
                }
            }
        }
    }

    /// Get the cluster for a specific SSA variable
    pub fn get_cluster_for_variable(&self, variable: &SsaVar) -> Option<&VariableCluster> {
        self.variable_to_cluster
            .get(&variable)
            .and_then(|&cluster_id| self.clusters.get(&cluster_id))
    }

    fn generate_cluster_name(
        &mut self,
        set_id: &SetId,
        vars: &HashSet<SsaVar>,
        globals: &HashMap<usize, SetId>,
    ) -> Option<String> {
        let rep = vars.iter().next().unwrap();
        let function_id = rep.origin_info.function_id;
        let params = &self
            .model
            .get_function_call_analysis()
            .unwrap()
            .callee_info
            .get(&function_id)
            .unwrap()
            .parameter_entry_vars;
        let state = self
            .function_state
            .entry(function_id)
            .or_insert_with(|| FunctionVarNamingState::new());
        let name = if globals.values().contains(set_id) {
            let addr = Self::global_memory(self.model, &rep).unwrap();
            format!("Global{}", addr)
        } else if let Some(_) = vars.iter().find_map(|v| v.kind.get_pointer()) {
            let n = state.next_pointer;
            state.next_pointer += 1;
            format!("ptr{}", n)
        } else if let Some(_) = vars
            .iter()
            .find(|v| matches!(v.kind, SsaVarKind::Memory(_)))
        {
            unreachable!("Memory variables are either pointers or globals at this point.");
        } else if vars.iter().any(|v| params.values().contains(v)) {
            let n = state.next_input;
            state.next_input += 1;
            format!("arg{}", n)
        } else {
            let n = state.next_local;
            state.next_local += 1;
            format!("local{}", n)
        };
        Some(name)
    }

    fn infer_type(&self, vars: &HashSet<SsaVar>) -> Type {
        let ti = self.model.get_type_inference_result().unwrap();
        println!("Inferring type for {:?}", vars);
        ti.get_type_for_ssavar(vars.iter().next().unwrap())
            .unwrap()
            .clone()
    }

    fn global_memory(model: &ProgramModel, v: &SsaVar) -> Option<usize> {
        let data_segments = &model.get_image_scanner_result().data_segments;
        match v.kind {
            SsaVarKind::Memory(addr) => data_segments
                .iter()
                .any(|s| s.contains_address(addr as usize))
                .then(|| addr as usize),
            _ => None,
        }
    }

    fn are_related(model: &ProgramModel, _function_id: FunctionId, a: &SsaVar, b: &SsaVar) -> bool {
        if let Some(addr) = Self::global_memory(model, a) {
            return Self::global_memory(model, b) == Some(addr);
        }
        if Self::global_memory(model, b).is_some() {
            return false;
        }
        return true;
    }
}

pub struct VariableAnalyzer {}

impl VariableAnalyzer {
    pub fn new() -> Self {
        VariableAnalyzer {}
    }
}

impl EventListener<Event, ProgramModel> for VariableAnalyzer {
    fn on_event(
        &mut self,
        model: &mut ProgramModel,
        event: Event,
        _collector: &mut EventCollector<Event>,
    ) -> Result<(), Error> {
        // Only process the event that indicates SSA conversion is complete
        match event {
            Event::TypeInferenceComplete(_) => {
                println!("Creating variable clusters");
                // Create variable clusters
                let mut merger = VariableMerger::new(&model);
                merger.build_clusters()?;

                // Store the result in the model
                for cluster in merger.clusters.values() {
                    println!(
                        "cluster for {}: {:?}:",
                        cluster.cluster_name, cluster.inferred_type,
                    );
                    for var in &cluster.ssa_variables {
                        print!(
                            "{}, ",
                            TraceColors::format_var(&VariableKind::from_ssavar(&var))
                        )
                    }
                    println!();
                }
                model.set_variable_merger_result(VariableMergerResult {
                    variable_to_cluster: merger.variable_to_cluster,
                    clusters: merger.clusters,
                })
            }
            _ => {}
        }
        Ok(())
    }
}
