use std::collections::{HashMap, HashSet};

use itertools::Itertools;

use crate::disasm::{
    v3::{
        control_flow::FunctionView,
        define_id_type,
        lir::{Instruction, MemoryReferenceInfo},
        model::{Model, TypeInferenceComplete, VariableMergerComplete},
        ssa::{types::VersionableMemoryKind, SsaMemoryReference, VersionedMemoryReference},
        type_inference::Type,
        FunctionId,
    },
    Error,
};

use super::disjoint_set::{DisjointSet, SetId};

define_id_type!(ClusterId);

/// A Variable cluster represents different versions of the same variable across a program
#[derive(Debug, Clone)]
pub struct VariableCluster {
    /// Unique identifier for this cluster
    pub id: ClusterId,

    /// Low-level representable name for this cluster
    pub cluster_name: String,

    /// All SSA variables that are part of this cluster
    pub ssa_variables: HashSet<VersionedMemoryReference>,
    /// The inferred type of this cluster
    pub inferred_type: Type,
}

#[derive(Debug, Clone)]
pub struct VariableMergerResult {
    /// Collection of all clusters
    pub clusters: HashMap<ClusterId, VariableCluster>,

    pub variable_to_cluster: HashMap<VersionedMemoryReference, ClusterId>,
}

/// Analyzes SSA form to create variable clusters that merge different versions of the same variable
pub struct VariableMerger {
    // <'a> {
    // model: &'a ProgramModel,
    /// Maps SSA variable to the cluster it belongs to
    variable_to_cluster: HashMap<VersionedMemoryReference, ClusterId>,
    /// Collection of all clusters
    clusters: HashMap<ClusterId, VariableCluster>,
    /// Next available cluster ID
    next_cluster_id: usize,

    function_state: HashMap<FunctionId, FunctionVarNamingState>,
    model: Model<TypeInferenceComplete>,
}

#[expect(dead_code)]
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

impl VariableMerger {
    /// Creates a new VariableclusterAnalyzer
    fn new(model: Model<TypeInferenceComplete>) -> VariableMerger {
        VariableMerger {
            variable_to_cluster: HashMap::new(),
            clusters: HashMap::new(),
            function_state: HashMap::new(),
            next_cluster_id: 0,
            model,
        }
    }

    pub fn run(
        model: Model<TypeInferenceComplete>,
    ) -> Result<Model<VariableMergerComplete>, Error> {
        let mut merger = Self::new(model);
        merger.build_clusters()?;

        Ok(merger.result())
    }

    fn build_clusters(&mut self) -> Result<(), Error> {
        let mut ds: DisjointSet<VersionedMemoryReference> = DisjointSet::new();
        let mut globals = HashMap::new();
        // Process all functions
        for (_, function) in self.model.functions() {
            // Initialize clusters based on Phi nodes
            Self::initialize_clusters_from_phi_nodes(function, &mut ds);

            // Merge clusters based on data flow
            self.merge_clusters_based_on_data_flow(function, &mut ds, &mut globals);
        }
        let mut processed_sets = HashSet::new();
        loop {
            let mut changed = false;
            for (set_id, vars) in ds.iter().sorted_by_key(|(_, v)| {
                v.iter()
                    .min_by_key(|v| v.as_stack_relative().map(|v| (1, v)).unwrap_or((0, 0)))
            }) {
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
                    .extend(vars.iter().map(|v| (*v, id)));
                processed_sets.insert(*set_id);
                changed = true;
            }
            if !changed {
                break;
            }
        }
        Ok(())
    }

    fn result(self) -> Model<VariableMergerComplete> {
        self.model
            .with_variable_merger_result(VariableMergerResult {
                variable_to_cluster: self.variable_to_cluster,
                clusters: self.clusters,
            })
    }

    /// Generate a new unique cluster ID
    fn next_id(&mut self) -> ClusterId {
        let id = self.next_cluster_id;
        self.next_cluster_id += 1;
        ClusterId::from(id)
    }

    /// Initialize clusters based on phi nodes, which show where variables merge
    fn initialize_clusters_from_phi_nodes(
        function: FunctionView<'_, TypeInferenceComplete>,
        ds: &mut DisjointSet<VersionedMemoryReference>,
    ) {
        // Process each block
        for (_, block) in function.blocks() {
            // Process phi functions
            for phi in &block.ssa().phi_functions {
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
        &self,
        function: FunctionView<'_, TypeInferenceComplete>,
        ds: &mut DisjointSet<VersionedMemoryReference>,
        globals: &mut HashMap<usize, SetId>,
    ) {
        let mut insert_var = |ds: &mut DisjointSet<VersionedMemoryReference>,
                              v: VersionedMemoryReference| {
            if v.kind == VersionableMemoryKind::RelativeMemory(0) {
                return;
            }
            if let Some(addr) = v.kind.as_memory() {
                if let Some(set_id) = globals.get(&addr) {
                    globals.insert(*addr, ds.insert_join(set_id, v));
                } else {
                    globals.insert(*addr, ds.insert(v));
                }
            }
            ds.insert(v);
        };

        // Process each block to find data flow relationships
        for (_, block) in function.blocks() {
            for instr in &block.folded_ssa().instructions {
                let Instruction::Assign { ref target, .. } = instr.kind else {
                    continue;
                };
                let reads = instr
                    .kind
                    .collect_read_addresses()
                    .iter()
                    .filter_map(|v| v.as_versioned())
                    .collect_vec();
                for i in &reads {
                    insert_var(ds, **i);
                }
                if let Some(target) = target.as_versioned() {
                    insert_var(ds, *target);
                    for r in reads.iter().filter(|r| r.kind == target.kind) {
                        ds.join(*target, **r);
                    }
                }
            }
        }
    }

    fn generate_cluster_name(
        &mut self,
        set_id: &SetId,
        vars: &HashSet<VersionedMemoryReference>,
        globals: &HashMap<usize, SetId>,
    ) -> Option<String> {
        let rep = vars.iter().next().unwrap();
        let function_id = rep.function_id;
        let params = &self
            .model
            .function(&function_id)
            .callee_info()
            .parameter_entry_vars;
        let state = self
            .function_state
            .entry(function_id)
            .or_insert_with(FunctionVarNamingState::new);
        let name = if globals.values().contains(set_id) {
            let addr = rep.as_global().unwrap();
            format!("Global{}", addr)
        } else if vars.iter().find_map(|v| v.kind.as_pointer()).is_some() {
            let n = state.next_pointer;
            state.next_pointer += 1;
            format!("ptr{}", n)
        } else if vars.iter().any(|v| v.kind.as_memory().is_some()) {
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

    fn infer_type(&self, vars: &HashSet<VersionedMemoryReference>) -> Type {
        let ti = self.model.type_inference_result();
        let rep = vars.iter().max().unwrap();
        ti.get_type_for(&SsaMemoryReference::Versioned(rep.clone()))
    }

    fn global_memory(v: &SsaMemoryReference) -> Option<usize> {
        v.as_versioned().and_then(|v| v.kind.as_memory()).cloned()
    }

    fn are_related(a: &SsaMemoryReference, b: &SsaMemoryReference) -> bool {
        if let Some(addr) = Self::global_memory(a) {
            return Self::global_memory(b) == Some(addr);
        }
        if Self::global_memory(b).is_some() {
            return false;
        }
        true
    }
}
