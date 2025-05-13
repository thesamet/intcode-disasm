

// mod disjoint_set;

// define_id_type!(ClusterId);

/*
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
pub struct VariableMerger {
    // <'a> {
    // model: &'a ProgramModel,
    /// Maps SSA variable to the cluster it belongs to
    variable_to_cluster: HashMap<SsaVar, ClusterId>,
    /// Collection of all clusters
    clusters: HashMap<ClusterId, VariableCluster>,
    /// Next available cluster ID
    next_cluster_id: usize,

    function_state: HashMap<FunctionId, FunctionVarNamingState>,
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
            Self::merge_clusters_based_on_data_flow(self.model, function, &mut ds, &mut globals);
        }
        let mut processed_sets = HashSet::new();
        loop {
            let mut changed = false;
            for (set_id, vars) in ds.iter().sorted_by_key(|(_, v)| {
                v.iter().min_by_key(|v| {
                    v.get_relative_memory()
                        .map(|v| (1, v))
                        .unwrap_or((0, v.origin_info.offset as i128))
                })
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
        instruction: &'b GenericNativeInstruction<SsaOperand>,
    ) -> Option<(&'b SsaVar, &'b SsaVar)> {
        match &instruction.kind {
            NativeInstructionKind::Add(a, b, c) => {
                match (a.as_variable(), b.as_variable(), c.as_variable()) {
                    (Some(a), _, Some(c)) if Self::are_same_location(a, c) => Some((a, c)),
                    (_, Some(b), Some(c)) if Self::are_same_location(b, c) => Some((b, c)),
                    _ => None,
                }
            }
            NativeInstructionKind::Mul(a, b, c) => {
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
            NativeInstructionKind::Assign(a, b) => a
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
                let target = &phi.native_result;
                let mut set_id = ds.insert(*target);

                // Add input to the same cluster
                for input in phi.native_inputs.values() {
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
                    globals.insert(addr, ds.insert_join(set_id, *v));
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
            for instr in &block.native_instructions {
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
                }
            }
        }
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
            .or_insert_with(FunctionVarNamingState::new);
        let name = if globals.values().contains(set_id) {
            let addr = Self::global_memory(self.model, rep).unwrap();
            format!("Global{}", addr)
        } else if vars.iter().find_map(|v| v.kind.get_pointer()).is_some() {
            let n = state.next_pointer;
            state.next_pointer += 1;
            format!("ptr{}", n)
        } else if vars.iter().any(|v| matches!(v.kind, SsaVarKind::Memory(_))) {
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
        let rep = vars.iter().max().unwrap();
        ti.get_type_for_ssavar(rep)
            .unwrap_or_else(|| {
                pretty_print_ssa(self.model);
                panic!("Type inference unavailable for {:?}", rep)
            })
            .clone()
    }

    fn global_memory(model: &ProgramModel, v: &SsaVar) -> Option<usize> {
        let data_segments = &model.get_image_scanner_result().data_segments;
        match v.kind {
            SsaVarKind::Memory(addr) => data_segments
                .iter()
                .any(|s| s.contains_address(addr))
                .then_some(addr),
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
        true
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
        collector: &mut EventCollector<Event>,
    ) -> Result<(), Error> {
        // Only process the event that indicates SSA conversion is complete
        if let Event::TypeInferenceComplete(_) = event {
            // Create variable clusters
            let mut merger = VariableMerger::new(model);
            merger.build_clusters()?;

            model.set_variable_merger_result(VariableMergerResult {
                variable_to_cluster: merger.variable_to_cluster,
                clusters: merger.clusters,
            });

            // Emit event to indicate variable analysis is complete
            collector.publish(VariableAnalysisComplete {});
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::disasm::{
        parser,
        v2::{
            dispatching::EventPublisher,
            events::Event,
            listeners::{
                control_flow_graph_builder::ControlFlowGraphBuilder,
                data_flow_analyzer::DataFlowAnalyzer, function_call_analyzer::FunctionCallAnalyzer,
                image_scanner::ImageScanner, ssa_converter::SsaConverter,
                variable_analyzer::VariableAnalyzer,
            },
            model::{FunctionId, ProgramModel},
            pretty_print::pretty_print_ssa,
            type_inference::TypeInferenceAnalyzer,
        },
    };

    struct TestContext {
        model: ProgramModel,
    }

    impl TestContext {
        fn new(assembly: &str) -> Self {
            let model = setup_analyzed_model(assembly);

            // Extract the main function (always at ID 0)
            TestContext { model }
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
        publisher.add_listener(Box::new(FunctionCallAnalyzer::new()));
        publisher.add_listener(Box::new(TypeInferenceAnalyzer::new()));
        publisher.add_listener(Box::new(VariableAnalyzer::new()));

        // Run the pipeline
        model.load_image(&binary, &mut publisher);
        publisher.process_events(&mut model).unwrap();

        model
    }

    #[test]
    fn test_negative_write_not_adding_arg() {
        let assembly = r#"
            R += 3
            [R-2] = 10
            R -= 3
            goto [R]
            "#;
        let ctx = TestContext::new(assembly);
        let call_info = ctx
            .model
            .get_function_call_analysis()
            .unwrap()
            .callee_info
            .get(&FunctionId::from(0))
            .unwrap();
        assert_eq!(call_info.parameter_entry_vars.len(), 0);
    }

    #[test]
    fn test_negative_write_multiple_paths() {
        let assembly = r#"
            R += 3
            [R-2] = 10
            [R] = @end
            goto @somefunc
            end:
            R -= 3
            goto [R]

        somefunc:
            R += 2
            R -= 2
            goto [R]
            "#;
        let ctx = TestContext::new(assembly);
        let call_info = ctx
            .model
            .get_function_call_analysis()
            .unwrap()
            .callee_info
            .get(&FunctionId::from(0))
            .unwrap();
        pretty_print_ssa(&ctx.model);
        assert_eq!(call_info.parameter_entry_vars.len(), 0);
    }

    #[test]
    fn test_negative_write_adding_arg_if_is_read() {
        let assembly = r#"
            R += 3
            [R-2] = [R-2] + 1
            R -= 3
            goto [R]
            "#;
        let ctx = TestContext::new(assembly);
        let call_info = ctx
            .model
            .get_function_call_analysis()
            .unwrap()
            .callee_info
            .get(&FunctionId::from(0))
            .unwrap();
        assert_eq!(call_info.parameter_entry_vars.len(), 1);
    }

    #[test]
    fn test_nested_if_else() {
        let _assembly = r#"
            R += 100                      ; 0: Initial R adjustment for main function
            [R-1] = 10                    ; 2: x = 10
            [R-2] = [R-1] < 5             ; 6: cond1 = (x < 5)
            if ![R-2] goto @else_outer    ; 10: if !cond1 goto else_outer

            ; Then branch of outer if
            [R-3] = [R-1] < 15            ; 13: cond2 = (x < 15)
            if ![R-3] goto @else_inner    ; 17: if !cond2 goto else_inner

            ; Then branch of inner if
            [R-4] = 1                     ; 20: result = 1
            goto @end_inner               ; 24:

            else_inner:
            ; Else branch of inner if
            [R-4] = 2                     ; 27: result = 2

            end_inner:
            goto @end_outer               ; 31:

            else_outer:
            ; Else branch of outer if
            [R-4] = 3                     ; 34: result = 3

            end_outer:
            output([R-4])                 ; 38: output(result)
            R -= 100                      ; 40:
            goto [R]                      ; 42:
        "#;

        let ctx = TestContext::new(_assembly);
        pretty_print_ssa(&ctx.model);
        let f_a = ctx.model.get_function_call_analysis().unwrap();
        assert_eq!(
            f_a.callee_info[&FunctionId::from(0)]
                .parameter_entry_vars
                .len(),
            0
        );
    }
}
*/
