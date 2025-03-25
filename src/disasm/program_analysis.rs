use std::collections::HashMap;

use super::{
    control_flow_graph::{BlockId, ControlFlowGraph, PredecessorKind},
    data_flow_analysis::GraphDataFlow,
    low_ir::Arg,
};

use itertools::Itertools;

pub struct FunctionInfo {
    pub start_block: BlockId,
    pub args: Vec<Arg>,        // from caller perspective
    pub return_vars: Vec<Arg>, // stack references for returned data from caller perspective
    pub local_vars: Vec<Arg>,  // local stack vars from callee perspective
}

pub struct ProgramAnalysis {
    pub control_flows: HashMap<BlockId, ControlFlowGraph<Arg>>,
    pub data_flows: HashMap<BlockId, GraphDataFlow<Arg>>,
    pub function_infos: HashMap<BlockId, FunctionInfo>,
    pub call_graph: HashMap<BlockId, Vec<BlockId>>,
}

fn function_call_analysis(
    control_flows: &HashMap<BlockId, ControlFlowGraph<Arg>>,
    data_flows: &HashMap<BlockId, GraphDataFlow<Arg>>,
) -> (
    HashMap<BlockId, FunctionInfo>,
    HashMap<BlockId, Vec<BlockId>>,
) {
    let mut function_infos: HashMap<BlockId, FunctionInfo> = HashMap::new();
    let mut call_graph: HashMap<BlockId, Vec<BlockId>> = HashMap::new();
    for (caller_id, caller_control_flow) in control_flows {
        let caller_data_flow = &data_flows[&caller_control_flow.start];
        for (block_id, block) in &caller_control_flow.blocks {
            let preds = &block.predecessors;
            let fc = preds.iter().find_map(|x| match x {
                PredecessorKind::FunctionCallReturns(fc) => Some(fc),
                _ => None,
            });

            let Some(fc) = fc else {
                continue;
            };

            let return_vars = caller_data_flow.block_defs[&block_id]
                .use_set
                .iter()
                .filter(|a| matches!(a, Arg::RelativeMem(r) if *r>0))
                .sorted()
                .copied()
                .collect_vec();
            let Some(callee_addr) = fc.function_addr.value() else {
                continue; // non-literal address
            };

            let callee_block = (callee_addr as usize).into();
            let callee_data_flow = &data_flows[&callee_block].block_defs[&callee_block];
            let callee_stack_size = control_flows[&callee_block].stack_size;

            let args = callee_data_flow
                .live_in
                .iter()
                .filter_map(|f| match f {
                    Arg::RelativeMem(r) if *r < 0 => {
                        Some(Arg::RelativeMem((callee_stack_size as i128) + *r))
                    }
                    _ => None,
                })
                .sorted()
                .collect_vec();
            let fi = FunctionInfo {
                start_block: callee_block,
                args,
                return_vars,
                local_vars: vec![],
            };
            if let Some(other_fi) = function_infos.get_mut(&callee_block) {
                assert_eq!(other_fi.args, fi.args);
                assert_eq!(other_fi.local_vars, fi.local_vars);
                other_fi.return_vars.extend(fi.return_vars);
                other_fi.return_vars.dedup();
                other_fi.return_vars.sort();
            } else {
                function_infos.insert(callee_block, fi);
            }
            call_graph.entry(*caller_id).or_default().push(callee_block);
        }
    }
    (function_infos, call_graph)
}

impl ProgramAnalysis {
    pub fn build(binary: &[i128]) -> Self {
        let control_flows: HashMap<BlockId, ControlFlowGraph<Arg>> =
            ControlFlowGraph::<Arg>::scan(binary)
                .into_iter()
                .map(|cfg| (cfg.start, cfg))
                .collect();

        let data_flows = control_flows
            .values()
            .map(|graph| (graph.start, GraphDataFlow::build_for(graph)))
            .collect();

        let (function_infos, call_graph) = function_call_analysis(&control_flows, &data_flows);
        ProgramAnalysis {
            control_flows,
            data_flows,
            function_infos,
            call_graph,
        }
    }

    /*
        let ssa = SSAConverter::new(&graph, &data_flow);
        let ssa_graph = ssa.convert();
        for (id, block) in ssa_graph.blocks.iter().sorted_by_key(|x| x.0) {
            if *id == graph.start {
                let bd = data_flow.block_defs.get(&block.id()).unwrap();
                println!(
                    "LiveIn={}",
                    bd.live_in.iter().sorted().map(|x| x.to_string()).join(", "),
                );
            }
            print!("{}", block);
            println!();
        Self {
            function_info: HashMap::new(),
        }
    }
    */
}
