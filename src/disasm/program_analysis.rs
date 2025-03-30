use core::fmt;
use std::collections::HashMap;

use super::{
    control_flow_graph::{BlockId, ControlFlowGraph, FunctionId, PredecessorKind},
    data_flow_analysis::GraphDataFlow,
    low_ir::{Arg, ArgBase, OpArg},
    ssa_form::{convert_to_ssa, SSAArg},
    type_inference::{Type, TypeInference, TypeVarId},
};

use itertools::Itertools;

#[derive(Debug)]
pub struct FunctionInfo {
    pub function_id: FunctionId,
    pub stack_size: usize,
    pub args: Vec<Arg>,        // from caller perspective
    pub return_vars: Vec<Arg>, // stack references for returned data from caller perspective
    pub local_vars: Vec<Arg>,  // local stack vars from callee perspective
}

pub struct ProgramAnalysis {
    pub control_flows: HashMap<FunctionId, ControlFlowGraph<OpArg>>,
    pub data_flows: HashMap<FunctionId, GraphDataFlow<OpArg>>,
    pub function_infos: HashMap<FunctionId, FunctionInfo>,
    pub call_graph: HashMap<FunctionId, Vec<FunctionId>>,
}

fn function_call_analysis(
    control_flows: &HashMap<FunctionId, ControlFlowGraph<OpArg>>,
    data_flows: &HashMap<FunctionId, GraphDataFlow<OpArg>>,
) -> (
    HashMap<FunctionId, FunctionInfo>,
    HashMap<FunctionId, Vec<FunctionId>>,
) {
    let mut function_infos: HashMap<FunctionId, FunctionInfo> = HashMap::new();
    let mut call_graph: HashMap<FunctionId, Vec<FunctionId>> = HashMap::new();
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
                .map(|a| a.as_arg())
                .filter(|a| matches!(a, Arg::RelativeMem(r) if *r>0))
                .sorted_by_key(|a| a.as_arg())
                .collect_vec();
            let Some(callee_addr) = fc.function_addr.value() else {
                continue; // non-literal address
            };

            let callee_function_id: FunctionId = (callee_addr as usize).into();
            let callee_data_flow =
                &data_flows[&callee_function_id].block_defs[&callee_function_id.as_block_id()];
            let callee_stack_size = control_flows[&callee_function_id].stack_size;

            let args = callee_data_flow
                .live_in
                .iter()
                .filter_map(|f| match f.as_arg() {
                    Arg::RelativeMem(r) if r < 0 => {
                        Some(Arg::RelativeMem((callee_stack_size as i128) + r))
                    }
                    _ => None,
                })
                .sorted()
                .collect_vec();
            let fi = FunctionInfo {
                function_id: callee_function_id,
                stack_size: callee_stack_size,
                args,
                return_vars,
                local_vars: vec![],
            };
            if let Some(other_fi) = function_infos.get_mut(&callee_function_id) {
                assert_eq!(other_fi.args, fi.args);
                assert_eq!(other_fi.local_vars, fi.local_vars);
                other_fi.return_vars.extend(fi.return_vars);
                other_fi.return_vars.dedup();
                other_fi.return_vars.sort();
            } else {
                function_infos.insert(callee_function_id, fi);
            }
            call_graph
                .entry(*caller_id)
                .or_default()
                .push(callee_function_id);
        }
    }
    (function_infos, call_graph)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnnotatedVar {
    ssa_arg: SSAArg,
    type_var: Type,
    substituted_type: Type,
    debug_marker: Option<char>,
}

impl fmt::Display for AnnotatedVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(marker) = self.debug_marker {
            write!(f, "'{} ", marker)?;
        }
        write!(
            f,
            "{}: ({}={})",
            self.ssa_arg, self.type_var, self.substituted_type
        )
    }
}

impl ProgramAnalysis {
    pub fn build(binary: &[i128]) -> Self {
        let control_flows: HashMap<FunctionId, ControlFlowGraph<OpArg>> =
            ControlFlowGraph::<OpArg>::scan(binary)
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

    pub fn list_program_with_types(
        &self,
        mut ti: &mut TypeInference,
        subst: &HashMap<TypeVarId, Type>,
    ) {
        for flow in self.control_flows.values().sorted_by_key(|c| c.start) {
            let data = &self.data_flows[&flow.start];
            let ssa = convert_to_ssa(self, flow, data);
            for block in ssa.cfg.blocks.values().sorted_by_key(|b| b.span.start) {
                for (addr, i) in block.ops.iter() {
                    let annotated = i.map_with_context(&mut ti, |p, ssa_arg: &SSAArg| {
                        let type_var = p.type_for_arg(*ssa_arg);
                        let substituted_type = TypeInference::substitute(type_var.clone(), subst);
                        let debug_marker = ssa.debug_markers.get(ssa_arg).cloned();
                        AnnotatedVar {
                            ssa_arg: *ssa_arg,
                            type_var: type_var,
                            substituted_type,
                            debug_marker,
                        }
                    });
                    let istr = format!("{}", annotated);
                    print!("{:8}  {:35}", addr, istr);
                    let read_args = i
                        .reads()
                        .iter()
                        .map(|&&a| ti.type_for_arg(a))
                        .map(|t| TypeInference::substitute(t, subst))
                        .collect_vec();
                    let write_args = i
                        .writes()
                        .iter()
                        .map(|&&a| ti.type_for_arg(a))
                        .map(|t| TypeInference::substitute(t, subst))
                        .collect_vec();

                    if !read_args.is_empty() {
                        print!("({})", read_args.iter().join(", "));
                    }
                    if !write_args.is_empty() {
                        print!(" -> {}", write_args.iter().join(", "));
                    }
                    println!();
                }
            }
        }
    }
}
