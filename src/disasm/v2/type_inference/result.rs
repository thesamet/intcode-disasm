#[deny(unused_imports)]
use std::collections::{HashMap, HashSet};

use crate::disasm::v2::{
    model::FunctionId,
    ssa_form::{SsaOperand, SsaVar},
};

use super::{
    types::{Type, VariableKind},
    AnalysisTrace,
};
use super::{visuals::TraceColors, ChangeReason};
use colored::Colorize;

pub type FunctionSignature = (Vec<(i128, SsaVar, Type)>, Vec<(i128, SsaVar, Type)>);

#[derive(Debug, Clone)]
pub struct TypeInferenceResult {
    pub inferred_types: HashMap<VariableKind, Type>,
    pub debug_markers: HashMap<char, SsaOperand>,
    pub traces: Vec<AnalysisTrace>,
    /// Inferred function signatures, including those discovered through indirect calls
    pub function_signatures: HashMap<FunctionId, FunctionSignature>,
}

impl TypeInferenceResult {
    pub fn get_type_for_ssavar(&self, var: &SsaVar) -> Option<&Type> {
        self.inferred_types.get(&VariableKind::SsaVar(*var))
    }

    pub fn get_type_for_ssaoperand(&self, op: &SsaOperand) -> Option<&Type> {
        self.inferred_types.get(&VariableKind::from_ssaoperand(op))
    }

    pub fn get_function_signature(&self, function_id: &FunctionId) -> Option<&FunctionSignature> {
        self.function_signatures.get(function_id)
    }

    /// Get the variable associated with a debug marker
    #[cfg(test)]
    pub fn get_marked_var(&self, marker: char) -> Option<&SsaOperand> {
        self.debug_markers.get(&marker)
    }

    /// Get the final type for a debug marker after unification
    #[cfg(test)]
    pub fn get_marker_type(&self, marker: char) -> Option<Type> {
        let ssa_op = self.get_marked_var(marker)?;
        self.get_type_for_ssaoperand(ssa_op).cloned()
    }

    /// Get traces for a variable plus any related traces through constraints
    pub fn get_recursive_traces_for_var(
        &self,
        type_var: VariableKind,
    ) -> Vec<(usize, &AnalysisTrace)> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();

        self.collect_related_traces(type_var, &mut result, &mut visited);

        // Sort the traces by their original order in the trace vector
        result.sort_by_key(|(idx, _)| *idx);

        result
    }

    fn collect_related_traces<'a>(
        &'a self,
        type_key: VariableKind,
        result: &mut Vec<(usize, &'a AnalysisTrace)>,
        visited: &mut HashSet<VariableKind>,
    ) {
        if !visited.insert(type_key) {
            return; // Already visited this type
        }

        // Find direct changes to this type
        for (idx, trace) in self.traces.iter().enumerate() {
            if trace.key == type_key {
                result.push((idx, trace));

                // For each trace, recursively follow any related types through constraints
                match &trace.reason {
                    ChangeReason::DecreaseUpperBoundFromConstraint {
                        constraint: _,
                        other: Type::Variable(other),
                    }
                    | ChangeReason::IncreaseLowerBoundFromConstraint {
                        constraint: _,
                        other: Type::Variable(other),
                    } => {
                        self.collect_related_traces(*other, result, visited);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Format all traces for an SSA variable in chronological order
    pub fn format_traces_for_var(&self, typ: VariableKind) -> String {
        let traces = self.get_recursive_traces_for_var(typ);
        if traces.is_empty() {
            return format!("No traces found for {typ}");
        }

        let mut result = String::new();
        result.push_str(&format!(
            "{} {}:\n",
            "Trace history for: ".yellow().bold(),
            TraceColors::format_var(&typ)
        ));
        for (idx, trace) in traces {
            result.push_str(&format!("{}. {}\n", idx + 1, trace));
        }

        result
    }
}
