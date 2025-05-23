//! Query engine for type inference debugging and analysis.
//!
//! ## Available Query Methods
//!
//! ### Variable Analysis
//! - `explain_bounds(tv_id)` - **Why does variable X have these bounds?**
//!   Detailed explanation with change history and affecting constraints
//! - `explain_variable_simply(tv_id)` - **What is variable X's current state?**
//!   One-line summary of bounds or converged type
//! - `list_all_variables()` - **What variables exist?**
//!   All type variables and their current bounds/types
//! - `find_root_causes(tv_id)` - **What originally caused variable X's type?**
//!   Traces back to original instructions
//!
//! ### Constraint Analysis
//! - `list_all_constraints()` - **What constraints exist?**
//!   All constraints with IDs, sources, and derivation info
//! - `get_affecting_constraints(tv_id)` - **What constraints involve variable X?**
//!   All constraints that mention this variable
//! - `trace_constraint_derivation(constraint)` - **How was constraint Y derived?**
//!   Full derivation chain back to original source
//!
//! ### Instruction Analysis
//! - `get_constraints_from_instruction(func, inst)` - **What constraints did instruction Z create?**
//!   All constraints from specific instruction
//! - `explain_instruction_impact(func, inst)` - **What did instruction Z contribute?**
//!   Constraints generated and variables affected
//!
//! ### Overview & Summary
//! - `summary()` - **High-level statistics**
//!   Total constraints, bound changes, original vs derived counts, converged variables
//!
//! ```
use std::fmt::Write;

use itertools::Itertools;

use super::{
    constraints::{Constraint, ConstraintStore},
    type_bounds_map::{ChangeLogEntry, ChangeReason, InferenceAlgorithmState},
    types::TypeVarId,
};
use crate::disasm::v3::{FunctionId, InstructionId};

/// Query engine for analyzing type inference results.
#[derive(Debug, Clone, Default)]
pub struct TypeInferenceQueryEngine {
    state: InferenceAlgorithmState,
    store: ConstraintStore,
}

impl TypeInferenceQueryEngine {
    /// Creates a new query engine from the solver's final state.
    pub fn new(state: InferenceAlgorithmState, store: ConstraintStore) -> Self {
        Self { state, store }
    }

    /// Explains how a type variable got its current bounds.
    pub fn explain_bounds(&self, tv_id: TypeVarId) -> String {
        let mut explanation = String::new();

        writeln!(
            explanation,
            "=== Explanation for {} ===",
            tv_id.display_with(&self.state)
        )
        .unwrap();

        if let Some((lower, upper)) = self.state.get_bounds(&tv_id) {
            writeln!(
                explanation,
                "Final bounds: {} <: {} <: {}",
                lower.display_with(&self.state),
                tv_id.display_with(&self.state),
                upper.display_with(&self.state)
            )
            .unwrap();
        } else {
            writeln!(explanation, "Type variable not found").unwrap();
            return explanation;
        }

        writeln!(explanation, "\nChange history:").unwrap();

        for (i, entry) in self.state.change_log.iter().enumerate() {
            if entry.tv_id == tv_id {
                writeln!(
                    explanation,
                    "  {}. {} because {}",
                    i + 1,
                    self.format_change_entry(entry),
                    self.format_change_reason(&entry.reason)
                )
                .unwrap();
            }
        }

        let affecting_constraints = self.get_affecting_constraints(tv_id);
        if !affecting_constraints.is_empty() {
            writeln!(explanation, "\nConstraints involving this variable:").unwrap();
            for constraint in affecting_constraints {
                writeln!(explanation, "  - {}", constraint.display_with(&self.state)).unwrap();
            }
        }

        explanation
    }

    /// Gets all constraints that affect a specific type variable.
    pub fn get_affecting_constraints(&self, tv_id: TypeVarId) -> Vec<&Constraint> {
        if let Some(constraint_ids) = self.store.get_constraints_involving_type_var(&tv_id) {
            constraint_ids
                .iter()
                .filter_map(|id| self.store.get_constraint_by_id(*id))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Gets all constraints that originated from a specific instruction.
    pub fn get_constraints_from_instruction(
        &self,
        function_id: FunctionId,
        instruction_id: InstructionId,
    ) -> Vec<&Constraint> {
        self.store
            .get_constraints_from_instruction(function_id, instruction_id)
    }

    /// Explains what an instruction contributed to type inference.
    pub fn explain_instruction_impact(
        &self,
        function_id: FunctionId,
        instruction_id: InstructionId,
    ) -> String {
        let mut explanation = String::new();

        writeln!(
            explanation,
            "=== Impact of {}:{} ===",
            function_id, instruction_id
        )
        .unwrap();

        let constraints = self.get_constraints_from_instruction(function_id, instruction_id);

        if constraints.is_empty() {
            writeln!(
                explanation,
                "No constraints generated from this instruction"
            )
            .unwrap();
        } else {
            writeln!(
                explanation,
                "Generated {} constraint(s):",
                constraints.len()
            )
            .unwrap();
            for constraint in constraints {
                writeln!(explanation, "  - {}", constraint.display_with(&self.state)).unwrap();

                // Show what this constraint affected
                let affected_vars = self.find_variables_affected_by_constraint(constraint);
                if !affected_vars.is_empty() {
                    writeln!(
                        explanation,
                        "    Affected variables: {}",
                        affected_vars
                            .iter()
                            .map(|tv| tv.display_with(&self.state).to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                    .unwrap();
                }
            }
        }

        explanation
    }

    /// Finds variables that were affected by a specific constraint.
    fn find_variables_affected_by_constraint(
        &self,
        target_constraint: &Constraint,
    ) -> Vec<TypeVarId> {
        let mut affected = Vec::new();

        for entry in &self.state.change_log {
            if let ChangeReason::Constraint(constraint) = &entry.reason {
                if constraint == target_constraint {
                    affected.push(entry.tv_id);
                }
            }
        }

        affected
    }

    /// Shows a summary of the type inference process.
    pub fn summary(&self) -> String {
        let mut summary = String::new();

        writeln!(summary, "=== Type Inference Summary ===").unwrap();
        writeln!(summary, "Total constraints: {}", self.store.len()).unwrap();
        writeln!(
            summary,
            "Total bound changes: {}",
            self.state.change_log.len()
        )
        .unwrap();

        // Count original vs derived constraints
        let mut original_count = 0;
        let mut derived_count = 0;
        for constraint_id in self.store.iter_ids() {
            if let Some(source) = self.store.get_constraint_source(constraint_id) {
                match source {
                    super::constraints::ConstraintSource::Original { .. } => original_count += 1,
                    super::constraints::ConstraintSource::Derived { .. } => derived_count += 1,
                }
            }
        }
        writeln!(summary, "Original constraints: {}", original_count).unwrap();
        writeln!(summary, "Derived constraints: {}", derived_count).unwrap();

        let converged_vars: Vec<_> = self
            .state
            .iter_all_type_states()
            .filter(|&(_, state)| {
                matches!(state, super::type_interval::TypeInterval::Converged(_))
            })
            .map(|(id, _)| *id)
            .collect();

        writeln!(summary, "Converged variables: {}", converged_vars.len()).unwrap();

        if !converged_vars.is_empty() {
            writeln!(summary, "Converged types:").unwrap();
            for tv_id in converged_vars {
                if let Some((lower, upper)) = self.state.get_bounds(&tv_id) {
                    if lower == upper {
                        writeln!(
                            summary,
                            "  {} = {}",
                            tv_id.display_with(&self.state),
                            lower.display_with(&self.state)
                        )
                        .unwrap();
                    }
                }
            }
        }

        summary
    }

    /// Helper method to format a change log entry.
    fn format_change_entry(&self, entry: &ChangeLogEntry) -> String {
        format!("updated to {}", entry.state.display_with(&self.state))
    }

    /// Helper method to format a change reason.
    fn format_change_reason(&self, reason: &ChangeReason) -> String {
        match reason {
            ChangeReason::Constraint(constraint) => {
                format!("constraint: {}", constraint.display_with(&self.state))
            }
            ChangeReason::ConcreteTypeRefinement => "concrete type refinement".to_string(),
            ChangeReason::ConvergenceOf(tv_id) => {
                format!("convergence of {}", tv_id.display_with(&self.state))
            }
            ChangeReason::Test => "test".to_string(),
        }
    }

    /// Simple query interface - explains a variable in a concise format.
    pub fn explain_variable_simply(&self, tv_id: TypeVarId) -> String {
        if let Some((lower, upper)) = self.state.get_bounds(&tv_id) {
            if lower == upper {
                format!(
                    "{:<5}: {} = {} (converged)",
                    tv_id,
                    tv_id.display_with(&self.state),
                    lower.display_with(&self.state)
                )
            } else {
                format!(
                    "{:<5}: {} ∈ [{}, {}]",
                    tv_id,
                    tv_id.display_with(&self.state),
                    lower.display_with(&self.state),
                    upper.display_with(&self.state)
                )
            }
        } else {
            format!("{} = <not found>", tv_id.display_with(&self.state))
        }
    }

    /// Lists all type variables and their current states.
    pub fn list_all_variables(&self) -> String {
        let mut output = String::new();

        writeln!(output, "=== All Type Variables ===").unwrap();

        for (tv_id, _) in self.state.iter_all_type_states().sorted_by_key(|v| v.0) {
            writeln!(output, "  {}", self.explain_variable_simply(*tv_id)).unwrap();
        }

        output
    }

    /// Traces the derivation chain of a constraint back to its original sources.
    pub fn trace_constraint_derivation(&self, constraint: &Constraint) -> String {
        let mut trace = String::new();

        if let Some(constraint_id) = self.store.get_constraint_id(constraint) {
            writeln!(trace, "=== Constraint Derivation Trace ===").unwrap();
            writeln!(trace, "Target: {}", constraint.display_with(&self.state)).unwrap();
            writeln!(trace, "\nDerivation chain:").unwrap();

            self.trace_constraint_derivation_recursive(constraint_id, 0, &mut trace);
        } else {
            writeln!(trace, "Constraint not found in store").unwrap();
        }

        trace
    }

    /// Recursive helper for constraint derivation tracing.
    fn trace_constraint_derivation_recursive(
        &self,
        constraint_id: super::constraints::ConstraintId,
        depth: usize,
        output: &mut String,
    ) {
        let indent = "  ".repeat(depth);

        if let Some(constraint) = self.store.get_constraint_by_id(constraint_id) {
            writeln!(
                output,
                "{}• {}",
                indent,
                constraint.display_with(&self.state)
            )
            .unwrap();

            if let Some(source) = self.store.get_constraint_source(constraint_id) {
                match source {
                    super::constraints::ConstraintSource::Original {
                        function_id,
                        instruction_id,
                        reason,
                    } => {
                        writeln!(
                            output,
                            "{}  └─ Original from {}:{} ({})",
                            indent,
                            function_id,
                            instruction_id,
                            format!("{:?}", reason)
                        )
                        .unwrap();
                    }
                    super::constraints::ConstraintSource::Derived {
                        from_constraint,
                        derivation_reason,
                    } => {
                        writeln!(
                            output,
                            "{}  └─ Derived via: {}",
                            indent,
                            self.format_change_reason(&derivation_reason)
                        )
                        .unwrap();
                        self.trace_constraint_derivation_recursive(
                            *from_constraint,
                            depth + 1,
                            output,
                        );
                    }
                }
            }
        }
    }

    /// Finds the root causes (original constraints) that led to a variable's bounds.
    pub fn find_root_causes(&self, tv_id: TypeVarId) -> String {
        let mut output = String::new();

        writeln!(
            output,
            "=== Root Causes for {} ===",
            tv_id.display_with(&self.state)
        )
        .unwrap();

        let affecting_constraints = self.get_affecting_constraints(tv_id);
        let mut root_causes = Vec::new();

        for constraint in affecting_constraints {
            if let Some(constraint_id) = self.store.get_constraint_id(constraint) {
                self.find_root_causes_recursive(constraint_id, &mut root_causes);
            }
        }

        // Remove duplicates
        root_causes.sort_by_key(|(func_id, inst_id, _)| (*func_id, *inst_id));
        root_causes.dedup();

        if root_causes.is_empty() {
            writeln!(output, "No root causes found").unwrap();
        } else {
            writeln!(output, "Found {} root cause(s):", root_causes.len()).unwrap();
            for (func_id, inst_id, reason) in root_causes {
                writeln!(output, "  • {}:{} - {:?}", func_id, inst_id, reason).unwrap();
            }
        }

        output
    }

    /// Recursive helper to find original constraints.
    fn find_root_causes_recursive(
        &self,
        constraint_id: super::constraints::ConstraintId,
        root_causes: &mut Vec<(
            FunctionId,
            InstructionId,
            super::constraints::ConstraintReason,
        )>,
    ) {
        if let Some(source) = self.store.get_constraint_source(constraint_id) {
            match source {
                super::constraints::ConstraintSource::Original {
                    function_id,
                    instruction_id,
                    reason,
                } => {
                    root_causes.push((*function_id, *instruction_id, reason.clone()));
                }
                super::constraints::ConstraintSource::Derived {
                    from_constraint, ..
                } => {
                    self.find_root_causes_recursive(*from_constraint, root_causes);
                }
            }
        }
    }

    /// Lists all constraints with their IDs and derivation sources.
    pub fn list_all_constraints(&self) -> String {
        let mut output = String::new();

        writeln!(output, "=== All Constraints ===").unwrap();
        writeln!(output, "Total: {}", self.store.len()).unwrap();
        writeln!(output).unwrap();

        for constraint_id in self.store.iter_ids() {
            if let Some(constraint) = self.store.get_constraint_by_id(constraint_id) {
                writeln!(
                    output,
                    "ID {:?}: {}",
                    constraint_id,
                    constraint.display_with(&self.state)
                )
                .unwrap();

                if let Some(source) = self.store.get_constraint_source(constraint_id) {
                    match source {
                        super::constraints::ConstraintSource::Original {
                            function_id,
                            instruction_id,
                            reason,
                        } => {
                            writeln!(
                                output,
                                "  └─ Original from {}:{} ({:?})",
                                function_id, instruction_id, reason
                            )
                            .unwrap();
                        }
                        super::constraints::ConstraintSource::Derived {
                            from_constraint,
                            derivation_reason,
                        } => {
                            writeln!(
                                output,
                                "  └─ Derived from ID {:?} via: {}",
                                from_constraint,
                                self.format_change_reason(&derivation_reason)
                            )
                            .unwrap();
                        }
                    }
                } else {
                    writeln!(output, "  └─ No source information").unwrap();
                }
                writeln!(output).unwrap();
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::v3::{
        lir::Expression,
        type_inference::{
            constraints::{Constraint, ConstraintReason, ConstraintStore},
            type_bounds_map::{ChangeReason, InferenceAlgorithmState},
            types::{Type, TypeVarId, TypeVarKind, TypeVarNode},
        },
    };
    use crate::disasm::v3::{FunctionId, InstructionId};

    fn create_test_query_engine() -> TypeInferenceQueryEngine {
        let mut state = InferenceAlgorithmState::new();
        let store = ConstraintStore::new();

        // Add a test type variable
        let tv_id = TypeVarId::new(1);
        let node = TypeVarNode {
            kind: TypeVarKind::Expression(Expression::Constant(42)),
            instruction_id: InstructionId::new(10),
            function_id: FunctionId::new(0),
        };
        state.add_type_var(tv_id, node);

        // Update its bounds to simulate inference
        state.update_upper_bound(&tv_id, &Type::Int, ChangeReason::ConcreteTypeRefinement);

        TypeInferenceQueryEngine::new(state, store)
    }

    #[test]
    fn test_explain_variable_simply() {
        let engine = create_test_query_engine();
        let tv_id = TypeVarId::new(1);

        let explanation = engine.explain_variable_simply(tv_id);
        // Just check that it contains some basic expected elements
        assert!(!explanation.is_empty());
        assert!(explanation.contains("Int"));
    }

    #[test]
    fn test_summary() {
        let engine = create_test_query_engine();

        let summary = engine.summary();
        assert!(summary.contains("Type Inference Summary"));
        assert!(summary.contains("Total constraints"));
        assert!(summary.contains("Total bound changes"));
    }

    #[test]
    fn test_explain_bounds() {
        let engine = create_test_query_engine();
        let tv_id = TypeVarId::new(1);

        let explanation = engine.explain_bounds(tv_id);
        assert!(explanation.contains("Explanation for"));
        assert!(explanation.contains("Final bounds"));
        assert!(explanation.contains("Change history"));
    }

    /// Example of how to use the query engine from a test.
    #[test]
    fn example_usage_from_test() {
        // This shows how you would use the query engine in your tests
        // to debug type inference issues.

        let engine = create_test_query_engine();

        // 1. Get a summary of the inference process (now includes derivation counts)
        let summary = engine.summary();
        println!("=== SUMMARY ===\n{}", summary);

        // 2. List all constraints with their IDs and sources
        let all_constraints = engine.list_all_constraints();
        println!("=== ALL CONSTRAINTS ===\n{}", all_constraints);

        // 3. List all variables and their current states
        let all_vars = engine.list_all_variables();
        println!("=== ALL VARIABLES ===\n{}", all_vars);

        // 4. Explain a specific variable in detail
        let tv_id = TypeVarId::new(1);
        let detailed_explanation = engine.explain_bounds(tv_id);
        println!("=== DETAILED EXPLANATION ===\n{}", detailed_explanation);

        // 5. Find root causes for a variable's bounds
        let root_causes = engine.find_root_causes(tv_id);
        println!("=== ROOT CAUSES ===\n{}", root_causes);

        // 6. Get constraints from a specific instruction
        let constraints =
            engine.get_constraints_from_instruction(FunctionId::new(0), InstructionId::new(10));
        println!("=== CONSTRAINTS FROM INSTRUCTION ===");
        for constraint in constraints {
            println!("  {}", constraint.display_with(&engine.state));

            // 7. Trace how this constraint was derived
            let derivation_trace = engine.trace_constraint_derivation(constraint);
            println!("=== CONSTRAINT DERIVATION ===\n{}", derivation_trace);
        }

        // 8. Explain what an instruction contributed
        let instruction_impact =
            engine.explain_instruction_impact(FunctionId::new(0), InstructionId::new(10));
        println!("=== INSTRUCTION IMPACT ===\n{}", instruction_impact);
    }

    /// Test with actual constraints to showcase constraint listing.
    #[test]
    fn test_with_constraints() {
        let mut state = InferenceAlgorithmState::new();
        let mut store = ConstraintStore::new();

        // Create some type variables
        let tv1 = TypeVarId::new(1);
        let tv2 = TypeVarId::new(2);

        let node1 = TypeVarNode {
            kind: TypeVarKind::Expression(Expression::Constant(10)),
            instruction_id: InstructionId::new(5),
            function_id: FunctionId::new(0),
        };
        let node2 = TypeVarNode {
            kind: TypeVarKind::Expression(Expression::Constant(20)),
            instruction_id: InstructionId::new(6),
            function_id: FunctionId::new(0),
        };

        state.add_type_var(tv1, node1);
        state.add_type_var(tv2, node2);

        // Add some original constraints
        let constraint1 = Constraint::new(
            Type::TypeVar(tv1),
            Type::Int,
            FunctionId::new(0),
            InstructionId::new(5),
            ConstraintReason::LiteralInteger,
        );
        let constraint2 = Constraint::new(
            Type::TypeVar(tv2),
            Type::Int,
            FunctionId::new(0),
            InstructionId::new(6),
            ConstraintReason::LiteralInteger,
        );

        let (c1_id, _) = store.add_original_constraint(constraint1.clone(), &state);
        let (c2_id, _) = store.add_original_constraint(constraint2.clone(), &state);

        // Add a derived constraint
        let derived_constraint = Constraint::new(
            Type::TypeVar(tv1),
            Type::TypeVar(tv2),
            FunctionId::new(0),
            InstructionId::new(7),
            ConstraintReason::Assignment,
        );

        let (_, _) = store.add_derived_constraint(
            derived_constraint,
            c1_id,
            ChangeReason::ConcreteTypeRefinement,
            &state,
        );

        let engine = TypeInferenceQueryEngine::new(state, store);

        // Now showcase the constraint listing with actual constraints
        let all_constraints = engine.list_all_constraints();
        println!("=== TEST WITH ACTUAL CONSTRAINTS ===\n{}", all_constraints);

        // Verify we have the expected constraints
        assert!(all_constraints.contains("Total: 3"));
        assert!(all_constraints.contains("Original from"));
        assert!(all_constraints.contains("Derived from"));
    }
}
