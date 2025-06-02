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

use itertools::Itertools;

use crate::disasm::v3::{type_inference::type_bounds_map::BoundChangeReason, FunctionId};

use super::{
    constraints::{Constraint, ConstraintId, ConstraintStore},
    type_bounds_map::{ChangeLogKind, InferenceAlgorithmState},
    types::TypeVarId,
};

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

    pub fn list_all_variables(&self) {
        for (tv_id, state) in self.state.iter_all_type_states().sorted_by_key(|t| t.0) {
            println!(
                "{:>5}: {}: {}",
                tv_id,
                tv_id.display_with(&self.state),
                state.display_with(&self.state)
            );
        }
    }

    pub fn list_function_variables(&self, function_id: &FunctionId) {
        for (tv_id, state) in self
            .state
            .iter_all_type_states()
            .filter(|v| {
                self.state
                    .get_type_var_node(v.0)
                    .unwrap()
                    .path
                    .function_id()
                    == *function_id
            })
            .sorted_by_key(|t| t.0)
        {
            println!(
                "{:>5}: {}: {}",
                tv_id,
                tv_id.display_with(&self.state),
                state.display_with(&self.state)
            );
        }
    }

    pub fn list_all_constraints(&self) {
        for (id, constraint) in self.store.iter() {
            println!("{:?}: {}", id, constraint.display_with(&self.state));
        }
    }

    pub fn list_variable_changes(&self, in_tv_id: TypeVarId) {
        for ch in self.state.change_log.iter() {
            if ch.tv_id != in_tv_id {
                continue;
            }
            match &ch.kind {
                ChangeLogKind::AddedBound {
                    direction: bound,
                    new_bound,
                    reason,
                } => {
                    println!(
                        "{} {} {:?}: {} because {}",
                        ch.tv_id,
                        ch.tv_id.display_with(&self.state),
                        bound,
                        new_bound.display_with(&self.state),
                        reason.display_with(&self.state)
                    );
                    if let BoundChangeReason::Constraint(constraint_id) = reason {
                        self.print_constraint_derivation(*constraint_id)
                    }
                }
                ChangeLogKind::Converged {
                    new_type,
                    convergence_type,
                } => {
                    println!(
                        "{} {}: {} because {:?}",
                        ch.tv_id,
                        ch.tv_id.display_with(&self.state),
                        new_type.display_with(&self.state),
                        convergence_type,
                    )
                }
                ChangeLogKind::DependencyConverged {
                    dependent_var_id,
                    new_value,
                } => {
                    println!(
                        "{} {}: dependency {} converted to {}",
                        ch.tv_id,
                        ch.tv_id.display_with(&self.state),
                        dependent_var_id,
                        new_value.display_with(&self.state),
                    )
                }
            }
        }
    }

    pub fn print_constraint_derivation(&self, id: ConstraintId) {
        if let Some(constraint) = self.store.get_constraint_by_id(id) {
            self.print_constraint_recursive(id, constraint, 0);
        } else {
            println!("Constraint {:?} not found", id);
        }
    }

    fn print_constraint_recursive(&self, id: ConstraintId, constraint: &Constraint, indent: usize) {
        let indent_str = "  ".repeat(indent);
        println!("{}{:?}: {}", indent_str, id, constraint,);

        if let Some(super::constraints::ConstraintSource::Derived {
            from_constraint, ..
        }) = self.store.get_constraint_source(id)
        {
            if let Some(parent_constraint) = self.store.get_constraint_by_id(*from_constraint) {
                self.print_constraint_recursive(*from_constraint, parent_constraint, indent + 1);
            }
        }
    }

    /*
    /// Explains how a type variable got its current bounds.
    pub fn explain_variable_simply(&self, tv_id: TypeVarId) -> String {
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
    */
}
