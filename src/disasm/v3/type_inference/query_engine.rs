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
    type_bounds_map::{ChangeLogEntry, ChangeReason, InferenceAlgorithmState, TypeVarRegistry},
    types::TypeVarId,
    TypeVarState,
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

    pub fn list_all_variables(&self) {
        for (tv_id, state) in self.state.iter_all_type_states() {
            let _ = println!(
                "{}: {}",
                tv_id.display_with(&self.state),
                state.display_with(&self.state)
            );
        }
    }

    pub fn list_all_constraints(&self) {
        for (id, constraint) in self.store.iter_with_ids() {
            println!("{:?}: {}", id, constraint.display_with(&self.state));
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
