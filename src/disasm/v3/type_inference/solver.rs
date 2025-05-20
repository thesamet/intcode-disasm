//! Type inference solver implementation.

use crate::disasm::v3::model::{FoldedSsaComplete, Model, TypeInferenceComplete};
use crate::disasm::v3::type_inference::analyzer::TypeInferenceAnalyzer;
use crate::disasm::v3::type_inference::TypeInferenceResult;
use crate::disasm::Error; // Assuming a general error type for the project

use std::collections::VecDeque;

use super::{Constraint, ConstraintStore, InferenceAlgorithmState, Type};

/// Solver for type inference.
///
/// The solver takes a model with folded SSA results and attempts to infer types
/// for virtual machine registers (VMRs) and memory locations by generating
/// and solving a set of type constraints.
pub struct Solver {
    /// The model containing the folded SSA result, which includes the CFG, DFG, and Function.
    model: Model<FoldedSsaComplete>,
    state: InferenceAlgorithmState,
    store: ConstraintStore,
}

impl Solver {
    /// Creates a new solver instance.
    ///
    /// # Arguments
    ///
    /// * `model` - The model with folded SSA results.
    pub fn new(model: Model<FoldedSsaComplete>) -> Self {
        Self {
            model,
            state: InferenceAlgorithmState::new(),
            store: ConstraintStore::new(),
        }
    }

    /// Runs the type inference solver.
    ///
    /// This is a convenience method that creates a new solver and calls `solve`.
    ///
    /// # Arguments
    ///
    /// * `model` - The model with folded SSA results.
    ///
    /// # Returns
    ///
    /// A `Result` containing the model with type inference complete, or an `Error`
    /// if type inference fails (e.g., due to a type contradiction or other issue).
    pub fn run(model: Model<FoldedSsaComplete>) -> Result<Model<TypeInferenceComplete>, Error> {
        let solver = Self::new(model);
        solver.solve()
    }

    /// Solves the type inference problem.
    ///
    /// This method implements a worklist algorithm to iteratively refine types
    /// based on the generated constraints until a fixed point is reached or a
    /// contradiction is found.
    ///
    /// # Returns
    ///
    /// A `Result` containing the model with type inference complete, or an `Error`.
    fn solve(mut self) -> Result<Model<TypeInferenceComplete>, Error> {
        // 1. Initialize Analyzer, State, and Store
        let mut analyzer = TypeInferenceAnalyzer::new();

        analyzer.generate_constraints(&self.model, &mut self.state, &mut self.store);

        let initial_constraints: VecDeque<Constraint> = self.store.iter().cloned().collect();
        //
        loop {
            let mut worklist: VecDeque<Constraint> =
                initial_constraints.clone().into_iter().collect();

            let mut iteration_count = 0;
            let mut changed = false;

            while let Some(constraint) = worklist.pop_front() {
                iteration_count += 1;

                changed |= self.apply_constraint(&constraint);
            }

            let mut to_remove = HashSet::new();

            for unclassified in self.store.iter_unclassified_add_expressions() {
                if self.try_classify_add_expression(unclassified) {
                    to_remove.insert(unclassified.clone());
                }
            }
            changed |= !to_remove.is_empty();

            for constraint in to_remove {
                self.store.remove(&constraint);
            }

            if !changed {
                break;
            }
        }

        let mut result = TypeInferenceResult::new();
        result.type_var_nodes = self
            .state
            .iter_all_type_nodes()
            .map(|(id, var)| (*id, var.clone()))
            .collect();
        result.type_var_states = self
            .state
            .iter_all_type_states()
            .map(|(id, state)| (*id, state.clone()))
            .collect();

        // 9. Finalize the result and embed it into a new model state.
        Ok(self.model.with_type_inference_result(result))
    }

    fn apply_constraint(&mut self, constraint: &Constraint) -> bool {
        let mut changed = false;
        let sub_type = self.state.resolve_type(&constraint.sub_type);
        let super_type = self.state.resolve_type(&constraint.super_type);
        if let Type::TypeVar(tv_id) = &sub_type {
            changed |= self
                .state
                .update_upper_bound(tv_id, &super_type, constraint);
        }
        if let Type::TypeVar(tv_id) = &super_type {
            changed |= self.state.update_lower_bound(tv_id, &sub_type, constraint);
        }
        changed
    }

    fn try_classify_add_expression(&mut self, unclassified: &UnclasifiedArithmeticExpresction) -> bool {
        let mut changed = false;
        let lhs_type = self.state.resolve_type(&unclassified.lhs_type);
        let rhs_type = self.state.resolve_type(&unclassified.rhs_type);
        let result_type = self.state.resolve_type(&unclassified.result_type);

        if let Type::TypeVar(lhs_tv_id) = &
}
