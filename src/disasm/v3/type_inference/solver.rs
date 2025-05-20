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

        let result = TypeInferenceResult::new();

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
            if !changed {
                break;
            }
        }

        // 9. Finalize the result and embed it into a new model state.
        Ok(self.model.with_type_inference_result(result))
    }

    fn apply_constraint(&mut self, constraint: &Constraint) -> bool {
        let mut changed = false;
        if let Type::TypeVar(tv_id) = &constraint.sub_type {
            let current_upper = self.state.get_bounds(tv_id).unwrap().1;
            let lub = Type::lub(current_upper, &constraint.super_type).unwrap();
            changed |= self.state.update_upper_bound(tv_id, &lub);
        }
        if let Type::TypeVar(tv_id) = &constraint.super_type {
            let current_lower = self.state.get_bounds(tv_id).unwrap().0;
            let glb = Type::glb(current_lower, &constraint.sub_type).unwrap();
            changed |= self.state.update_lower_bound(tv_id, &glb);
        }
        changed
    }
}
