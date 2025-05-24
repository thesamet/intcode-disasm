//! Type inference solver implementation.

use colored::Colorize;
use itertools::Itertools;
use log::{debug, trace};

use crate::disasm::v3::lir::{BinaryOperator, Expression};
use crate::disasm::v3::model::{FoldedSsaComplete, Model, TypeInferenceComplete};
use crate::disasm::v3::type_inference::TypeInferenceResult;
use crate::disasm::v3::{FunctionId, InstructionId};
use crate::disasm::Error; // Assuming a general error type for the project

use std::any::Any;
use std::collections::{HashMap, HashSet, VecDeque};

use super::constraints::UnclassifiedArithmeticExpression;
use super::constraints_generator::TypeConstraintGeneratorResult;
use super::query_engine::TypeInferenceQueryEngine;
use super::type_bounds_map::ChangeReason;
use super::type_interval::TypeInterval;
use super::types::TypeVarId;
use super::{
    generate_constraints, Constraint, ConstraintReason, ConstraintStore, InferenceAlgorithmState,
    Type, TypeVarState,
};

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
        let generator_result = generate_constraints(&self.model);
        self.store = generator_result.store;
        self.state = generator_result.state;
        let markers = generator_result.markers;

        //
        let mut iteration_count = 0;
        loop {
            let mut worklist: VecDeque<Constraint> = self.store.iter().cloned().collect();
            iteration_count += 1;
            if iteration_count >= 30 {
                panic!("Too many iterations");
            }

            let mut changed = false;

            while let Some(constraint) = worklist.pop_front() {
                changed |= self.apply_constraint(&constraint, &generator_result.function_types);
            }

            let mut to_remove = HashSet::new();
            let e = self
                .store
                .iter_unclassified_add_expressions()
                .cloned()
                .collect_vec();
            for unclassified in e {
                if self.try_classify_add_expression(&unclassified) {
                    to_remove.insert(unclassified.clone());
                }
            }
            changed |= !to_remove.is_empty();

            if !changed {
                changed |= self.refine_concrete_types();
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
        for (id, state) in self.state.iter_all_type_states() {
            result.type_var_states.insert(*id, state.clone());
            if let Some(mem_ref) = self
                .state
                .get_type_var_node(id)
                .unwrap()
                .kind
                .as_memory_reference()
            {
                result.mem_ref_to_type_var_id.insert(mem_ref.clone(), *id);
            }
        }
        result.debug_markers = markers;
        for entry in self.state.change_log.iter() {
            debug!(
                "{}: updated to {}  reason: {}",
                entry.tv_id.display_with(&self.state),
                entry.state.display_with(&self.state),
                entry.reason.display_with(&self.state)
            );
        }
        result.query_engine = TypeInferenceQueryEngine::new(self.state.clone(), self.store.clone());

        // 9. Finalize the result and embed it into a new model state.
        let result_model = self.model.with_type_inference_result(result);

        // Create query engine from the solver's final state

        Ok(result_model)
    }

    fn apply_constraint(
        &mut self,
        constraint: &Constraint,
        function_types: &HashMap<FunctionId, (Type, Type)>,
    ) -> bool {
        let mut changed = false;
        let sub_type = self.state.resolve_type(&constraint.sub_type);
        let super_type = self.state.resolve_type(&constraint.super_type);
        if let Type::TypeVar(tv_id) = &sub_type {
            changed |= self.state.update_upper_bound(
                tv_id,
                &constraint.super_type,
                ChangeReason::Constraint(constraint.clone()),
            );
        }
        if let Type::TypeVar(tv_id) = &super_type {
            changed |= self.state.update_lower_bound(
                tv_id,
                &constraint.sub_type,
                ChangeReason::Constraint(constraint.clone()),
            );
        }

        match (&sub_type, &super_type) {
            (Type::TypeVar(tv_id), Type::TypeVar(tv_id2)) if tv_id == tv_id2 => {
                changed |= self.state.update_lower_bound(
                    tv_id,
                    &sub_type,
                    ChangeReason::Constraint(constraint.clone()),
                );
            }
            (Type::Tuple(ts), Type::Tuple(us)) => {
                for (t, u) in ts.iter().zip(us) {
                    let new_constraint = Constraint::new(
                        t.clone(),
                        u.clone(),
                        constraint.origin_function_id,
                        constraint.origin_instruction_id,
                        ConstraintReason::TupleSubtype,
                    );

                    // Get the parent constraint ID for derivation tracking
                    let (_, ch) = if let Some(parent_id) = self.store.get_constraint_id(constraint)
                    {
                        // Track this as a derived constraint from tuple subtyping
                        self.store.add_derived_constraint(
                            new_constraint,
                            parent_id,
                            ChangeReason::Constraint(constraint.clone()),
                            &self.state,
                        )
                    } else {
                        // Fallback to original constraint if parent not found
                        self.store
                            .add_original_constraint(new_constraint, &self.state)
                    };
                    changed |= ch;
                }
            }
            (Type::TypeVar(tv_id), Type::Function { .. })
                if self
                    .state
                    .get_type_var_node(tv_id)
                    .unwrap()
                    .kind
                    .as_const()
                    .is_some() =>
            {
                let addr = self
                    .state
                    .get_type_var_node(tv_id)
                    .unwrap()
                    .kind
                    .as_const()
                    .unwrap();
                if let Some((callee_arg_type, callee_ret_type)) =
                    function_types.get(&FunctionId::new(*addr as usize))
                {
                    let func_type =
                        Type::function(callee_arg_type.clone(), callee_ret_type.clone());
                    changed |= self.store.add_equality_constraint(
                        Constraint {
                            sub_type: func_type,
                            super_type: tv_id.to_type(),
                            origin_function_id: constraint.origin_function_id,
                            origin_instruction_id: constraint.origin_instruction_id,
                            reason: ConstraintReason::ConstIsFunctionPointer,
                        },
                        &self.state,
                    )
                }
                println!("TypeVar {:?} is a function", tv_id);
            }
            _ => {}
        }
        changed
    }

    fn try_classify_add_expression(
        &mut self,
        unclassified: &UnclassifiedArithmeticExpression,
    ) -> bool {
        let mut changed = false;
        let Expression::Binary { lhs, rhs, op } = &unclassified.expression else {
            panic!("Expected BinaryOp expression");
        };
        if op != &BinaryOperator::Add && op != &BinaryOperator::Sub {
            panic!("Expected Add or Sub operator");
        }
        let Type::TypeVar(op1_type_var) = unclassified.lhs_type else {
            panic!("Expected TypeVar for lhs type");
        };
        let Type::TypeVar(op2_type_var) = unclassified.rhs_type else {
            panic!("Expected TypeVar for rhs type");
        };
        let Type::TypeVar(res_type_var) = unclassified.result_type else {
            panic!("Expected TypeVar for result type");
        };
        let (op1_lower_unresolved, op1_upper_unresolved) =
            self.state.get_bounds(&op1_type_var).unwrap();
        let (op2_lower_unresolved, op2_upper_unresolved) =
            self.state.get_bounds(&op2_type_var).unwrap();
        let (res_lower_unresolved, res_upper_unresolved) =
            self.state.get_bounds(&res_type_var).unwrap();

        let op1_lower = self.state.resolve_type(&op1_lower_unresolved);
        let op1_upper = self.state.resolve_type(&op1_upper_unresolved);
        let op2_lower = self.state.resolve_type(&op2_lower_unresolved);
        let op2_upper = self.state.resolve_type(&op2_upper_unresolved);
        let res_lower = self.state.resolve_type(&res_lower_unresolved);
        let res_upper = self.state.resolve_type(&res_upper_unresolved);

        let is_op1_int = matches!(op1_lower, Type::Int);
        let is_op2_int = matches!(op2_lower, Type::Int);
        let is_result_int = matches!(res_lower, Type::Int);
        let is_op1_pointer = matches!(op1_upper, Type::Pointer(_));
        let is_op2_pointer = matches!(op2_upper, Type::Pointer(_));
        let is_result_pointer = matches!(res_upper, Type::Pointer(_));
        let is_result_char = matches!(res_lower, Type::Char);
        let mut changed = false;

        let mut add_constraint = |sub_type: Type, super_type: Type, reason: ConstraintReason| {
            let new_constraint = Constraint::new(
                sub_type,
                super_type,
                FunctionId::new(0),
                InstructionId::new(0),
                reason,
            );
            // For arithmetic classification, treat as derived from the expression analysis
            let (_, is_new) = self
                .store
                .add_original_constraint(new_constraint, &self.state);
            changed |= is_new;
        };

        if is_op1_int && is_op2_int {
            add_constraint(
                unclassified.result_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticResultOp1IntOp2Int,
            );
        }
        if is_result_char || is_result_int {
            add_constraint(
                unclassified.lhs_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticResultCharOrInt,
            );
            add_constraint(
                unclassified.rhs_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticResultCharOrInt,
            );
        }
        if is_op1_pointer {
            add_constraint(
                unclassified.rhs_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticOp1Pointer,
            );
            add_constraint(
                unclassified.lhs_type.clone(),
                unclassified.result_type.clone(),
                ConstraintReason::ArithmeticOp1Pointer,
            );
            add_constraint(
                unclassified.result_type.clone(),
                unclassified.lhs_type.clone(),
                ConstraintReason::ArithmeticOp1Pointer,
            );
        }
        if is_op2_pointer {
            add_constraint(
                unclassified.lhs_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticOp2Pointer,
            );
            add_constraint(
                unclassified.rhs_type.clone(),
                unclassified.result_type.clone(),
                ConstraintReason::ArithmeticOp2Pointer,
            );
            add_constraint(
                unclassified.result_type.clone(),
                unclassified.rhs_type.clone(),
                ConstraintReason::ArithmeticOp2Pointer,
            );
        }
        if is_result_pointer && is_op1_int {
            add_constraint(
                unclassified.rhs_type.clone(),
                unclassified.result_type.clone(),
                ConstraintReason::ArithmeticResultPointerOp1Int,
            );
        }
        if is_result_pointer && is_op2_int {
            add_constraint(
                unclassified.lhs_type.clone(),
                unclassified.result_type.clone(),
                ConstraintReason::ArithmeticResultPointerOp2Int,
            );
        }
        if is_op1_int || is_op2_int {
            add_constraint(
                unclassified.result_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticOp1IntOrOp2Int,
            );
        }

        changed
    }

    fn refine_concrete_types(&mut self) -> bool {
        trace!("{}", "Refining concrete types".red());
        let type_states: Vec<(TypeVarId, TypeVarState)> = self
            .state
            .iter_all_type_states()
            .map(|(id, state)| (*id, state.clone()))
            .collect();

        for (tv_id, var) in type_states {
            if let TypeInterval::Bounds {
                lower_bound,
                upper_bound,
            } = var
            {
                if lower_bound == Type::Nothing && upper_bound.is_concrete_type() {
                    self.state.update_lower_bound(
                        &tv_id,
                        &upper_bound,
                        ChangeReason::ConcreteTypeRefinement,
                    );
                    return true;
                }
                if upper_bound == Type::Any && lower_bound.is_concrete_type() {
                    self.state.update_upper_bound(
                        &tv_id,
                        &lower_bound,
                        ChangeReason::ConcreteTypeRefinement,
                    );
                    return true;
                }
                if lower_bound == Type::Nothing && upper_bound == Type::Truthy {
                    self.state.update_upper_bound(
                        &tv_id,
                        &Type::Bool,
                        ChangeReason::ConcreteTypeRefinement,
                    );
                    self.state.update_lower_bound(
                        &tv_id,
                        &Type::Bool,
                        ChangeReason::ConcreteTypeRefinement,
                    );
                    return true;
                } else if upper_bound == Type::Truthy {
                    self.state.update_lower_bound(
                        &tv_id,
                        &Type::Truthy,
                        ChangeReason::ConcreteTypeRefinement,
                    );
                }
            }
        }
        false
    }
}
