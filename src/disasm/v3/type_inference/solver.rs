//! Type inference solver implementation.

use itertools::Itertools;
use log::debug;

use crate::disasm::v3::lir::{BinaryOperator, Expression, MemoryReferenceInfo};
use crate::disasm::v3::model::{FoldedSsaComplete, Model, TypeInferenceComplete};
use crate::disasm::v3::type_inference::constraints::AddConstraintResult;
use crate::disasm::v3::type_inference::type_bounds_map::ConverganceType;
use crate::disasm::v3::type_inference::types::TypeVarNode;
use crate::disasm::v3::type_inference::TypeInferenceResult;
use crate::disasm::v3::{FunctionId, InstructionId};
use crate::disasm::{Error, SymbolRenaming}; // Assuming a general error type for the project

use std::collections::{HashMap, HashSet, VecDeque};

use super::constraints::{ConstraintId, UnclassifiedArithmeticExpression};
use super::constraints_generator::generate_constraints;
use super::result::FunctionSignature;
use super::type_bounds_map::{BoundChangeReason, TypeVarRegistry};
use super::types::{TypeBounds, TypeVarId, TypeVarPath};
use super::{
    Constraint, ConstraintReason, ConstraintStore, InferenceAlgorithmState, Type, TypeVarState,
};

/// Trait for compound type refinement strategies
trait CompoundTypeRefinement {
    /// Check if this strategy can refine the given type variable
    fn can_refine(&self, tv_id: TypeVarId, state: &InferenceAlgorithmState) -> bool;

    /// Create the refinement pattern for this type variable
    fn create_pattern(
        &self,
        tv_id: TypeVarId,
        state: &mut InferenceAlgorithmState,
    ) -> CompoundTypePattern;

    /// Get the convergence type for this refinement
    fn convergence_type(&self) -> ConverganceType;
}

/// Declarative representation of how compound types decompose
#[derive(Debug, Clone)]
pub enum CompoundTypePattern {
    Function {
        args_tv_id: TypeVarId,
        rets_tv_id: TypeVarId,
    },
    Tuple {
        element_tv_ids: Vec<TypeVarId>,
    },
    Pointer {
        pointee_tv_id: TypeVarId,
    },
}

impl CompoundTypePattern {
    /// Construct the actual Type from this pattern
    fn into_type(self) -> Type {
        match self {
            CompoundTypePattern::Function {
                args_tv_id,
                rets_tv_id,
            } => Type::function(args_tv_id.to_type(), rets_tv_id.to_type()),
            CompoundTypePattern::Tuple { element_tv_ids } => Type::tuple(
                &element_tv_ids
                    .into_iter()
                    .map(|id| id.to_type())
                    .collect::<Vec<_>>(),
            ),
            CompoundTypePattern::Pointer { pointee_tv_id } => {
                Type::pointer(pointee_tv_id.to_type())
            }
        }
    }
}

/// Function refinement strategy
struct FunctionRefinement;

impl CompoundTypeRefinement for FunctionRefinement {
    fn can_refine(&self, tv_id: TypeVarId, state: &InferenceAlgorithmState) -> bool {
        if let Some(TypeVarState::Bounds {
            upper_bounds,
            lower_bounds,
        }) = state.get_type_var_state(&tv_id)
        {
            let has_function_upper = upper_bounds.iter().any(|t| t.is_function());
            let intersection_count = lower_bounds
                .intersection(upper_bounds)
                .filter(|t| t.is_function())
                .count();

            if intersection_count > 0 {
                panic!("Function bounds intersection should have been resolved earlier");
            }

            // Only refine if we have function bounds
            has_function_upper
        } else {
            false
        }
    }

    fn create_pattern(
        &self,
        tv_id: TypeVarId,
        state: &mut InferenceAlgorithmState,
    ) -> CompoundTypePattern {
        let function_id = state.get_type_var_node(&tv_id).unwrap().path.function_id();

        let args_tv_id = state.add_type_var(TypeVarNode {
            path: TypeVarPath::FunctionArgsRefinement {
                function_id,
                original_type_var_id: tv_id,
            },
            vmr: None,
        });

        let rets_tv_id = state.add_type_var(TypeVarNode {
            path: TypeVarPath::FunctionRetsRefinement {
                function_id,
                original_type_var_id: tv_id,
            },
            vmr: None,
        });

        CompoundTypePattern::Function {
            args_tv_id,
            rets_tv_id,
        }
    }

    fn convergence_type(&self) -> ConverganceType {
        ConverganceType::ReplacedWithFunctionType
    }
}

/// Tuple refinement strategy
struct TupleRefinement;

impl CompoundTypeRefinement for TupleRefinement {
    fn can_refine(&self, tv_id: TypeVarId, state: &InferenceAlgorithmState) -> bool {
        if let Some(TypeVarState::Bounds {
            upper_bounds,
            lower_bounds,
        }) = state.get_type_var_state(&tv_id)
        {
            let has_tuple_upper = upper_bounds.iter().any(|t| t.is_tuple());
            let intersection_count = lower_bounds
                .intersection(upper_bounds)
                .filter(|t| t.is_tuple())
                .count();

            if intersection_count > 0 {
                panic!("Tuple bounds intersection should have been resolved earlier");
            }

            // Only refine if we have tuple bounds
            has_tuple_upper
        } else {
            false
        }
    }

    fn create_pattern(
        &self,
        tv_id: TypeVarId,
        state: &mut InferenceAlgorithmState,
    ) -> CompoundTypePattern {
        let function_id = state.get_type_var_node(&tv_id).unwrap().path.function_id();
        let upper_bounds = state.upper_bounds(&tv_id);

        // Determine maximum arity from upper bounds
        let max_arity = upper_bounds
            .iter()
            .filter_map(|t| t.tuple_arity())
            .max()
            .unwrap_or(0);

        let element_tv_ids: Vec<TypeVarId> = (0..max_arity)
            .map(|index| {
                state.add_type_var(TypeVarNode {
                    path: TypeVarPath::TupleRefinement {
                        function_id,
                        original_type_var_id: tv_id,
                        index,
                    },
                    vmr: None,
                })
            })
            .collect();

        CompoundTypePattern::Tuple { element_tv_ids }
    }

    fn convergence_type(&self) -> ConverganceType {
        ConverganceType::ReplacedWithTuple
    }
}

/// Pointer refinement strategy
struct PointerRefinement;

impl CompoundTypeRefinement for PointerRefinement {
    fn can_refine(&self, tv_id: TypeVarId, state: &InferenceAlgorithmState) -> bool {
        if let Some(TypeVarState::Bounds {
            upper_bounds,
            lower_bounds,
        }) = state.get_type_var_state(&tv_id)
        {
            let has_pointer_upper = upper_bounds.iter().any(|t| t.is_pointer());
            let intersection_count = lower_bounds
                .intersection(upper_bounds)
                .filter(|t| t.is_pointer())
                .count();

            if intersection_count > 0 {
                panic!("Pointer bounds intersection should have been resolved earlier");
            }

            // Only refine if we have pointer bounds
            has_pointer_upper
        } else {
            false
        }
    }

    fn create_pattern(
        &self,
        tv_id: TypeVarId,
        state: &mut InferenceAlgorithmState,
    ) -> CompoundTypePattern {
        let function_id = state.get_type_var_node(&tv_id).unwrap().path.function_id();

        let pointee_tv_id = state.add_type_var(TypeVarNode {
            path: TypeVarPath::PointerRefinement {
                function_id,
                original_type_var_id: tv_id,
            },
            vmr: None,
        });

        CompoundTypePattern::Pointer { pointee_tv_id }
    }

    fn convergence_type(&self) -> ConverganceType {
        ConverganceType::ReplacedWithPointer
    }
}

/// Unified refinement engine for compound types
struct CompoundTypeRefiner {
    strategies: Vec<Box<dyn CompoundTypeRefinement>>,
}

impl CompoundTypeRefiner {
    fn new() -> Self {
        let strategies: Vec<Box<dyn CompoundTypeRefinement>> = vec![
            Box::new(FunctionRefinement),
            Box::new(TupleRefinement),
            Box::new(PointerRefinement),
        ];

        Self { strategies }
    }

    fn refine_compound_types(
        &self,
        vars: &[(TypeVarId, TypeVarState)],
        state: &mut InferenceAlgorithmState,
        function_types: &HashMap<FunctionId, (Type, Type)>,
        model: &Model<FoldedSsaComplete>,
        store: &mut ConstraintStore,
    ) -> bool {
        for (tv_id, type_state) in vars {
            if type_state.is_converged() {
                continue;
            }

            // Try each strategy in order
            for strategy in &self.strategies {
                if strategy.can_refine(*tv_id, state) {
                    let pattern = strategy.create_pattern(*tv_id, state);
                    let refined_type = pattern.clone().into_type();
                    let convergence_type = strategy.convergence_type();

                    state.converge(tv_id, refined_type, convergence_type);

                    // Handle special post-convergence logic
                    self.handle_post_convergence(
                        *tv_id,
                        &pattern,
                        state,
                        function_types,
                        model,
                        store,
                    );

                    return true; // Early return on first change
                }
            }
        }
        false
    }

    fn handle_post_convergence(
        &self,
        tv_id: TypeVarId,
        pattern: &CompoundTypePattern,
        state: &mut InferenceAlgorithmState,
        function_types: &HashMap<FunctionId, (Type, Type)>,
        model: &Model<FoldedSsaComplete>,
        store: &mut ConstraintStore,
    ) {
        // Handle special cases like function pointer derivation
        if let CompoundTypePattern::Function { .. } = pattern {
            let instruction_id = state
                .get_type_var_node(&tv_id)
                .unwrap()
                .path
                .instruction_id()
                .unwrap_or(InstructionId::new(0));
            let function_id = state.get_type_var_node(&tv_id).unwrap().path.function_id();

            // Inline the derive_when_subtype_of_function logic
            if let Some(Expression::Constant(addr)) = state
                .get_type_var_node(&tv_id)
                .unwrap()
                .path
                .expression_from_model(model)
            {
                if let Some((callee_arg_type, callee_ret_type)) =
                    function_types.get(&FunctionId::new(*addr as usize))
                {
                    let func_type =
                        Type::function(callee_arg_type.clone(), callee_ret_type.clone());
                    store.add_equality_constraint(
                        Constraint {
                            sub_type: func_type,
                            super_type: tv_id.to_type(),
                            origin_function_id: function_id,
                            origin_instruction_id: instruction_id,
                            reason: ConstraintReason::ConstIsFunctionPointer,
                        },
                        None,
                        state,
                    );
                }
            }
        }
    }
}

/// Represents a detected opportunity for generic type introduction
#[derive(Debug, Clone)]
struct GenericOpportunity {
    /// The refinement type variable that could become generic
    refinement_tv_id: TypeVarId,
    /// The concrete types that appear in the upper bounds
    concrete_types: Vec<Type>,
    /// The path of the refinement (e.g., PointerRefinement, TupleRefinement)
    refinement_path: TypeVarPath,
}

/// Solver for type inference.
///
/// The solver takes a model with folded SSA results and attempts to infer types
/// for virtual machine registers (VMRs) and memory locations by generating
/// and solving a set of type constraints.
pub struct Solver<'a> {
    /// The model containing the folded SSA result, which includes the CFG, DFG, and Function.
    model: Model<FoldedSsaComplete>,
    state: InferenceAlgorithmState,
    store: ConstraintStore,
    function_types: HashMap<FunctionId, (Type, Type)>,
    compound_type_refiner: CompoundTypeRefiner,
    symbol_renaming: &'a SymbolRenaming,
}

impl<'a> Solver<'a> {
    /// Creates a new solver instance.
    ///
    /// # Arguments
    ///
    /// * `model` - The model with folded SSA results.
    pub fn new(model: Model<FoldedSsaComplete>, symbol_renaming: &'a SymbolRenaming) -> Self {
        Self {
            model,
            state: InferenceAlgorithmState::new(),
            store: ConstraintStore::new(),
            function_types: HashMap::new(),
            compound_type_refiner: CompoundTypeRefiner::new(),
            symbol_renaming,
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
    pub fn run(
        model: Model<FoldedSsaComplete>,
        symbol_renaming: &'a SymbolRenaming,
    ) -> Result<Model<TypeInferenceComplete>, Error> {
        let solver = Self::new(model, symbol_renaming);
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
        let generator_result = generate_constraints(&self.model, self.symbol_renaming);
        self.store = generator_result.store;
        self.state = generator_result.state;
        self.function_types = generator_result.function_types;
        let markers = generator_result.markers;

        //
        let mut vars_worklist: Vec<TypeVarId> = self
            .state
            .iter_all_type_states()
            .map(|(id, _)| id)
            .cloned()
            .collect();
        loop {
            self.state.next_iteration();

            let mut constraint_ids: HashSet<ConstraintId> = HashSet::new();
            for tv_id in vars_worklist.iter() {
                self.store
                    .update_constraints_involving_type_var_id(*tv_id, &self.state);
                for c in self
                    .store
                    .get_constraints_involving_type_var(tv_id)
                    .into_iter()
                    .flatten()
                {
                    constraint_ids.insert(*c);
                }
            }
            let mut constraint_ids: VecDeque<ConstraintId> = constraint_ids.into_iter().collect();
            while !constraint_ids.is_empty() {
                while let Some(constraint_id) = constraint_ids.pop_front() {
                    let new_constraints = self.apply_constraint(constraint_id);
                    for constraint in new_constraints {
                        match self.store.add_constraint(
                            constraint,
                            Some(constraint_id),
                            &self.state,
                        ) {
                            AddConstraintResult::NewConstraint(id)
                            | AddConstraintResult::ExistingConstraint(id) => {
                                constraint_ids.push_back(id)
                            }
                            _ => {}
                        }
                    }
                }

                let e = self
                    .store
                    .iter_unclassified_add_expressions()
                    .cloned()
                    .collect_vec();
                for unclassified in e {
                    for constraint in self.try_classify_add_expression(&unclassified) {
                        match self.store.add_constraint(constraint, None, &self.state) {
                            AddConstraintResult::NewConstraint(id) => constraint_ids.push_back(id),
                            _ => {}
                        }
                    }
                }
            }

            let changed = self.try_solving();

            if !changed {
                break;
            }
            vars_worklist = self.state.take_updated_vars();
        }

        // Phase 2 & 3: Detect and transform generic patterns iteratively
        // We need multiple passes because some refinements depend on others
        let mut iteration = 0;
        loop {
            let generic_opportunities = self.detect_generic_patterns();
            if generic_opportunities.is_empty() {
                debug!(
                    "Iteration {}: No more generic opportunities detected",
                    iteration
                );
                break;
            }

            debug!(
                "Iteration {}: Detected {} generic pattern opportunities",
                iteration,
                generic_opportunities.len()
            );
            for opportunity in &generic_opportunities {
                debug!(
                    "Generic opportunity: TypeVar {} ({:?}) with bounds {:?}",
                    opportunity.refinement_tv_id,
                    opportunity.refinement_path,
                    opportunity
                        .concrete_types
                        .iter()
                        .map(|t| t.display_with(&self.state).to_string())
                        .collect::<Vec<_>>()
                );
            }

            // Transform detected patterns into generic types
            let transformed_count = self.apply_generic_transformations(generic_opportunities);

            debug!("Transformed {} type variables", transformed_count);

            if transformed_count == 0 {
                // No more transformations possible
                debug!("No more generic transformations possible");
                break;
            }

            iteration += 1;
        }

        let mut result = TypeInferenceResult::new();
        result.type_var_nodes = self
            .state
            .iter_all_type_nodes()
            .map(|(id, var)| (*id, var.clone()))
            .collect();
        for (id, state) in self.state.iter_all_type_states() {
            match state {
                TypeVarState::Bounds { .. } => {
                    result.type_var_states.insert(*id, state.clone());
                }
                TypeVarState::Converged(ty) => {
                    self.state.resolve_type(ty);
                }
            }
            result.type_var_states.insert(*id, state.clone());
            let node = self.state.get_type_var_node(id).unwrap();
            if let Some(vmr) = node.vmr {
                result.vmr_to_type_var_id.insert(vmr, *id);
            }
            result.path_to_type_var_id.insert(node.path.clone(), *id);
        }
        result.debug_markers = markers;

        result.constraint_store = self.store;
        result.generic_type_vars = self.state.generic_type_vars();
        result.change_log = self.state.change_log;
        result.custom_type_names = self.symbol_renaming.get_custom_types().clone();
        for (function_id, _) in self.model.functions() {
            let args = self.model.function_call_analysis_result().functions[&function_id]
                .parameter_entry_vars
                .values()
                .sorted_by_key(|v| v.as_stack_relative().unwrap())
                .map(|v| (*v, result.get_type_for(v), result.get_type_id_for_vmr(v)))
                .collect_vec();
            let returns = self
                .model
                .function_call_analysis_result()
                .get_effective_return_values(function_id)
                .unwrap_or_default()
                .iter()
                .sorted_by_key(|(v, _)| v)
                .map(|(_, v)| (*v, result.get_type_for(v), result.get_type_id_for_vmr(v)))
                .collect_vec();
            result
                .function_signatures
                .insert(function_id, FunctionSignature { args, returns });
        }

        // 9. Finalize the result and embed it into a new model state.
        let result_model = self.model.with_type_inference_result(result);

        // Create query engine from the solver's final state

        Ok(result_model)
    }

    // Applies a constraint and returns new constraints derived from it.
    fn apply_constraint(&mut self, constraint_id: ConstraintId) -> Vec<Constraint> {
        let constraint = self.store.get_constraint_by_id(constraint_id).unwrap();
        let mut new_constraints: Vec<Constraint> = vec![];
        let sub_type = self.state.resolve_type(&constraint.sub_type);
        let super_type = self.state.resolve_type(&constraint.super_type);
        if let Type::TypeVar(tv_id) = &sub_type {
            self.state.update_upper_bound(
                tv_id,
                &super_type,
                BoundChangeReason::Constraint(constraint_id),
            );
        }
        if let Type::TypeVar(tv_id) = &super_type {
            self.state.update_lower_bound(
                tv_id,
                &sub_type,
                BoundChangeReason::Constraint(constraint_id),
            );
        }

        match (&sub_type, &super_type) {
            (Type::TypeVar(lower_tvid), Type::TypeVar(upper_tvid)) if lower_tvid == upper_tvid => {
                self.state.update_lower_bound(
                    lower_tvid,
                    &sub_type,
                    BoundChangeReason::Constraint(constraint_id),
                );
            }
            (Type::Tuple(ts), Type::Tuple(us)) => {
                for (idx, (t, u)) in ts.iter().zip(us).enumerate() {
                    new_constraints.push(Constraint::new(
                        t.clone(),
                        u.clone(),
                        constraint.origin_function_id,
                        constraint.origin_instruction_id,
                        ConstraintReason::TupleElementSubtype(idx),
                    ));
                }
            }
            (Type::Pointer(x), Type::Pointer(y)) => {
                // Pointer subtyping
                new_constraints.push(Constraint::new(
                    *x.clone(),
                    *y.clone(),
                    constraint.origin_function_id,
                    constraint.origin_instruction_id,
                    ConstraintReason::PointerSubtype,
                ));
            }
            (
                Type::Function {
                    params: params1,
                    returns: returns1,
                },
                Type::Function {
                    params: params2,
                    returns: returns2,
                },
            ) => {
                let params_constraint = Constraint::new(
                    params2.as_ref().clone(),
                    params1.as_ref().clone(),
                    constraint.origin_function_id,
                    constraint.origin_instruction_id,
                    ConstraintReason::FunctionParamsSubtype,
                );

                let returns_constraint = Constraint::new(
                    returns1.as_ref().clone(),
                    returns2.as_ref().clone(),
                    constraint.origin_function_id,
                    constraint.origin_instruction_id,
                    ConstraintReason::FunctionReturnsSubtype,
                );
                new_constraints.push(params_constraint);
                new_constraints.push(returns_constraint);
            }
            _ => {}
        }
        new_constraints
    }

    fn try_classify_add_expression(
        &mut self,
        unclassified: &UnclassifiedArithmeticExpression,
    ) -> Vec<Constraint> {
        let Expression::Binary { op, .. } = &unclassified.expression else {
            panic!("Expected BinaryOp expression");
        };
        if op != &BinaryOperator::Add && op != &BinaryOperator::Sub {
            panic!("Expected Add or Sub operator");
        }
        let Type::TypeVar(op1_tvid) = unclassified.lhs_type else {
            panic!("Expected TypeVar for lhs type");
        };
        let Type::TypeVar(op2_tvid) = unclassified.rhs_type else {
            panic!("Expected TypeVar for rhs type");
        };
        let Type::TypeVar(res_tvid) = unclassified.result_type else {
            panic!("Expected TypeVar for result type");
        };
        let op1 = self.state.resolve_type(&op1_tvid.to_type());
        let op2 = self.state.resolve_type(&op2_tvid.to_type());
        let res = self.state.resolve_type(&res_tvid.to_type());

        let is_op1_int = op1.is_subtype_of(&Type::Int, &self.state).is_yes();
        let is_op2_int = op2.is_subtype_of(&Type::Int, &self.state).is_yes();
        let is_op1_char = op1.is_subtype_of(&Type::Char, &self.state).is_yes();
        let is_op2_char = op2.is_subtype_of(&Type::Char, &self.state).is_yes();
        let is_result_int = res.is_subtype_of(&Type::Int, &self.state).is_yes();
        let is_op1_pointer = op1
            .is_subtype_of(&Type::pointer(Type::Any), &self.state)
            .is_yes();
        let is_op2_pointer = op2
            .is_subtype_of(&Type::pointer(Type::Any), &self.state)
            .is_yes();
        let is_result_pointer = res
            .is_subtype_of(&Type::pointer(Type::Any), &self.state)
            .is_yes();
        let is_result_char = Type::Char.is_subtype_of(&res, &self.state).is_yes();
        let mut new_constraints = Vec::new();

        let mut add_constraint = |sub_type: Type, super_type: Type, reason: ConstraintReason| {
            new_constraints.push(Constraint::new(
                sub_type,
                super_type,
                FunctionId::new(0),
                InstructionId::new(0),
                reason,
            ));
        };

        if is_op1_int && is_op2_int {
            add_constraint(
                unclassified.result_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticResultBothInt,
            );
        }
        if (is_result_int || is_result_char || is_result_pointer) && is_op1_int {
            add_constraint(
                unclassified.rhs_type.clone(),
                res.clone(),
                ConstraintReason::ArithmeticOperandToIntLikeResult,
            );
            add_constraint(
                res.clone(),
                unclassified.rhs_type.clone(),
                ConstraintReason::ArithmeticOperandToIntLikeResult,
            );
        }
        if (is_result_int || is_result_char || is_result_pointer) && is_op2_int {
            add_constraint(
                unclassified.lhs_type.clone(),
                res.clone(),
                ConstraintReason::ArithmeticOperandToIntLikeResult,
            );
            add_constraint(
                res.clone(),
                unclassified.lhs_type.clone(),
                ConstraintReason::ArithmeticOperandToIntLikeResult,
            );
        }
        if is_op1_char || is_op1_pointer {
            add_constraint(
                unclassified.rhs_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticOtherOperandMustBeInt,
            );
            add_constraint(
                res.clone(),
                op1.clone(),
                ConstraintReason::ArithmeticResultMatchesOther,
            );
            add_constraint(
                op1,
                res.clone(),
                ConstraintReason::ArithmeticResultMatchesOther,
            );
        }
        if is_op2_char || is_op2_pointer {
            add_constraint(
                unclassified.lhs_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticOtherOperandMustBeInt,
            );
            add_constraint(
                res.clone(),
                op2.clone(),
                ConstraintReason::ArithmeticResultMatchesOther,
            );
            add_constraint(
                op2,
                res.clone(),
                ConstraintReason::ArithmeticResultMatchesOther,
            );
        }
        if is_op1_int {
            add_constraint(
                unclassified.rhs_type.clone(),
                unclassified.result_type.clone(),
                ConstraintReason::ArithmeticIntOperandImpliesResult,
            );
            add_constraint(
                unclassified.result_type.clone(),
                unclassified.rhs_type.clone(),
                ConstraintReason::ArithmeticIntOperandImpliesResult,
            );
        }
        if is_op2_int {
            add_constraint(
                unclassified.lhs_type.clone(),
                unclassified.result_type.clone(),
                ConstraintReason::ArithmeticIntOperandImpliesResult,
            );
            add_constraint(
                unclassified.result_type.clone(),
                unclassified.lhs_type.clone(),
                ConstraintReason::ArithmeticIntOperandImpliesResult,
            );
        }
        if is_result_int {
            add_constraint(
                unclassified.lhs_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticResultBothInt,
            );
            add_constraint(
                unclassified.rhs_type.clone(),
                Type::Int,
                ConstraintReason::ArithmeticResultBothInt,
            );
        }

        new_constraints
    }

    fn effective_glb(&self, types: &[Type]) -> Option<Type> {
        if !types.iter().all(|t| t.is_concrete_type()) {
            return None;
        }
        if types.len() == 1 && types[0].is_concrete_type() {
            return Some(types[0].clone());
        }
        for i in types {
            if types
                .iter()
                .all(|j| i.is_subtype_of(j, &self.state).is_yes())
            {
                return Some(i.clone());
            }
        }
        None
    }

    fn effective_lub(&self, types: &[Type]) -> Option<Type> {
        if !types.iter().all(|t| t.is_concrete_type()) {
            return None;
        }
        if types.len() == 1 && types[0].is_concrete_type() {
            return Some(types[0].clone());
        }
        None
    }

    fn try_solving(&mut self) -> bool {
        let mut conv = HashMap::new();
        for (tv_id, state) in self.state.iter_all_type_states() {
            match state {
                TypeVarState::Bounds {
                    lower_bounds,
                    upper_bounds,
                } => {
                    if conv.contains_key(tv_id) {
                        // already processed as a type alias (was the max end)
                        continue;
                    }
                    let intersection: Vec<&Type> = lower_bounds
                        .intersection(upper_bounds)
                        .filter(|t| **t != tv_id.to_type())
                        .sorted()
                        .collect_vec();
                    if let Ok(&concrete) = intersection
                        .iter()
                        .filter(|t| t.is_concrete_type())
                        .exactly_one()
                    {
                        conv.insert(*tv_id, concrete.clone());
                    } else if let Some(&t) = intersection.iter().find_map(|t| t.as_type_var_id()) {
                        // To prevent cycles, make the larger tv_id always converge to the smaller id, unless it converged in a prior iteration.
                        let (u, v) = if self.state.get_type_var_state(&t).unwrap().is_converged() {
                            (*tv_id, t)
                        } else {
                            (t.max(*tv_id), t.min(*tv_id))
                        };
                        conv.insert(u, v.to_type());
                    } else if let Some(item) = intersection.iter().find(|t| !t.is_concrete_type()) {
                        // The case of exactly one concrete convergence is handle above. We don't want to pocess here cases of two or more concrete convergences -
                        // since it is potentially a generic type or a conflict.
                        conv.insert(*tv_id, (*item).clone());
                    }
                }
                TypeVarState::Converged(_) => continue,
            }
        }
        let mut changed = false;
        let mut converge_count = 0;
        for (tv_id, target_type) in conv.iter().sorted() {
            let new_value = self.state.resolve_type(target_type);
            if new_value == tv_id.to_type() {
                continue;
            }
            let conv_type = if new_value.is_concrete_type() {
                ConverganceType::ConcreteConvergence
            } else {
                ConverganceType::NonConcreteConvergence
            };
            self.state.converge(tv_id, new_value, conv_type);
            changed = true;
            converge_count += 1;
        }
        if changed {
            return true;
        }

        let vars = self
            .state
            .iter_all_type_states()
            .map(|(id, state)| (*id, state.clone()))
            .collect_vec();
        changed |= self.compound_type_refiner.refine_compound_types(
            &vars,
            &mut self.state,
            &self.function_types,
            &self.model,
            &mut self.store,
        );
        if changed {
            return true;
        }

        for (tv_id, state) in vars {
            if let TypeVarState::Bounds {
                lower_bounds,
                upper_bounds,
            } = state
            {
                let effective_glb = self.effective_glb(
                    &upper_bounds
                        .iter()
                        .filter(|t| !t.is_numeric_literal())
                        .cloned()
                        .collect_vec(),
                );
                let effective_lub = self.effective_lub(
                    &lower_bounds
                        .iter()
                        .filter(|t| !t.is_numeric_literal())
                        .cloned()
                        .collect_vec(),
                );
                if effective_lub.is_some() {
                    debug!(
                        "Type {} {} converged to {} (effective lub)",
                        tv_id,
                        tv_id.display_with(&self.state),
                        effective_lub.as_ref().unwrap().display_with(&self.state)
                    );
                    self.state.converge(
                        &tv_id,
                        effective_lub.unwrap(),
                        ConverganceType::ConvergeToLUB,
                    );
                    return true;
                }
                if let Some(glb) = effective_glb {
                    debug!(
                        "Type {} {} converged to {} (effective glb)",
                        tv_id,
                        tv_id.display_with(&self.state),
                        glb.display_with(&self.state)
                    );
                    let final_type = if glb == Type::NumericLiteral {
                        Type::Int
                    } else {
                        glb
                    };
                    self.state
                        .converge(&tv_id, final_type, ConverganceType::ConvergeToGLB);
                    return true;
                }
                if upper_bounds
                    .iter()
                    .exactly_one()
                    .is_ok_and(|t| t.is_numeric_literal())
                {
                    self.state
                        .converge(&tv_id, Type::Int, ConverganceType::ConvergeToGLB);
                    return true;
                }
            }
        }
        false
    }

    /// Detects patterns in refinement type variables that could benefit from generics
    fn detect_generic_patterns(&self) -> Vec<GenericOpportunity> {
        let mut opportunities = Vec::new();

        for (tv_id, state) in self.state.iter_all_type_states() {
            if let TypeVarState::Bounds {
                upper_bounds,
                lower_bounds: _,
            } = state
            {
                // Look for patterns like ty59: upper bounds {Char, Truthy, Int}
                // Include all types that could represent different concrete types
                let potential_generic_types: Vec<_> = upper_bounds
                    .iter()
                    .filter(|t| Self::is_potential_generic_type(t))
                    .cloned()
                    .collect();

                // Check if this is a refinement type variable OR has generic bounds
                if let Some(node) = self.state.get_type_var_node(tv_id) {
                    let has_generic = upper_bounds.iter().any(|t| matches!(t, Type::Generic(_)));
                    let generic_count = upper_bounds
                        .iter()
                        .filter(|t| matches!(t, Type::Generic(_)))
                        .count();

                    if self.is_refinement_path(&node.path) {
                        // Original logic for refinement paths
                        if potential_generic_types.len() >= 2
                            || (has_generic && generic_count == upper_bounds.len())
                        {
                            opportunities.push(GenericOpportunity {
                                refinement_tv_id: *tv_id,
                                concrete_types: upper_bounds.iter().cloned().collect(),
                                refinement_path: node.path.clone(),
                            });
                        }
                    } else if has_generic && upper_bounds.len() > 1 {
                        // New case: Non-refinement paths with generic + other types
                        // This handles cases like ty581 with bounds {T, Int}
                        // Check if all non-generic bounds are compatible with the generic's bounds
                        let generics_in_bounds: Vec<_> = upper_bounds
                            .iter()
                            .filter(|t| matches!(t, Type::Generic(_)))
                            .collect();

                        if generics_in_bounds.len() == 1 {
                            if let Type::Generic(generic_id) = generics_in_bounds[0] {
                                if let Some(generic_var) =
                                    self.state.get_generic_type_var(generic_id)
                                {
                                    let non_generic_bounds: Vec<_> = upper_bounds
                                        .iter()
                                        .filter(|t| !matches!(t, Type::Generic(_)))
                                        .collect();

                                    // Check if all non-generic bounds are subtypes of the generic's bounds
                                    let all_compatible =
                                        non_generic_bounds.iter().all(|other_type| {
                                            generic_var.bounds.upper_bounds.iter().any(
                                                |generic_bound| {
                                                    other_type
                                                        .is_subtype_of(generic_bound, &self.state)
                                                        .is_yes()
                                                },
                                            )
                                        });

                                    if all_compatible {
                                        opportunities.push(GenericOpportunity {
                                            refinement_tv_id: *tv_id,
                                            concrete_types: upper_bounds.iter().cloned().collect(),
                                            refinement_path: node.path.clone(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        opportunities
    }

    /// Checks if a TypeVarPath represents a refinement that could be made generic
    fn is_refinement_path(&self, path: &TypeVarPath) -> bool {
        matches!(
            path,
            TypeVarPath::PointerRefinement { .. }
                | TypeVarPath::TupleRefinement { .. }
                | TypeVarPath::FunctionArgsRefinement { .. }
                | TypeVarPath::FunctionRetsRefinement { .. }
                | TypeVarPath::FunctionDefArg { .. }
                | TypeVarPath::FunctionDefRet { .. }
        )
    }

    /// Determines if a type could represent different concrete types and thus be part of a generic pattern
    fn is_potential_generic_type(ty: &Type) -> bool {
        match ty {
            // Concrete types that could vary
            Type::Int | Type::Bool | Type::Char | Type::Truthy => true,

            Type::CustomType(_) => true,

            // Any might represent unconverged types
            Type::Any => true,

            // Type variables could resolve to different types
            Type::TypeVar(_) => true,

            // Generic types are also potential indicators of generic patterns
            Type::Generic(_) => true,

            // Recursively check compound types
            Type::Pointer(inner) => Self::is_potential_generic_type(inner),
            Type::Function { params, returns } => {
                Self::is_potential_generic_type(params) || Self::is_potential_generic_type(returns)
            }
            Type::Tuple(elements) => elements.iter().any(Self::is_potential_generic_type),

            // These are not considered generic
            Type::NumericLiteral | Type::Nothing => false,
        }
    }

    /// Apply generic transformations to the detected opportunities
    /// Returns the number of type variables that were actually transformed
    fn apply_generic_transformations(&mut self, opportunities: Vec<GenericOpportunity>) -> usize {
        let mut transformed_count = 0;

        for opportunity in opportunities {
            // Check if this specific refinement has already been converged to a generic
            if let Some(TypeVarState::Converged(Type::Generic(_))) =
                self.state.get_type_var_state(&opportunity.refinement_tv_id)
            {
                continue;
            }

            let all_bounds: HashSet<Type> = opportunity.concrete_types.iter().cloned().collect();

            // Create the generic type variable - let the state handle ID assignment
            let generic_bounds = TypeBounds::with_upper_bounds(all_bounds.clone());
            let generic_id = self
                .state
                .create_generic_type_var_with_bounds(generic_bounds);

            debug!(
                "Created generic {} with bounds: {:?}",
                generic_id.display_with(&self.state),
                all_bounds
                    .iter()
                    .map(|t| t.display_with(&self.state).to_string())
                    .collect::<Vec<_>>()
            );

            // Replace the refinement type variable with the generic type
            self.state.converge(
                &opportunity.refinement_tv_id,
                Type::Generic(generic_id),
                ConverganceType::ReplacedWithGeneric,
            );

            debug!(
                "Replaced TypeVar {} with generic type {}",
                opportunity.refinement_tv_id,
                generic_id.display_with(&self.state)
            );

            transformed_count += 1;
        }

        transformed_count
    }
}
