use colored::Colorize;
use itertools::Itertools;
use log::{info, trace};
use std::collections::HashMap;
use std::fmt;

use super::constraints::{Constraint, ConstraintReason};
use super::result::TypeInferenceResult;
use super::types::{is_concrete_type, VariableKind};
use super::visuals::TraceColors;
use crate::disasm;
use crate::disasm::v2::instructions::InstructionId;
use crate::disasm::v2::model::{FunctionId, ProgramModel};
use crate::disasm::v2::ssa_form::SsaOperand;
use crate::disasm::v2::type_inference::types::{glb, lub, Type};

/// Enum to distinguish between upper and lower bound conflicts
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum BoundType {
    Upper,
    Lower,
}

impl fmt::Display for BoundType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundType::Upper => write!(f, "Upper"),
            BoundType::Lower => write!(f, "Lower"),
        }
    }
}

impl BoundType {
    pub fn is_upper(&self) -> bool {
        matches!(self, BoundType::Upper)
    }

    pub fn is_lower(&self) -> bool {
        matches!(self, BoundType::Lower)
    }

    pub fn other(&self) -> Self {
        match self {
            BoundType::Upper => BoundType::Lower,
            BoundType::Lower => BoundType::Upper,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeBounds {
    pub lower: Type,
    pub upper: Type,
}

impl TypeBounds {
    fn new(lower: Type, upper: Type) -> Self {
        Self { lower, upper }
    }
}

pub(crate) struct TypeBoundsMap {
    bounds: HashMap<VariableKind, TypeBounds>,
    pub traces: Vec<AnalysisTrace>,
}

impl TypeBoundsMap {
    fn new() -> Self {
        Self {
            bounds: HashMap::new(),
            traces: Vec::new(),
        }
    }

    fn all_keys(&self) -> Vec<VariableKind> {
        self.bounds.keys().cloned().collect()
    }

    fn iter(&self) -> std::collections::hash_map::Iter<'_, VariableKind, TypeBounds> {
        self.bounds.iter()
    }

    fn upper_bound(&self, key: &VariableKind) -> Option<&Type> {
        self.bounds.get(key).map(|b| &b.upper)
    }

    fn lower_bound(&self, key: &VariableKind) -> Option<&Type> {
        self.bounds.get(key).map(|b| &b.lower)
    }

    fn create_key(&mut self, key: VariableKind, lower: Type, upper: Type) {
        assert!(
            self.bounds
                .insert(key, TypeBounds::new(lower, upper))
                .is_none(),
            "Attempted to create existing key: {}",
            key
        );
    }

    fn contains_key(&self, key: &VariableKind) -> bool {
        self.bounds.contains_key(key)
    }

    fn update_bound(
        &mut self,
        key: VariableKind,
        bound_type: BoundType,
        new_value: Type,
        reason: ChangeReason,
    ) -> Result<bool, disasm::Error> {
        let old_bounds = self
            .bounds
            .get(&key)
            .cloned()
            .expect(format!("Update bound for missing key: {}", key).as_str());
        let mut new_bounds = old_bounds.clone();
        match bound_type {
            BoundType::Lower => new_bounds.lower = new_value,
            BoundType::Upper => new_bounds.upper = new_value,
        }
        if old_bounds == new_bounds {
            return Ok(false);
        }
        if !new_bounds.lower.is_subtype_of(&new_bounds.upper) {
            return Err(disasm::Error::TypeInconsistency {
                key: key.clone(),
                bound_type,
                lower: new_bounds.lower,
                upper: new_bounds.upper,
            });
        }
        let trace = AnalysisTrace {
            key: key.clone(),
            change: BoundChange {
                bound_type,
                old_bounds,
                new_bounds: new_bounds.clone(),
            },
            reason,
        };
        trace!("{}", trace);
        self.bounds.insert(key, new_bounds);
        self.traces.push(trace);
        Ok(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundChange {
    pub bound_type: BoundType,
    pub old_bounds: TypeBounds,
    pub new_bounds: TypeBounds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeReason {
    DecreaseUpperBoundFromConstraint { constraint: Constraint, other: Type },
    IncreaseLowerBoundFromConstraint { constraint: Constraint, other: Type },
    ConcreteRefinement,
    TruthyToBoolHeuristic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisTrace {
    pub key: VariableKind,
    pub change: BoundChange,
    pub reason: ChangeReason,
}

impl fmt::Display for AnalysisTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Colorize the key type

        let key_str = TraceColors::format_var(&self.key);

        if self.change.bound_type == BoundType::Upper {
            write!(
                f,
                "{} {:>14} {} {:<18} was {:<8}",
                TraceColors::format_header("Type"),
                key_str,
                ":<".blue(),
                TraceColors::format_type(&self.change.new_bounds.upper),
                TraceColors::format_type(&self.change.old_bounds.upper)
            )?;
        } else {
            write!(
                f,
                "{} {:>14} {} {:<18} was {:<8}",
                TraceColors::format_header("Type"),
                key_str,
                ":>".green(),
                TraceColors::format_type(&self.change.new_bounds.lower),
                TraceColors::format_type(&self.change.old_bounds.lower)
            )?;
        }

        match &self.reason {
            ChangeReason::DecreaseUpperBoundFromConstraint { constraint, other } => {
                let other_str = if let Type::Variable(var) = other {
                    TraceColors::format_var(var)
                } else {
                    TraceColors::format_type(other)
                };

                let constraint_str = format!("{}", TraceColors::format_constraint(constraint),);

                write!(f, "  {} caused by {}", constraint_str, other_str)
            }
            ChangeReason::IncreaseLowerBoundFromConstraint { constraint, other } => {
                let other_str = if let Type::Variable(var) = other {
                    TraceColors::format_var(var)
                } else {
                    TraceColors::format_type(other)
                };
                let constraint_str = format!("{}", TraceColors::format_constraint(constraint),);
                write!(f, "  {} caused by {}", constraint_str, other_str)
            }
            ChangeReason::ConcreteRefinement => {
                write!(
                    f,
                    "  {}",
                    TraceColors::format_bound("Concrete type refinement")
                )
            }
            ChangeReason::TruthyToBoolHeuristic => {
                write!(
                    f,
                    "  {}",
                    TraceColors::format_bound("Truthy to Bool heuristic")
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FunctionPointerInfo {
    args: Type,               // tuple of argument types
    returns: Type,            // tuple of return types
    arg_count: Option<usize>, // number of arguments
    ret_count: Option<usize>, // number of return arguments
}

struct Solver {
    model: ProgramModel,
    debug_markers: HashMap<char, SsaOperand>,
    constraints: Vec<Constraint>,
    bounds_map: TypeBoundsMap,
    function_pointer_variables: HashMap<VariableKind, FunctionPointerInfo>,
}

impl Solver {
    fn new(
        model: ProgramModel,
        constraints: &[Constraint],
        debug_markers: HashMap<char, SsaOperand>,
    ) -> Self {
        Self {
            model,
            debug_markers,
            constraints: constraints.to_vec(),
            bounds_map: TypeBoundsMap::new(),
            function_pointer_variables: HashMap::new(),
        }
    }

    fn unify(&mut self) -> Result<TypeInferenceResult, disasm::Error> {
        let constraints = self.constraints.to_vec();
        for c in &constraints {
            init_bounds_for_type(&c.left, &mut self.bounds_map);
            init_bounds_for_type(&c.right, &mut self.bounds_map);
        }
        loop {
            while self.reach_constraint_fixed_point()? {}
            if refine_concrete_types(&mut self.bounds_map)? {
                continue;
            }
            if replace_truthy_with_bool(&mut self.bounds_map)? {
                trace!("Replaced truthy with bool changed");
                continue;
            }
            break;
        }
        info!("{}", "Type inference completed successfully".bold());
        for (function_id, key, value) in self
            .bounds_map
            .iter()
            .filter_map(|(key, value)| key.origin_info().map(|oi| (oi.function_id, key, value)))
            .sorted()
        {
            log::debug!(
                "Type for {:>15} <: {:<15} <: {}",
                value.lower.to_string().purple(),
                format!("{}:{}", function_id, key).blue(),
                value.upper.to_string().green()
            );
        }

        Ok(self.build_result())
    }

    fn reach_constraint_fixed_point(&mut self) -> Result<bool, disasm::Error> {
        let mut overall_changed = false;
        loop {
            let mut changed_in_iteration = false;
            let mut worklist = self.constraints.to_vec(); // Clone constraints into a worklist
                                                          // self.add_indirect_function_call_constraints(&mut worklist);
            while let Some(c) = worklist.pop() {
                let (changed, constraints) = self.process_constraint(&c)?;
                changed_in_iteration |= changed;
                overall_changed |= changed_in_iteration;
                worklist.extend(constraints);
            }
            if !changed_in_iteration {
                return Ok(overall_changed);
            }
        }
    }

    fn process_constraint(
        &mut self,
        constraint: &Constraint,
    ) -> Result<(bool, Vec<Constraint>), disasm::Error> {
        let mut result = vec![];
        let mut changed = false;
        if let Type::Variable(u) = &constraint.left {
            let current_upper = self.bounds_map.upper_bound(u).unwrap();
            let eub = effective_upper_bound(&constraint.right, &self.bounds_map);
            let glb = glb(&current_upper, &eub);
            let glb = self.ok_or_bound_conflict(
                u,
                glb,
                BoundType::Upper,
                current_upper.clone(),
                eub,
                &constraint,
            )?;
            changed |= self.bounds_map.update_bound(
                u.clone(),
                BoundType::Upper,
                glb.clone(),
                ChangeReason::DecreaseUpperBoundFromConstraint {
                    constraint: constraint.clone(),
                    other: constraint.right.clone(),
                },
            )?;
            if glb.is_function_pointer() {
                let fpi = self
                    .function_pointer_variables
                    .entry(*u)
                    .or_insert_with(|| {
                        let args = Type::new_var();
                        let returns = Type::new_var();
                        init_bounds_for_type(&args, &mut self.bounds_map);
                        init_bounds_for_type(&returns, &mut self.bounds_map);
                        trace!(
                            "Identified {} as a function pointer {} -> {}",
                            TraceColors::format_var(u),
                            TraceColors::format_type(&args),
                            TraceColors::format_type(&returns)
                        );
                        changed = true;
                        FunctionPointerInfo {
                            args,
                            returns,
                            arg_count: None,
                            ret_count: None,
                        }
                    });
                let fp = Type::function_pointer(fpi.args.clone(), fpi.returns.clone());
                if constraint.right != fp {
                    // prevents adding a copy of the current constraint.
                    result.push(Constraint {
                        left: constraint.left.clone(),
                        right: fp,
                        addr: constraint.addr,
                        function_id: constraint.function_id,
                        reason: ConstraintReason::FunctionPointerSignature,
                    });
                }
            }
        }
        if let Type::Variable(v) = &constraint.right {
            let current_lower = self.bounds_map.lower_bound(v).unwrap();
            let elb = effective_lower_bound(&constraint.left, &self.bounds_map);
            let lub = lub(&current_lower, &elb);
            let lub = self.ok_or_bound_conflict(
                v,
                lub,
                BoundType::Lower,
                current_lower.clone(),
                elb,
                &constraint,
            )?;
            changed |= self.bounds_map.update_bound(
                v.clone(),
                BoundType::Lower,
                lub,
                ChangeReason::IncreaseLowerBoundFromConstraint {
                    constraint: constraint.clone(),
                    other: constraint.left.clone(),
                },
            )?;
        }
        changed |= self.handle_function_pointer_constraints(constraint, &mut result)?;
        match (&constraint.left, &constraint.right) {
            (Type::Pointer(x), Type::Pointer(y)) => {
                result.push(Constraint {
                    left: *x.clone(),
                    right: *y.clone(),
                    addr: constraint.addr,
                    function_id: constraint.function_id,
                    reason: ConstraintReason::PointerSubtype,
                });
            }

            (Type::Tuple(ts), Type::Tuple(us)) => {
                assert!(ts.len() == us.len());
                for (t, u) in ts.iter().zip(us) {
                    result.push(Constraint {
                        left: t.clone(),
                        right: u.clone(),
                        addr: constraint.addr,
                        function_id: constraint.function_id,
                        reason: ConstraintReason::TupleSubtype,
                    });
                }
            }
            (Type::Tuple(ts), right)
                if effective_upper_bound(right, &self.bounds_map)
                    .as_tuple()
                    .is_some() =>
            {
                let us = effective_upper_bound(right, &self.bounds_map)
                    .as_tuple()
                    .cloned()
                    .unwrap();
                assert!(ts.len() == us.len());
                for (t, u) in ts.iter().zip(us) {
                    result.push(Constraint {
                        left: t.clone(),
                        right: u.clone(),
                        addr: constraint.addr,
                        function_id: constraint.function_id,
                        reason: ConstraintReason::TupleSubtype,
                    });
                }
            }
            (Type::Function { args: a1, .. }, Type::Function { args: a2, .. }) => {
                result.push(Constraint {
                    left: *a2.clone(),
                    right: *a1.clone(),
                    addr: constraint.addr,
                    function_id: constraint.function_id,
                    reason: ConstraintReason::FunctionTypeParameter,
                });
            }
            _ => {}
        };
        Ok((changed, result))
    }

    /// Create a TypeInferenceResult from the current state of bounds
    fn build_result(&self) -> TypeInferenceResult {
        let inferred_types = self
            .bounds_map
            .iter()
            .filter_map({
                |(k, v)| match k {
                    VariableKind::SsaVar(var) => {
                        let typ = if specifity(&v.upper) >= specifity(&v.lower) {
                            &v.upper
                        } else {
                            &v.lower
                        };
                        Some((*var, typ.clone()))
                    }
                    _ => None,
                }
            })
            .collect();

        // Collect inferred function signatures from function pointer variables
        let mut function_signatures = HashMap::new();

        for (var_kind, fp_info) in &self.function_pointer_variables {
            if let VariableKind::Const { value, .. } = var_kind {
                let function_id = FunctionId::from(*value as usize);

                let args = effective_lower_bound(&fp_info.args, &self.bounds_map);
                let returns = effective_upper_bound(&fp_info.returns, &self.bounds_map);

                let signature = Type::Function {
                    args: Box::new(args),
                    returns: Box::new(returns),
                };

                function_signatures.insert(function_id, signature);
            }
        }

        TypeInferenceResult {
            inferred_types,
            traces: self.bounds_map.traces.clone(),
            debug_markers: self.debug_markers.clone(),
            function_signatures,
        }
    }

    fn ok_or_bound_conflict(
        &self,
        key: &VariableKind,
        refined: Option<Type>,
        bound_type: BoundType,
        current_value: Type,
        other: Type,
        constraint: &Constraint,
    ) -> Result<Type, disasm::Error> {
        match refined {
            Some(refined) => Ok(refined),
            None => {
                if constraint.reason == ConstraintReason::PhiAssignment {
                    // Phi assignments may not be a live variable. For now,
                    // return a "Conflict" type and not fail the unification.
                    Ok(Type::Conflict)
                } else {
                    // Extract SSA var from the type if possible for better error reporting
                    let current_bound = match bound_type {
                        BoundType::Lower => self.bounds_map.lower_bound(key),
                        BoundType::Upper => self.bounds_map.upper_bound(key),
                    }
                    .unwrap()
                    .clone();
                    Err(disasm::Error::TypeConflict {
                        key: key.clone(),
                        bound_type,
                        current_value,
                        other,
                        constraint: constraint.clone(),
                        partial_result: Box::new(self.build_result()),
                    })
                }
            }
        }
    }

    fn handle_function_pointer_constraints(
        &mut self,
        constraint: &Constraint,
        result: &mut Vec<Constraint>,
    ) -> Result<bool, disasm::Error> {
        let left_var = constraint.left.as_variable();
        let right_var = constraint.right.as_variable();
        let left_fp = left_var.and_then(|x| self.function_pointer_variables.get(x).cloned());
        let right_fp = right_var.and_then(|x| self.function_pointer_variables.get(x).cloned());
        let left_const = constraint.left.as_const();
        let right_const = constraint.right.as_const();
        let Some(fca) = self.model.get_function_call_analysis() else {
            return Ok(false);
        };
        if let ConstraintReason::IndirectFunctionCall { calling_block } = &constraint.reason {
            // The constraint is left_var < Pointer(Function(..)))
            let left_var = left_var.expect("Left side must be a variable missing");
            if let Some(FunctionPointerInfo {
                args: ptr_args,
                returns: ptr_rets,
                arg_count: Some(arg_count),
                ret_count,
            }) = &left_fp
            {
                // Case: Function Pointer Variable <: Constant (e.g., `some_func_ptr = fp_var;` where some_func_ptr is known)
                // This implies the function pointer variable's type must be a subtype
                // of the constant function's type.
                let csi = fca
                    .call_site_info
                    .get(calling_block)
                    .expect("Call site info missing");
                let mut caller_args_vec = vec![];
                for i in 0..*arg_count {
                    caller_args_vec.push(Type::from_ssavar(&csi.argument_writes[&(i as i128 + 1)]));
                }
                let caller_args_tuple = Type::Tuple(caller_args_vec);
                let mut caller_rets_vec = vec![];
                for (_, caller_ssa_var) in csi.return_reads.iter().sorted() {
                    caller_rets_vec.push(Type::from_ssavar(caller_ssa_var));
                }
                let caller_ret_count = Some(caller_rets_vec.len());
                let caller_rets_tuple = Type::Tuple(caller_rets_vec);
                assert!(ret_count.is_none() || *ret_count == caller_ret_count);
                if *ret_count != caller_ret_count {
                    self.function_pointer_variables
                        .get_mut(left_var)
                        .unwrap()
                        .ret_count = caller_ret_count;
                }

                let c = Constraint {
                    left: caller_args_tuple,
                    right: ptr_args.clone(),
                    addr: InstructionId::from(calling_block.index()),
                    function_id: csi.calling_function_id,
                    reason: ConstraintReason::FunctionParameterBinding,
                };
                result.push(c);
                let c = Constraint {
                    left: ptr_rets.clone(),
                    right: caller_rets_tuple,
                    addr: InstructionId::from(csi.return_block_id.index()),
                    function_id: csi.calling_function_id,
                    reason: ConstraintReason::FunctionReturnBinding,
                };
                trace!("Added rets constraint: {}", c);
                result.push(c);
            }
        }
        if let (Some(left_const), Some(right_fp_info)) = (left_const, right_fp.clone()) {
            // Case: Constant <: Function Pointer Variable (e.g., `fp_var = &my_func;`)
            // This implies the function pointer variable's type must be a supertype
            // of the constant function's type.
            add_function_parameter_binding_constraint(
                self,
                *left_const,
                right_var.unwrap(),
                &right_fp_info,
                BoundType::Lower, // const is lower bound
                constraint,
                result,
            )?;
        } else if let (Some(left_fp_info), Some(right_const)) = (left_fp.clone(), right_const) {
            // Case: Function Pointer Variable <: Constant (e.g., `some_func_ptr = fp_var;` where some_func_ptr is known)
            // This implies the function pointer variable's type must be a subtype
            // of the constant function's type.
            add_function_parameter_binding_constraint(
                self,
                *right_const,
                left_var.unwrap(),
                &left_fp_info,
                BoundType::Upper, // const is upper bound
                constraint,
                result,
            )?;
        } else if let (Some(left_fp), Some(right_fp)) = (left_fp, right_fp) {
            // Case: Function Pointer Variable <: Function Pointer Variable.
            let FunctionPointerInfo {
                args: args1,
                returns: rets1,
                arg_count: arg_count1,
                ret_count: ret_count1,
            } = left_fp;
            let FunctionPointerInfo {
                args: args2,
                returns: rets2,
                arg_count: arg_count2,
                ret_count: ret_count2,
            } = right_fp;
            result.push(Constraint {
                left: args2.clone(),
                right: args1.clone(),
                addr: constraint.addr,
                function_id: constraint.function_id,
                reason: ConstraintReason::FunctionPointerSubtype,
            });
            result.push(Constraint {
                left: rets1.clone(),
                right: rets2.clone(),
                addr: constraint.addr,
                function_id: constraint.function_id,
                reason: ConstraintReason::FunctionPointerSubtype,
            });
            assert!(
                arg_count1.is_none() || arg_count2.is_none() || arg_count1 == arg_count2,
                "Got different arg counts: {arg_count1:?} and {arg_count2:?} for {constraint}"
            );
            if let Some(arg_count) = arg_count1.or(arg_count2) {
                self.function_pointer_variables
                    .get_mut(left_var.unwrap())
                    .unwrap()
                    .arg_count = Some(arg_count);
                self.function_pointer_variables
                    .get_mut(right_var.unwrap())
                    .unwrap()
                    .arg_count = Some(arg_count);
            }
            assert!(ret_count1.is_none() || ret_count2.is_none() || ret_count1 == ret_count2);
            if let Some(ret_count) = ret_count1.or(ret_count2) {
                self.function_pointer_variables
                    .get_mut(left_var.unwrap())
                    .unwrap()
                    .ret_count = Some(ret_count);
                self.function_pointer_variables
                    .get_mut(right_var.unwrap())
                    .unwrap()
                    .ret_count = Some(ret_count);
            }
        }

        Ok(false)
    }
}

fn add_function_parameter_binding_constraint(
    solver: &mut Solver,
    func_addr: i128,
    func_key: &VariableKind,
    func_ptr_info: &FunctionPointerInfo,
    bound_type: BoundType,
    constraint: &Constraint,
    result: &mut Vec<Constraint>,
) -> Result<(), disasm::Error> {
    let callee_function_id = FunctionId::from(func_addr as usize);
    let fca = solver.model.get_function_call_analysis().unwrap();
    let Some(callee_info) = fca.callee_info.get(&callee_function_id) else {
        trace!(
            "Function address {} not found in callee info for constraint: {}",
            func_addr,
            constraint
        );
        return Err(disasm::Error::InvalidFunctionPointerValue {
            addr: callee_function_id.index(),
            constraint: constraint.clone(),
        });
    };

    let FunctionPointerInfo {
        args: arg_type,
        returns: ret_type,
        ..
    } = func_ptr_info;

    // Construct the tuple type from the callee's parameters
    let mut tuple_elems = vec![];
    for (_, callee_ssa_var) in callee_info
        .parameter_entry_vars
        .iter()
        .sorted_by_key(|(k, _)| *k)
    {
        tuple_elems.push(Type::from_ssavar(callee_ssa_var));
    }
    let actual_param_tuple_type = Type::Tuple(tuple_elems);
    let arg_count = Some(callee_info.parameter_entry_vars.len());
    assert!(func_ptr_info.arg_count.is_none() || func_ptr_info.arg_count == arg_count);
    solver
        .function_pointer_variables
        .get_mut(func_key)
        .expect(format!("Function pointer variable {} is untracked", arg_type).as_str())
        .arg_count = arg_count;

    // Determine the direction of the constraint based on the original constraint
    // and which side held the constant function address.
    let (arg_left, arg_right) = match bound_type {
        BoundType::Lower => {
            // Original case: const_addr <: func_ptr_var
            // By contravariance of args: func_ptr_arg_type <: actual_param_tuple_type
            (arg_type.clone(), actual_param_tuple_type)
        }
        BoundType::Upper => {
            // New case: func_ptr_var <: const_addr
            // By contravariance of args: actual_param_tuple_type <: func_ptr_arg_type
            (actual_param_tuple_type, arg_type.clone())
        }
    };

    result.push(Constraint {
        left: arg_left,
        right: arg_right,
        addr: constraint.addr,
        function_id: constraint.function_id,
        reason: ConstraintReason::FunctionParameterBinding,
    });

    if let Some(ret_count) = func_ptr_info.ret_count {
        let mut tuple_elems = vec![];
        let stack_size = solver.model.get_function(callee_function_id).stack_size as i128;
        for i in 1..=ret_count {
            let callee_ssa_var = callee_info
                .return_writes
                .get(&((i as i128) - stack_size))
                .expect(format!("Return write not found not found for {}", i).as_str());
            tuple_elems.push(Type::from_ssavar(&callee_ssa_var));
        }
        let actual_return_type = Type::Tuple(tuple_elems);

        let (ret_left, ret_right) = match bound_type {
            BoundType::Lower => {
                // New case: func_ptr_var <: const_addr
                // By contravariance of args: actual_param_tuple_type <: func_ptr_arg_type
                (actual_return_type, ret_type.clone())
            }
            BoundType::Upper => {
                // Original case: const_addr <: func_ptr_var
                // By contravariance of args: func_ptr_arg_type <: actual_param_tuple_type
                (ret_type.clone(), actual_return_type)
            }
        };

        result.push(Constraint {
            left: ret_left,
            right: ret_right,
            addr: constraint.addr,
            function_id: constraint.function_id,
            reason: ConstraintReason::FunctionParameterBinding,
        });
    }

    Ok(())
}

pub fn unify(
    model: &ProgramModel,
    constraints: &[Constraint],
    debug_markers: &HashMap<char, SsaOperand>,
) -> Result<TypeInferenceResult, disasm::Error> {
    let mut solver = Solver::new(model.clone(), constraints, debug_markers.clone());
    solver.unify()
}

/*
fn refine_function_pointers(
    model: &ProgramModel,
    bounds: &mut TypeBoundsMap,
) -> Result<bool, TypeInferenceError> {
    let mut changed = false;
    let bounds_keys = bounds.all_keys();
    for key in bounds_keys {
        match key {
            Type::Variable(VariableKind::SsaVar(SsaVar {
                kind: SsaVarKind::Immediate(func_addr),
                ..
            })) => {
                let upper_bound = bounds.upper_bound(&key).unwrap().clone();
                let Type::Pointer(ptr_type) = upper_bound else {
                    continue;
                };
                let Type::Function { args, .. } = &(*ptr_type) else {
                    continue;
                };
                let function_id = FunctionId::from(func_addr as usize);
                if !model.has_function(function_id) {
                    continue;
                }
                let Some(callee_info) = model
                    .get_function_call_analysis()
                    .unwrap()
                    .callee_info
                    .get(&function_id)
                else {
                    continue;
                };
                if **args != Type::Any {
                    let args_upper = bounds.upper_bound(&args).unwrap();
                    if matches!(args_upper, Type::Tuple(_)) {
                        // already unified this call.
                        continue;
                    }
                }
                let mut tuple_elems = vec![];

                for (_, callee_ssa_var) in callee_info
                    .parameter_entry_vars
                    .iter()
                    .sorted_by_key(|(k, _)| *k)
                {
                    let v = Type::new_var();
                    tuple_elems.push(v.clone());
                    bounds.insert_key(v, Type::Nothing, Type::from_ssavar(callee_ssa_var));
                }
                let tuple_type = Type::Tuple(tuple_elems);
                let fp = Type::new_function_pointer();
                let Some((func_args, _)) = Type::extract_function_from_pointer(&fp) else {
                    panic!("Failed to extract function from pointer");
                };

                // bounds.insert_key(func_args.clone(), Type::Nothing, tuple_type);
                trace!("I AM HER!");
                init_bounds_for_type(func_args, bounds);

                bounds.register_new_upper(
                    *args.clone(),
                    tuple_type,
                    ChangeReason::IndirectFuctionParameterBinding(function_id),
                );
                changed = true;
            }
            _ => {}
        }
    }
    Ok(changed)
}
*/

fn refine_concrete_types(bounds: &mut TypeBoundsMap) -> Result<bool, disasm::Error> {
    for key in bounds.all_keys() {
        let lower = bounds.lower_bound(&key).unwrap().clone();
        let upper = bounds.upper_bound(&key).unwrap().clone();
        if specifity(&lower) > specifity(&upper) && is_concrete_type(&lower) {
            bounds.update_bound(
                key,
                BoundType::Upper,
                lower.clone(),
                ChangeReason::ConcreteRefinement,
            )?;
            return Ok(true);
        } else if specifity(&upper) > specifity(&lower) && is_concrete_type(&upper) {
            bounds.update_bound(
                key,
                BoundType::Lower,
                upper.clone(),
                ChangeReason::ConcreteRefinement,
            )?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn replace_truthy_with_bool(bounds: &mut TypeBoundsMap) -> Result<bool, disasm::Error> {
    for key in bounds.all_keys() {
        let lower = bounds.lower_bound(&key).unwrap().clone();
        let upper = bounds.upper_bound(&key).unwrap().clone();
        if upper == Type::Truthy && lower == Type::Nothing {
            bounds.update_bound(
                key,
                BoundType::Upper,
                Type::Bool,
                ChangeReason::TruthyToBoolHeuristic,
            )?;
            bounds.update_bound(
                key,
                BoundType::Lower,
                Type::Bool,
                ChangeReason::TruthyToBoolHeuristic,
            )?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn effective_upper_bound(typ: &Type, bounds: &TypeBoundsMap) -> Type {
    match typ {
        Type::Int | Type::Bool | Type::Char => typ.clone(),
        Type::Truthy | Type::Conflict | Type::Nothing | Type::Any => typ.clone(),
        Type::Pointer(x) => Type::Pointer(Box::new(effective_upper_bound(x, bounds))),
        Type::Function { args, returns } => {
            let args = effective_lower_bound(args, bounds);
            let returns = effective_upper_bound(returns, bounds);
            Type::Function {
                args: Box::new(args),
                returns: Box::new(returns),
            }
        }
        Type::Tuple(ts) => Type::Tuple(
            ts.iter()
                .map(|t| effective_upper_bound(t, bounds))
                .collect(),
        ),
        Type::Variable(v) => bounds.upper_bound(v).unwrap().clone(),
    }
}

fn effective_lower_bound(typ: &Type, bounds: &TypeBoundsMap) -> Type {
    match typ {
        Type::Int | Type::Bool | Type::Char => typ.clone(),
        Type::Truthy | Type::Conflict | Type::Nothing | Type::Any => typ.clone(),
        Type::Pointer(x) => Type::Pointer(Box::new(effective_lower_bound(x, bounds))),
        Type::Function { args, returns } => {
            let args = effective_upper_bound(args, bounds);
            let returns = effective_lower_bound(returns, bounds);
            Type::Function {
                args: Box::new(args),
                returns: Box::new(returns),
            }
        }
        Type::Tuple(ts) => Type::Tuple(
            ts.iter()
                .map(|t| effective_lower_bound(t, bounds))
                .collect(),
        ),
        Type::Variable(v) => {
            let v_lower = bounds.lower_bound(v).unwrap();
            v_lower.clone()
        }
    }
}

pub(crate) fn init_bounds_for_type(typ: &Type, bounds: &mut TypeBoundsMap) {
    match typ {
        Type::Int | Type::Bool | Type::Char => {}
        Type::Truthy | Type::Conflict | Type::Nothing | Type::Any => {}
        Type::Pointer(x) => {
            init_bounds_for_type(x, bounds);
        }
        Type::Function { args, returns } => {
            let _ = init_bounds_for_type(args, bounds);
            let _ = init_bounds_for_type(returns, bounds);
        }
        Type::Tuple(ts) => {
            for t in ts {
                init_bounds_for_type(t, bounds);
            }
        }
        Type::Variable(v) => {
            if !bounds.contains_key(&v) {
                bounds.create_key(v.clone(), Type::Nothing, Type::Any);
            }
        }
    }
}

fn specifity(typ: &Type) -> u32 {
    match typ {
        Type::Int | Type::Bool | Type::Char => 1,
        Type::Truthy | Type::Conflict | Type::Nothing | Type::Any => 0,
        Type::Pointer(x) => 1 + specifity(x),
        Type::Function { args, returns } => {
            let args = specifity(args);
            let returns = specifity(returns);
            1 + args.max(returns)
        }
        Type::Tuple(ts) => 1 + ts.iter().map(specifity).sum::<u32>(),
        Type::Variable(_) => 1,
    }
}
