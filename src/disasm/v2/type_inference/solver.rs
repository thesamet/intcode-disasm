use colored::Colorize;
use itertools::Itertools;
use log::{error, info, trace};
use std::collections::HashMap;
use std::fmt::{self, Display};

use super::analyzer::AddInstruction;
use super::constraints::{Constraint, ConstraintReason};
use super::result::TypeInferenceResult;
use super::types::{is_concrete_type, VariableKind};
use super::visuals::TraceColors;
use crate::disasm;
use crate::disasm::v2::model::{FunctionId, ProgramModel};
use crate::disasm::v2::native::NativeInstructionId;
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
            .unwrap_or_else(|| panic!("Update bound for missing key: {}", key));
        let mut new_bounds = old_bounds.clone();
        match bound_type {
            BoundType::Lower => new_bounds.lower = new_value,
            BoundType::Upper => new_bounds.upper = new_value,
        }
        if old_bounds == new_bounds {
            return Ok(false);
        }
        if !new_bounds.lower.is_subtype_of(&new_bounds.upper) {
            error!("Type inconsistency detected.");
            error!(
                "New bound for {key} is [{}, {}]. Previously: [{}, {}].\nReason: {}",
                new_bounds.lower, new_bounds.upper, old_bounds.lower, old_bounds.upper, reason
            );
            return Err(disasm::Error::TypeInconsistency {
                key,
                bound_type,
                lower: new_bounds.lower,
                upper: new_bounds.upper,
            });
        }
        let trace = AnalysisTrace {
            key,
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
}

impl Display for ChangeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ChangeReason::DecreaseUpperBoundFromConstraint { constraint, other } => {
                let other_str = if let Type::Variable(var) = other {
                    TraceColors::format_var(var)
                } else {
                    TraceColors::format_type(other)
                };

                let constraint_str = TraceColors::format_constraint(constraint).to_string();

                write!(f, "  {} with {}", constraint_str, other_str)
            }
            ChangeReason::IncreaseLowerBoundFromConstraint { constraint, other } => {
                let other_str = if let Type::Variable(var) = other {
                    TraceColors::format_var(var)
                } else {
                    TraceColors::format_type(other)
                };
                let constraint_str = TraceColors::format_constraint(constraint).to_string();
                write!(f, "  {} with {}", constraint_str, other_str)
            }
            ChangeReason::ConcreteRefinement => {
                write!(
                    f,
                    "  {}",
                    TraceColors::format_bound("Concrete type refinement")
                )
            }
        }
    }
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
        write!(f, "{}", self.reason)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FunctionPointerInfo {
    args: Type,    // tuple of argument types
    returns: Type, // tuple of return types

    // Functions have a minimum number of arguments, as we can view the rest
    // of the arguments as being ignored. This allows for FunctionPointers
    // to see what the different callees require and take the maximum of that
    // as the minimum number of arguments for the function pointer type.
    // The min_arg_count is the lower_bound on the function type, and upper bound
    // on the args tuple itself.  None means we haven't seen any example functions
    // being passed, so we can't determine the min_arg_count yet.
    min_arg_count: Option<usize>,
    ret_count: Option<usize>, // number of return arguments
}

struct SolverState {
    bounds_map: TypeBoundsMap,
    add_instructions: Vec<AddInstruction>,
    function_pointer_variables: HashMap<VariableKind, FunctionPointerInfo>,
}

struct Solver<'a> {
    model: &'a ProgramModel,
    debug_markers: HashMap<char, SsaOperand>,
    constraints: Vec<Constraint>,
    state: SolverState,
}

impl<'a> Solver<'a> {
    fn new(
        model: &'a ProgramModel,
        constraints: &[Constraint],
        add_instructions: &[AddInstruction],
        debug_markers: HashMap<char, SsaOperand>,
    ) -> Self {
        Self {
            model,
            debug_markers,
            constraints: constraints.to_vec(),
            state: SolverState {
                bounds_map: TypeBoundsMap::new(),
                add_instructions: add_instructions.to_vec(),
                function_pointer_variables: HashMap::new(),
            },
        }
    }

    fn unify(&mut self) -> Result<TypeInferenceResult, disasm::Error> {
        let constraints = self.constraints.to_vec();
        for c in &constraints {
            init_bounds_for_type(&c.left, &mut self.state.bounds_map);
            init_bounds_for_type(&c.right, &mut self.state.bounds_map);
        }
        loop {
            while self.reach_constraint_fixed_point()? {}
            if refine_concrete_types(&mut self.state.bounds_map, true, false)? {
                continue;
            }
            if refine_concrete_types(&mut self.state.bounds_map, false, true)? {
                continue;
            }
            /*
            if replace_truthy_with_bool(&mut self.state.bounds_map)? {
                trace!("Replaced truthy with bool changed");
                continue;
            }
            */
            break;
        }
        info!("{}", "Type inference completed successfully".bold());
        for (function_id, key, value) in self
            .state
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
            self.append_add_contraints(&mut worklist);
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
            let current_upper = self.state.bounds_map.upper_bound(u).unwrap();
            let eub = effective_upper_bound(&constraint.right, &self.state.bounds_map);
            let glb = glb(current_upper, &eub);
            let glb = self.ok_or_bound_conflict(
                u,
                glb,
                BoundType::Upper,
                current_upper.clone(),
                eub,
                constraint,
            )?;
            changed |= self.state.bounds_map.update_bound(
                *u,
                BoundType::Upper,
                glb.clone(),
                ChangeReason::DecreaseUpperBoundFromConstraint {
                    constraint: constraint.clone(),
                    other: constraint.right.clone(),
                },
            )?;
            if glb.is_function_pointer() {
                let fpi = self
                    .state
                    .function_pointer_variables
                    .entry(*u)
                    .or_insert_with(|| {
                        let args = Type::new_var();
                        let returns = Type::new_var();
                        init_bounds_for_type(&args, &mut self.state.bounds_map);
                        init_bounds_for_type(&returns, &mut self.state.bounds_map);
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
                            min_arg_count: None,
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
            let current_lower = self.state.bounds_map.lower_bound(v).unwrap();
            let elb = effective_lower_bound(&constraint.left, &self.state.bounds_map);
            let lub = lub(current_lower, &elb);
            let lub = self.ok_or_bound_conflict(
                v,
                lub,
                BoundType::Lower,
                current_lower.clone(),
                elb,
                constraint,
            )?;
            changed |= self.state.bounds_map.update_bound(
                *v,
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
                if effective_upper_bound(right, &self.state.bounds_map)
                    .as_tuple()
                    .is_some() =>
            {
                let us = effective_upper_bound(right, &self.state.bounds_map)
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

    fn append_add_contraints(&mut self, worklist: &mut Vec<Constraint>) {
        for instruction @ AddInstruction {
            op1, op2, result, ..
        } in &self.state.add_instructions
        {
            init_bounds_for_type(&op1.as_type(), &mut self.state.bounds_map);
            init_bounds_for_type(&op2.as_type(), &mut self.state.bounds_map);
            init_bounds_for_type(&result.as_type(), &mut self.state.bounds_map);
            let op1_lower = self.state.bounds_map.lower_bound(op1).unwrap();
            let op1_upper = self.state.bounds_map.upper_bound(op1).unwrap();
            let op2_lower = self.state.bounds_map.lower_bound(op2).unwrap();
            let op2_upper = self.state.bounds_map.upper_bound(op2).unwrap();
            let result_upper = self.state.bounds_map.upper_bound(result).unwrap();
            let result_lower = self.state.bounds_map.lower_bound(result).unwrap();
            let is_op1_int = matches!(op1_lower, Type::Int);
            let is_op2_int = matches!(op2_lower, Type::Int);
            let is_result_int = matches!(result_lower, Type::Int);
            let is_op1_pointer = op1_upper.is_pointer();
            let is_op2_pointer = op2_upper.is_pointer();
            let is_result_pointer = result_upper.is_pointer();
            let is_result_char = matches!(result_lower, Type::Char);

            let constaint = |left, right| Constraint {
                left,
                right,
                addr: instruction.instruction_id,
                function_id: instruction.function_id,
                reason: ConstraintReason::AddRules,
            };

            // Stating that a type is <: Type::Int doesn't mean much where practically every type
            // is a subtype of Type::Int. This however, will get concrete refinement to pick this type
            // if there is nothing more specific.

            if is_op1_int && is_op2_int {
                worklist.push(constaint(result.as_type(), Type::Int));
            } else if is_result_char || is_result_int {
                worklist.push(constaint(op1.as_type(), Type::Int));
                worklist.push(constaint(op2.as_type(), Type::Int));
            } else if is_op1_pointer {
                worklist.push(constaint(op2.as_type(), Type::Int));
                worklist.push(constaint(op1.as_type(), result.as_type()));
            } else if is_op2_pointer {
                worklist.push(constaint(op1.as_type(), Type::Int));
                worklist.push(constaint(op2.as_type(), result.as_type()));
            } else if is_result_pointer && is_op1_int {
                worklist.push(constaint(op2.as_type(), result.as_type()));
            } else if is_result_pointer && is_op2_int {
                worklist.push(constaint(op1.as_type(), result.as_type()));
            } else if is_op1_int || is_op2_int {
                worklist.push(constaint(result.as_type(), Type::Int));
            }
        }
    }

    /// Create a TypeInferenceResult from the current state of bounds
    fn build_result(&self) -> TypeInferenceResult {
        let inferred_types: HashMap<VariableKind, Type> = self
            .state
            .bounds_map
            .iter()
            .map({
                |(k, v)| {
                    let typ = if specifity(&v.upper) >= specifity(&v.lower) {
                        &v.upper
                    } else {
                        &v.lower
                    };

                    (*k, typ.clone())
                }
            })
            .collect();

        let mut function_signatures = HashMap::new();
        if let Some(fca) = self.model.get_function_call_analysis() {
            for (function_id, callee_info) in &fca.callee_info {
                let args = callee_info
                    .parameter_entry_vars
                    .iter()
                    .sorted()
                    .map(|(k, v)| {
                        (
                            *k,
                            *v,
                            inferred_types
                                .get(&VariableKind::from_ssavar(v))
                                .unwrap()
                                .clone(),
                        )
                    })
                    .collect_vec();
                let returns =
                    if let Some(return_values) = fca.get_effective_return_values(*function_id) {
                        return_values
                            .iter()
                            .sorted()
                            .map(|(k, v)| {
                                (
                                    *k,
                                    *v,
                                    inferred_types
                                        .get(&VariableKind::from_ssavar(v))
                                        .unwrap()
                                        .clone(),
                                )
                            })
                            .collect_vec()
                    } else {
                        vec![]
                    };
                function_signatures.insert(*function_id, (args, returns));
            }
        }

        TypeInferenceResult {
            inferred_types,
            traces: self.state.bounds_map.traces.clone(),
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
        refined.ok_or_else(|| disasm::Error::TypeConflict {
            key: *key,
            bound_type,
            current_value,
            other,
            constraint: constraint.clone(),
            partial_result: Box::new(self.build_result()),
        })
    }

    fn handle_function_pointer_constraints(
        &mut self,
        constraint: &Constraint,
        result: &mut Vec<Constraint>,
    ) -> Result<bool, disasm::Error> {
        let left_var = constraint.left.as_variable();
        let right_var = constraint.right.as_variable();
        let left_fp = left_var.and_then(|x| self.state.function_pointer_variables.get(x).cloned());
        let right_fp =
            right_var.and_then(|x| self.state.function_pointer_variables.get(x).cloned());
        let left_const = constraint.left.as_const();
        let right_const = constraint.right.as_const();
        let mut changed = false;
        let Some(fca) = self.model.get_function_call_analysis() else {
            return Ok(changed);
        };
        if let ConstraintReason::IndirectFunctionCall { calling_block } = &constraint.reason {
            // The constraint is left_var < Pointer(Function(..)))
            let left_var = left_var.expect("Left side must be a variable missing");
            if let Some(FunctionPointerInfo {
                args: ptr_args,
                returns: ptr_rets,
                min_arg_count: Some(min_arg_count),
                ret_count,
                ..
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
                for i in 0..*min_arg_count {
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
                    self.state
                        .function_pointer_variables
                        .get_mut(left_var)
                        .unwrap()
                        .ret_count = caller_ret_count;
                }

                let c = Constraint {
                    left: caller_args_tuple,
                    right: ptr_args.clone(),
                    addr: NativeInstructionId::from(calling_block.index()),
                    function_id: csi.calling_function_id,
                    reason: ConstraintReason::FunctionParameterBindingAtCallSite,
                };
                trace!("Adding constraint: {c}");
                result.push(c);
                let c = Constraint {
                    left: ptr_rets.clone(),
                    right: caller_rets_tuple,
                    addr: NativeInstructionId::from(csi.return_block_id.index()),
                    function_id: csi.calling_function_id,
                    reason: ConstraintReason::FunctionReturnBinding,
                };
                trace!("Adding constraint: {c}");
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
                constraint,
                result,
            )?;
        } else if let (Some(_), Some(_)) = (left_fp.clone(), right_const) {
            // Case: Function Pointer Variable <: Constant (e.g., `some_func_ptr = fp_var;` where some_func_ptr is known)
            // This implies the function pointer variable's type must be a subtype
            // of the constant function's type.
            unreachable!("Does this ever happen?");
            // Unreachable branch for Upper bound; code removed.
        } else if let (Some(left_fp), Some(right_fp)) = (left_fp, right_fp) {
            // Case: Function Pointer Variable <: Function Pointer Variable.
            let FunctionPointerInfo {
                args: args1,
                returns: rets1,
                min_arg_count: min_arg_count1,
                ret_count: ret_count1,
                ..
            } = left_fp;
            let FunctionPointerInfo {
                args: args2,
                returns: rets2,
                ret_count: ret_count2,
                ..
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
            // For function types, the subtyping relationship is:
            // A function type with fewer parameters is a subtype of a function type with more parameters
            //
            // In this case, we have constraint: left_fp <: right_fp
            // So left_fp should have fewer or equal args than right_fp
            let right_fpi_mut = self
                .state
                .function_pointer_variables
                .get_mut(right_var.unwrap())
                .unwrap();
            right_fpi_mut.min_arg_count = right_fpi_mut.min_arg_count.max(min_arg_count1);
            if right_fp.min_arg_count != right_fpi_mut.min_arg_count {
                changed = true;
            };
            if let Some(ret_count) = ret_count1.or(ret_count2) {
                self.state
                    .function_pointer_variables
                    .get_mut(left_var.unwrap())
                    .unwrap()
                    .ret_count = Some(ret_count);
                self.state
                    .function_pointer_variables
                    .get_mut(right_var.unwrap())
                    .unwrap()
                    .ret_count = Some(ret_count);
            }
        }

        Ok(changed)
    }
}

fn add_function_parameter_binding_constraint(
    solver: &mut Solver,
    func_addr: i128,
    func_key: &VariableKind,
    func_ptr_info: &FunctionPointerInfo,
    constraint: &Constraint,
    result: &mut Vec<Constraint>,
) -> Result<(), disasm::Error> {
    // bound_type is always lower:
    //  means fptr = &func_addr, and does fptr >: type(func_addr)
    //  which means that fptr takes at least as many arguments as func_addr.

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

    // Construct the tuple type from the callee's parameters
    let mut callee_args_vec = vec![];
    for (_, callee_ssa_var) in callee_info
        .parameter_entry_vars
        .iter()
        .sorted_by_key(|(k, _)| *k)
    {
        callee_args_vec.push(Type::from_ssavar(callee_ssa_var));
    }
    let callee_args_type = Type::Tuple(callee_args_vec);
    let callee_args_count = callee_info.parameter_entry_vars.len();
    // Push up the minimum argument count based on callee args count (always lower bound)
    let fpi = solver
        .state
        .function_pointer_variables
        .get_mut(func_key)
        .unwrap_or_else(|| panic!("Function pointer variable {} is untracked", func_key));
    fpi.min_arg_count = Some(fpi.min_arg_count.unwrap_or_default().max(callee_args_count));

    // Constraint for function parameters (lower bound semantics)
    let arg_left = func_ptr_info.args.clone();
    let arg_right = callee_args_type.clone();

    let c = Constraint {
        left: arg_left,
        right: arg_right,
        addr: constraint.addr,
        function_id: constraint.function_id,
        reason: ConstraintReason::FunctionParameterBindingBetweenCalleeAndTypeVar,
    };
    trace!("Adding constraint: {:?}", c);
    result.push(c);

    if let Some(ret_count) = func_ptr_info.ret_count {
        let mut tuple_elems = vec![];
        let stack_size = solver.model.get_function(callee_function_id).stack_size as i128;
        for i in 1..=ret_count {
            let callee_ssa_var = callee_info
                .return_writes
                .get(&((i as i128) - stack_size))
                .unwrap_or_else(|| panic!("Return write not found not found for {}", i));
            tuple_elems.push(Type::from_ssavar(callee_ssa_var));
        }
        let callee_return_type = Type::Tuple(tuple_elems);

        // Constraint for function return types (lower bound semantics)
        let ret_left = callee_return_type.clone();
        let ret_right = func_ptr_info.returns.clone();

        result.push(Constraint {
            left: ret_left,
            right: ret_right,
            addr: constraint.addr,
            function_id: constraint.function_id,
            reason: ConstraintReason::FunctionReturnBinding,
        });
    }

    Ok(())
}

pub fn unify(
    model: &ProgramModel,
    constraints: &[Constraint],
    add_instructions: &[AddInstruction],
    debug_markers: &HashMap<char, SsaOperand>,
) -> Result<TypeInferenceResult, disasm::Error> {
    let mut solver = Solver::new(model, constraints, add_instructions, debug_markers.clone());
    solver.unify()
}

fn refine_concrete_types(
    bounds: &mut TypeBoundsMap,
    do_lower: bool,
    do_upper: bool,
) -> Result<bool, disasm::Error> {
    for key in bounds.all_keys().into_iter().sorted() {
        let lower = bounds.lower_bound(&key).unwrap().clone();
        let upper = bounds.upper_bound(&key).unwrap().clone();
        if do_lower && lower == Type::Nothing && is_concrete_type(&upper) {
            bounds.update_bound(
                key,
                BoundType::Lower,
                upper.clone(),
                ChangeReason::ConcreteRefinement,
            )?;
            return Ok(true);
        }
        if do_upper && upper == Type::Any && is_concrete_type(&lower) {
            bounds.update_bound(
                key,
                BoundType::Upper,
                lower.clone(),
                ChangeReason::ConcreteRefinement,
            )?;
            return Ok(true);
        }
    }
    /*
    for key in bounds.all_keys().into_iter().sorted() {
        let lower = bounds.lower_bound(&key).unwrap().clone();
        let upper = bounds.upper_bound(&key).unwrap().clone();
        if specifity(&lower) > specifity(&upper) && is_concrete_type(&lower) {
            println!("{}: {upper} -> {lower}", key);
            count += 1;
        } else if specifity(&upper) > specifity(&lower) && is_concrete_type(&upper) {
            println!("{}: {lower} -> {upper}", key);
            count += 1;
        }
    }
    println!("Refinement count: {}", count);
    */
    /*
    for key in bounds.all_keys().into_iter().sorted() {
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
    */
    Ok(false)
}

fn effective_upper_bound(typ: &Type, bounds: &TypeBoundsMap) -> Type {
    match typ {
        Type::Int | Type::Bool | Type::Char => typ.clone(),
        Type::Truthy | Type::Nothing | Type::Any => typ.clone(),
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
        Type::Truthy | Type::Nothing | Type::Any => typ.clone(),
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
        Type::Truthy | Type::Nothing | Type::Any => {}
        Type::Pointer(x) => {
            init_bounds_for_type(x, bounds);
        }
        Type::Function { args, returns } => {
            init_bounds_for_type(args, bounds);
            init_bounds_for_type(returns, bounds);
        }
        Type::Tuple(ts) => {
            for t in ts {
                init_bounds_for_type(t, bounds);
            }
        }
        Type::Variable(v) => {
            if !bounds.contains_key(v) {
                bounds.create_key(*v, Type::Nothing, Type::Any);
            }
        }
    }
}

fn specifity(typ: &Type) -> u32 {
    match typ {
        Type::Int | Type::Bool | Type::Char => 1,
        Type::Truthy | Type::Nothing | Type::Any => 0,
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
