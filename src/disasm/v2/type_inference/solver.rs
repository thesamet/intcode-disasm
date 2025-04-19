use colored::Colorize;
use itertools::Itertools;
use log::trace;
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

use super::constraints::{Constraint, ConstraintReason};
use super::result::TypeInferenceResult;
use super::types::{is_concrete_type, VariableKind};
use super::visuals::TraceColors;
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

#[derive(Error, Debug)]
pub enum TypeInferenceError {
    #[error("Type conflict for {key}: type conflict between existing {bound_type} bound {current_bound} and {other} at {constraint}")]
    TypeConflict {
        key: VariableKind,
        bound_type: BoundType,
        other: Type,
        current_bound: Type,
        constraint: Constraint,
        partial_result: Box<TypeInferenceResult>,
    },

    #[error("{bound_type} bound conflict: type conflict between {left} and {right} for {var_type} at {constraint}")]
    BoundConflict {
        bound_type: BoundType,
        left: Type,
        right: Type,
        var_type: Type,
        constraint: Constraint,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    ) -> bool {
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
            return false;
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
        true
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
    IndirectFuctionParameterBinding(FunctionId),
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
                "{} {:>7} {} {:<18} was {:<8}",
                TraceColors::format_header("Type"),
                key_str,
                ":<".blue(),
                TraceColors::format_type(&self.change.new_bounds.upper),
                TraceColors::format_type(&self.change.old_bounds.upper)
            )?;
        } else {
            write!(
                f,
                "{} {:>7} {} {:<18} was {:<8}",
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

                let constraint_str = format!(
                    "{} @ {}:{}",
                    TraceColors::format_constraint(constraint.reason),
                    TraceColors::format_location(constraint.function_id),
                    TraceColors::format_location(constraint.addr)
                );

                write!(f, "  {} caused by {}", constraint_str, other_str)
            }
            ChangeReason::IncreaseLowerBoundFromConstraint { constraint, other } => {
                let other_str = if let Type::Variable(var) = other {
                    TraceColors::format_var(var)
                } else {
                    TraceColors::format_type(other)
                };

                let constraint_str = format!(
                    "{} @ {}:{}",
                    TraceColors::format_constraint(constraint.reason),
                    TraceColors::format_location(constraint.function_id),
                    TraceColors::format_location(constraint.addr)
                );

                write!(f, "  {} caused by {}", constraint_str, other_str)
            }
            ChangeReason::IndirectFuctionParameterBinding(function_id) => {
                write!(
                    f,
                    "  {} {}",
                    TraceColors::format_bound("Indirect function parameter binding with function"),
                    TraceColors::format_location(format!("{}", function_id),)
                )
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

struct Solver {
    model: ProgramModel,
    debug_markers: HashMap<char, SsaOperand>,
    constraints: Vec<Constraint>,
    bounds_map: TypeBoundsMap,
    indirect_function_types: HashMap<FunctionId, Type>,
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
            indirect_function_types: HashMap::new(),
        }
    }

    fn unify(&mut self) -> Result<TypeInferenceResult, TypeInferenceError> {
        let constraints = self.constraints.to_vec();
        for c in &constraints {
            init_bounds_for_type(&c.left, &mut self.bounds_map);
            init_bounds_for_type(&c.right, &mut self.bounds_map);
        }
        loop {
            while self.reach_constraint_fixed_point()? {}
            /*
            if refine_function_pointers(&mut self.bounds_map)? {
                continue;
            }
            */
            if refine_concrete_types(&mut self.bounds_map)? {
                continue;
            }
            if replace_truthy_with_bool(&mut self.bounds_map)? {
                trace!("Replaced truthy with bool changed");
                continue;
            }
            break;
        }
        Ok(self.build_result())
    }

    fn reach_constraint_fixed_point(&mut self) -> Result<bool, TypeInferenceError> {
        let mut overall_changed = false;
        loop {
            let mut changed_in_iteration = false;
            let mut worklist = self.constraints.to_vec(); // Clone constraints into a worklist
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
    ) -> Result<(bool, Vec<Constraint>), TypeInferenceError> {
        let mut result = vec![];
        let mut changed = false;
        if let Type::Variable(u) = &constraint.left {
            let current_upper = self.bounds_map.upper_bound(u).unwrap();
            let glb = glb(
                &current_upper,
                &effective_upper_bound(&constraint.right, &self.bounds_map),
            );
            let glb =
                self.ok_or_bound_conflict(u, glb, BoundType::Upper, constraint, &constraint.right)?;
            changed |= self.bounds_map.update_bound(
                u.clone(),
                BoundType::Upper,
                glb,
                ChangeReason::DecreaseUpperBoundFromConstraint {
                    constraint: constraint.clone(),
                    other: constraint.right.clone(),
                },
            );
        }
        if let Type::Variable(v) = &constraint.right {
            let current_lower = self.bounds_map.lower_bound(v).unwrap();
            let lub = lub(
                &current_lower,
                &effective_lower_bound(&constraint.left, &self.bounds_map),
            );
            let lub =
                self.ok_or_bound_conflict(v, lub, BoundType::Lower, constraint, &constraint.left)?;
            changed |= self.bounds_map.update_bound(
                v.clone(),
                BoundType::Lower,
                lub,
                ChangeReason::IncreaseLowerBoundFromConstraint {
                    constraint: constraint.clone(),
                    other: constraint.left.clone(),
                },
            );
        }
        match (constraint.left.clone(), constraint.right.clone()) {
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

    fn add_function_pointer_constraints(
        &mut self,
        lower: &VariableKind,
        upper: &Type,
        result: &mut Vec<Constraint>,
    ) {
        let VariableKind::Const {
            value: addr,
            origin_info,
        } = lower
        else {
            return;
        };
        let function_id = FunctionId::from(*addr as usize);
        let Some(callee_info) = self
            .model
            .get_function_call_analysis()
            .unwrap()
            .callee_info
            .get(&function_id)
        else {
            return;
        };
        if upper == &Type::Pointer(Box::new(Type::Callable)) {
            let args = self
                .indirect_function_types
                .entry(function_id)
                .or_insert_with(|| {
                    // We have not processed this function pointer yet. Processing
                    // ensures that the type variable of args is a subtype of a tuple
                    // that corresponds to the callee's parameter SSA vars.
                    println!("Processing function pointer {}", lower);
                    let mut t_vars = vec![];
                    for _ in 0..callee_info.parameter_entry_vars.len() {
                        let v = Type::new_var();
                        t_vars.push(v.clone());
                    }
                    let t = Type::Tuple(t_vars);
                    init_bounds_for_type(&t, &mut self.bounds_map);
                    t
                });
            result.push(Constraint {
                right: Type::Variable(lower.clone()),
                left: Type::Pointer(Box::new(Type::Function {
                    args: Box::new(args.clone()),
                    returns: Box::new(Type::Int),
                })),
                addr: InstructionId::from(function_id.index()),
                function_id,
                reason: ConstraintReason::FunctionParameterBinding,
            });
            let Type::Tuple(ts) = args else {
                unreachable!();
            };
            for (ti, (_, callee_ssa_var)) in ts.iter().zip(
                callee_info
                    .parameter_entry_vars
                    .iter()
                    .sorted_by_key(|(k, _)| *k),
            ) {
                result.push(Constraint {
                    right: ti.clone(),
                    left: Type::from_ssavar(callee_ssa_var),
                    addr: InstructionId::from(function_id.index()),
                    function_id,
                    reason: ConstraintReason::FunctionParameterBinding,
                });
                // println!("Added constraint: {} <: {}", &callee_ssa_var, ti.clone());
            }
            /*
            bounds.register_new_upper(
                lower,
                t.clone(),
                ChangeReason::IndirectFuctionParameterBinding(function_id),
            );
            */
        }
        /*
        let Some((args, rets)) = Type::extract_function_from_pointer(upper) else {
            return;
        };
        let Type::Variable(args_kind @ VariableKind::TypeVar(_)) = args else {
            return;
        };
        assert!(matches!(args, Type::Variable(VariableKind::TypeVar(_))));
        let args_upper = effective_upper_bound(args, bounds);
        let args_upper = if args_upper == Type::Any {
        } else {
            args_upper
        };
        let Type::Tuple(ts) = args_upper else {
            unreachable!();
        };
        */

        /*
        result.push(Constraint {
            left: rets.clone(),
            right: Type::Nothing,
            addr: lower.
            function_id: lower.
            reason: ConstraintReason::FunctionReturnBinding,
        });
        */
    }

    /// Create a TypeInferenceResult from the current state of bounds
    fn build_result(&self) -> TypeInferenceResult {
        let inferred_types = self
            .bounds_map
            .iter()
            .filter_map({
                |(k, v)| match k {
                    VariableKind::SsaVar(var) => Some((*var, v.upper.clone())), // Use upper bound as the inferred type for now
                    _ => None,
                }
            })
            .collect();

        TypeInferenceResult {
            inferred_types,
            traces: self.bounds_map.traces.clone(),
            debug_markers: self.debug_markers.clone(),
        }
    }

    fn ok_or_bound_conflict(
        &self,
        key: &VariableKind,
        refined: Option<Type>,
        bound_type: BoundType,
        constraint: &Constraint,
        other: &Type,
    ) -> Result<Type, TypeInferenceError> {
        match refined {
            Some(refined) => Ok(refined),
            None => {
                let current_bound = match bound_type {
                    BoundType::Lower => self.bounds_map.lower_bound(key),
                    BoundType::Upper => self.bounds_map.upper_bound(key),
                }
                .unwrap()
                .clone();
                if constraint.reason == ConstraintReason::PhiAssignment {
                    // Phi assignments may not be a live variable. For now,
                    // return a "Conflict" type and not fail the unification.
                    Ok(Type::Conflict)
                } else {
                    // Extract SSA var from the type if possible for better error reporting
                    Err(TypeInferenceError::TypeConflict {
                        key: key.clone(),
                        bound_type,
                        other: other.clone(),
                        current_bound,
                        constraint: constraint.clone(),
                        partial_result: Box::new(self.build_result()),
                    })
                }
            }
        }
    }
}

pub fn unify(
    model: &ProgramModel,
    constraints: &[Constraint],
    debug_markers: &HashMap<char, SsaOperand>,
) -> Result<TypeInferenceResult, TypeInferenceError> {
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

fn refine_concrete_types(bounds: &mut TypeBoundsMap) -> Result<bool, TypeInferenceError> {
    let mut changed = false;
    for key in bounds.all_keys() {
        let lower = bounds.lower_bound(&key).unwrap().clone();
        let upper = bounds.upper_bound(&key).unwrap().clone();
        if is_concrete_type(&lower) && !is_concrete_type(&upper) {
            bounds.update_bound(
                key,
                BoundType::Upper,
                lower.clone(),
                ChangeReason::ConcreteRefinement,
            );
            changed = true;
        }
        if is_concrete_type(&upper) && !is_concrete_type(&lower) {
            bounds.update_bound(
                key,
                BoundType::Lower,
                upper.clone(),
                ChangeReason::ConcreteRefinement,
            );
            changed = true;
        }
    }
    Ok(changed)
}

fn replace_truthy_with_bool(bounds: &mut TypeBoundsMap) -> Result<bool, TypeInferenceError> {
    let mut changed = false;
    for key in bounds.all_keys() {
        let lower = bounds.lower_bound(&key).unwrap().clone();
        let upper = bounds.upper_bound(&key).unwrap().clone();
        if lower == Type::Truthy && upper == Type::Any
            || upper == Type::Truthy && lower == Type::Nothing
        {
            bounds.update_bound(
                key,
                BoundType::Upper,
                Type::Bool,
                ChangeReason::TruthyToBoolHeuristic,
            );
            bounds.update_bound(
                key,
                BoundType::Lower,
                Type::Bool,
                ChangeReason::TruthyToBoolHeuristic,
            );
            changed = true;
        }
    }
    Ok(changed)
}

fn effective_upper_bound(typ: &Type, bounds: &TypeBoundsMap) -> Type {
    match typ {
        Type::Int | Type::Bool | Type::Char => typ.clone(),
        Type::Truthy | Type::Callable | Type::Conflict | Type::Nothing | Type::Any => typ.clone(),
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
        Type::Truthy | Type::Callable | Type::Conflict | Type::Nothing | Type::Any => typ.clone(),
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
        Type::Truthy | Type::Callable | Type::Conflict | Type::Nothing | Type::Any => {}
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
