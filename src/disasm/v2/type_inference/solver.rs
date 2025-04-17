use itertools::Itertools;
use log::trace;
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

use super::constraints::{Constraint, ConstraintReason};
use super::result::TypeInferenceResult;
use super::types::VariableKind;
use super::visuals::TraceColors;
use crate::disasm::v2::instructions::InstructionId;
use crate::disasm::v2::model::{FunctionId, ProgramModel};
use crate::disasm::v2::ssa_form::{SsaVar, SsaVarKind};
use crate::disasm::v2::type_inference::types::{glb, lub, Type};

/// Enum to distinguish between upper and lower bound conflicts
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub(crate) fn new() -> Self {
        Self {
            bounds: HashMap::new(),
            traces: Vec::new(),
        }
    }

    pub(crate) fn all_keys(&self) -> Vec<VariableKind> {
        self.bounds.keys().cloned().collect()
    }

    pub(crate) fn iter(&self) -> std::collections::hash_map::Iter<'_, VariableKind, TypeBounds> {
        self.bounds.iter()
    }

    pub(crate) fn upper_bound(&self, key: &VariableKind) -> Option<&Type> {
        self.bounds.get(key).map(|b| &b.upper)
    }

    pub(crate) fn lower_bound(&self, key: &VariableKind) -> Option<&Type> {
        self.bounds.get(key).map(|b| &b.lower)
    }

    pub(crate) fn insert_key(&mut self, key: VariableKind, lower: Type, upper: Type) {
        self.bounds
            .insert(key, TypeBounds::new(lower.clone(), upper.clone()));
    }

    fn update_bound(
        &mut self,
        key: &VariableKind,
        old_bounds: Option<TypeBounds>,
        new_bounds: TypeBounds,
        reason: ChangeReason,
    ) {
        let trace = AnalysisTrace {
            key: key.clone(),
            change: BoundChange {
                old_bounds,
                new_bounds: new_bounds.clone(),
            },
            reason,
        };
        self.traces.push(trace);
        self.bounds.insert(key.clone(), new_bounds);
    }

    pub(crate) fn register_new_upper(
        &mut self,
        key: &VariableKind,
        new_upper: Type,
        reason: ChangeReason,
    ) {
        let old_bounds = self.bounds.get(&key).cloned();
        let lower = old_bounds
            .as_ref()
            .map(|b| b.lower.clone())
            .unwrap_or(Type::Nothing);

        trace!(
            "Registering new upper bound for {} from {} to {}",
            key,
            lower,
            new_upper
        );
        let new_bounds = TypeBounds {
            lower,
            upper: new_upper,
        };

        self.update_bound(key, old_bounds, new_bounds, reason);
    }

    pub(crate) fn register_new_lower(
        &mut self,
        key: &VariableKind,
        new_lower: Type,
        reason: ChangeReason,
    ) {
        let old_bounds = self.bounds.get(&key).cloned();
        let upper = old_bounds
            .as_ref()
            .map(|b| b.upper.clone())
            .clone()
            .unwrap_or(Type::Any);

        trace!(
            "Registering new lower bound for {} from {} to {}",
            key,
            upper,
            new_lower
        );

        let new_bounds = TypeBounds {
            lower: new_lower,
            upper: upper.clone(),
        };

        self.update_bound(&key, old_bounds, new_bounds, reason);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundChange {
    pub old_bounds: Option<TypeBounds>,
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

        // Format old bounds with colors
        let old_bounds_str = match &self.change.old_bounds {
            Some(bounds) => format!(
                "{}, {}",
                TraceColors::format_type(&bounds.lower),
                TraceColors::format_type(&bounds.upper)
            ),
            None => "none".to_string(),
        };

        // Format new bounds with colors
        let new_bounds_str = format!(
            "{}, {}",
            TraceColors::format_type(&self.change.new_bounds.lower),
            TraceColors::format_type(&self.change.new_bounds.upper)
        );

        writeln!(
            f,
            "{} {}: changed from [{}] to [{}]",
            TraceColors::format_header("Type"),
            key_str,
            old_bounds_str,
            new_bounds_str
        )?;

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

                write!(
                    f,
                    "  {} from constraint: {} caused by {}",
                    TraceColors::format_bound("Upper bound decreased"),
                    constraint_str,
                    other_str
                )
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

                write!(
                    f,
                    "  {} from constraint: {} caused by {}",
                    TraceColors::format_bound("Lower bound increased"),
                    constraint_str,
                    other_str
                )
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

/// Solve the collected constraints using unification
pub fn unify(
    model: &ProgramModel,
    constraints: &[Constraint],
    debug_markers: &HashMap<char, SsaVar>,
) -> Result<TypeInferenceResult, TypeInferenceError> {
    let constraints = constraints.to_vec();
    let mut bounds = TypeBoundsMap::new();
    for c in &constraints {
        init_bounds_for_type(&c.left, &mut bounds);
        init_bounds_for_type(&c.right, &mut bounds);
    }

    loop {
        while reach_constraint_fixed_point(model, &constraints, &mut bounds, debug_markers)? {}
        /*
        if refine_function_pointers(model, &mut bounds)? {
            continue;
        }
        */
        if refine_concrete_types(&mut bounds)? {
            trace!("Refined concrete types changed");
            continue;
        }
        if replace_truthy_with_bool(&mut bounds)? {
            trace!("Replaced truthy with bool changed");
            continue;
        }
        break;
    }

    let result = create_partial_result(&bounds, debug_markers);
    Ok(result)
}

fn reach_constraint_fixed_point(
    model: &ProgramModel,
    constraints: &[Constraint],
    bounds: &mut TypeBoundsMap,
    debug_markers: &HashMap<char, SsaVar>,
) -> Result<bool, TypeInferenceError> {
    let mut overall_changed = false;
    loop {
        let mut changed_in_iteration = false;
        let mut worklist = constraints.to_vec(); // Clone constraints into a worklist
        while let Some(c) = worklist.pop() {
            let (changed, constraints) = process_constraint(model, &c, bounds, debug_markers)?;
            changed_in_iteration |= changed;
            overall_changed |= changed_in_iteration;
            worklist.extend(constraints);
        }
        trace!(
            "changed_in_iteration: {} changed_overall: {}",
            changed_in_iteration,
            overall_changed
        );
        if !changed_in_iteration {
            return Ok(overall_changed);
        }
    }
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
    /*
    for key in &keys {
        let lower = bounds.lower_bound(key).unwrap().clone();
        let upper = bounds.upper_bound(key).unwrap().clone();
        if is_concrete_type(&lower)
            && (upper == Type::Any || upper == Type::Truthy)
            && upper != lower
        {
            bounds.register_new_upper(key.clone(), lower.clone(), ChangeReason::ConcreteRefinement);
            if *key == Type::Variable(VariableKind::TypeVar(3)) {
                trace!(
                    "concreting upper: {} now: {:?}",
                    key,
                    bounds.bounds.get(key)
                );
            }
            changed = true;
        }
        if is_concrete_type(&upper)
            && (lower == Type::Nothing || lower == Type::Truthy)
            && upper != lower
        {
            bounds.register_new_lower(key.clone(), upper.clone(), ChangeReason::ConcreteRefinement);
            if *key == Type::Variable(VariableKind::TypeVar(3)) {
                trace!(
                    "concreting lower: {} now: {:?}",
                    key,
                    bounds.bounds.get(key)
                );
            }
            changed = true;
        }
    }
    */
    Ok(changed)
}

fn replace_truthy_with_bool(bounds: &mut TypeBoundsMap) -> Result<bool, TypeInferenceError> {
    let mut changed = false;
    /*
    for key in bounds.all_keys() {
        if key.is_var_free() {
            continue;
        }
        let lower = bounds.lower_bound(&key).unwrap().clone();
        let upper = bounds.upper_bound(&key).unwrap().clone();
        if lower == Type::Truthy && upper == Type::Any
            || upper == Type::Truthy && lower == Type::Nothing
        {
            bounds.register_new_lower(key.clone(), Type::Bool, ChangeReason::TruthyToBoolHeuristic);
            bounds.register_new_upper(key.clone(), Type::Bool, ChangeReason::TruthyToBoolHeuristic);
            changed = true;
        }
    }
    */
    Ok(changed)
}

/// Helper function for handling bound conflicts uniformly
fn ok_or_bound_conflict(
    constraint: &Constraint,
    key: &VariableKind,
    bound_type: BoundType,
    refined: Option<Type>,
    other: &Type,
    bounds: &mut TypeBoundsMap,
    debug_markers: &HashMap<char, SsaVar>,
) -> Result<Type, TypeInferenceError> {
    match refined {
        Some(refined) => Ok(refined),
        None => {
            let current_bound = match bound_type {
                BoundType::Upper => bounds.upper_bound(key),
                BoundType::Lower => bounds.lower_bound(key),
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
                    partial_result: Box::new(create_partial_result(bounds, debug_markers)),
                })
            }
        }
    }
}

fn process_constraint(
    model: &ProgramModel,
    constraint: &Constraint,
    bounds: &mut TypeBoundsMap,
    debug_markers: &HashMap<char, SsaVar>,
) -> Result<(bool, Vec<Constraint>), TypeInferenceError> {
    trace!("Processing constraint: {}", constraint);
    let mut result = vec![];
    let mut changed = false;
    match (constraint.left.clone(), constraint.right.clone()) {
        (Type::Variable(v), x) => {
            let v_upper = bounds.upper_bound(&v).cloned().unwrap();
            let new_v_upper = glb(&v_upper, &effective_upper_bound(&x, bounds));
            let new_v_upper = ok_or_bound_conflict(
                constraint,
                &v,
                BoundType::Upper,
                new_v_upper,
                &x,
                bounds,
                debug_markers,
            )?;
            if v_upper != new_v_upper {
                bounds.register_new_upper(
                    &v,
                    new_v_upper.clone(),
                    ChangeReason::DecreaseUpperBoundFromConstraint {
                        constraint: constraint.clone(),
                        other: x,
                    },
                );
                trace!(
                    "Changed upper bound of {} from {} to {}",
                    v,
                    v_upper,
                    new_v_upper,
                );
                changed = true;
            }
            add_function_pointer_constraints(model, bounds, &v, &v_upper, &mut result);
        }
        (x, Type::Variable(v)) => {
            let v_lower = bounds.lower_bound(&v).unwrap().clone();
            let new_v_lower = lub(&v_lower, &effective_lower_bound(&x, bounds));
            let new_v_lower = ok_or_bound_conflict(
                constraint,
                &v,
                BoundType::Lower,
                new_v_lower,
                &x,
                bounds,
                debug_markers,
            )?;
            if v_lower != new_v_lower {
                bounds.register_new_lower(
                    &v,
                    new_v_lower.clone(),
                    ChangeReason::IncreaseLowerBoundFromConstraint {
                        constraint: constraint.clone(),
                        other: x,
                    },
                );
                trace!(
                    "Changed lower bound of {} from {} to {}",
                    v,
                    v_lower,
                    new_v_lower,
                );
                changed = true;
            }
            add_function_pointer_constraints(model, bounds, &v, &v_lower, &mut result);
        }
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

fn add_function_pointer_constraints(
    model: &ProgramModel,
    bounds: &mut TypeBoundsMap,
    lower: &VariableKind,
    upper: &Type,
    result: &mut Vec<Constraint>,
) {
    let VariableKind::SsaVar(SsaVar {
        kind: SsaVarKind::Immediate(addr),
        ..
    }) = lower
    else {
        return;
    };
    let function_id = FunctionId::from(*addr as usize);
    let Some(callee_info) = model
        .get_function_call_analysis()
        .unwrap()
        .callee_info
        .get(&function_id)
    else {
        return;
    };

    let Some((args, rets)) = Type::extract_function_from_pointer(upper) else {
        return;
    };
    let Type::Variable(args_kind @ VariableKind::TypeVar(_)) = args else {
        return;
    };
    assert!(matches!(args, Type::Variable(VariableKind::TypeVar(_))));
    let args_upper = effective_upper_bound(args, bounds);
    let args_upper = if args_upper == Type::Any {
        // We have not processed this function pointer yet. Processing
        // ensures that the type variable of args is a subtype of a tuple
        // that corresponds to the callee's parameter SSA vars.
        let mut t_vars = vec![];
        for _ in 0..callee_info.parameter_entry_vars.len() {
            let v = Type::new_var();
            t_vars.push(v.clone());
        }
        let t = Type::Tuple(t_vars);
        init_bounds_for_type(&t, bounds);
        bounds.register_new_upper(
            args_kind,
            t.clone(),
            ChangeReason::IndirectFuctionParameterBinding(function_id),
        );
        t
    } else {
        args_upper
    };
    let Type::Tuple(ts) = args_upper else {
        unreachable!();
    };
    for (ti, (_, callee_ssa_var)) in ts.iter().zip(
        callee_info
            .parameter_entry_vars
            .iter()
            .sorted_by_key(|(k, _)| *k),
    ) {
        result.push(Constraint {
            left: Type::from_ssavar(callee_ssa_var),
            right: ti.clone(),
            addr: InstructionId::from(function_id.index()),
            function_id,
            reason: ConstraintReason::FunctionParameterBinding,
        });
    }

    /*
    result.push(Constraint {
        left: rets.clone(),
        right: Type::Nothing,
        addr: callee_info.return_var,
        function_id: FunctionId::from(addr as usize),
        reason: ConstraintReason::FunctionReturnBinding,
    });
    */
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
            bounds.insert_key(v.clone(), Type::Nothing, Type::Any);
        }
    }
}

/// Create a TypeInferenceResult from the current state of bounds
pub(crate) fn create_partial_result(
    bounds: &TypeBoundsMap,
    debug_markers: &HashMap<char, SsaVar>,
) -> TypeInferenceResult {
    let inferred_types = bounds
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
        traces: bounds.traces.clone(),
        debug_markers: debug_markers.clone(),
    }
}
