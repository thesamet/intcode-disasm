use itertools::Itertools;
use log::trace;
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

use super::constraints::{Constraint, ConstraintReason};
use super::result::TypeInferenceResult;
use super::types::{glb, is_concrete_type, lub, Type, VariableKind};
use super::visuals::TraceColors;
use crate::disasm::v2::model::{FunctionId, ProgramModel};
use crate::disasm::v2::ssa_form::{SsaVar, SsaVarKind};

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
    #[error("Type conflict for {ssa_var}: {bound_type} type conflict between {left} and {right} for {var_type} at {constraint}")]
    TypeConflict {
        ssa_var: SsaVar,
        bound_type: BoundType,
        left: Type,
        right: Type,
        var_type: Type,
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
    bounds: HashMap<Type, TypeBounds>,
    pub traces: Vec<AnalysisTrace>,
}

impl TypeBoundsMap {
    pub(crate) fn new() -> Self {
        Self {
            bounds: HashMap::new(),
            traces: Vec::new(),
        }
    }

    pub(crate) fn all_keys(&self) -> Vec<Type> {
        self.bounds.keys().cloned().collect()
    }

    pub(crate) fn iter(&self) -> std::collections::hash_map::Iter<'_, Type, TypeBounds> {
        self.bounds.iter()
    }

    pub(crate) fn upper_bound(&self, key: &Type) -> Option<&Type> {
        self.bounds.get(key).map(|b| &b.upper)
    }

    pub(crate) fn lower_bound(&self, key: &Type) -> Option<&Type> {
        self.bounds.get(key).map(|b| &b.lower)
    }

    pub(crate) fn insert_key(&mut self, key: Type, lower: Type, upper: Type) -> (Type, Type) {
        self.bounds
            .insert(key, TypeBounds::new(lower.clone(), upper.clone()));
        (lower, upper)
    }

    fn update_bound(
        &mut self,
        key: Type,
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
        self.bounds.insert(key, new_bounds);
    }

    pub(crate) fn register_new_upper(&mut self, key: Type, new_upper: Type, reason: ChangeReason) {
        let old_bounds = self.bounds.get(&key).cloned();
        let lower = old_bounds
            .as_ref()
            .map(|b| b.lower.clone())
            .unwrap_or(Type::Nothing);

        let new_bounds = TypeBounds {
            lower,
            upper: new_upper,
        };

        self.update_bound(key, old_bounds, new_bounds, reason);
    }

    pub(crate) fn register_new_lower(&mut self, key: Type, new_lower: Type, reason: ChangeReason) {
        let old_bounds = self.bounds.get(&key).cloned();
        let upper = old_bounds
            .as_ref()
            .map(|b| b.upper.clone())
            .clone()
            .unwrap_or(Type::Any);

        let new_bounds = TypeBounds {
            lower: new_lower,
            upper: upper.clone(),
        };

        self.update_bound(key, old_bounds, new_bounds, reason);
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
    pub key: Type,
    pub change: BoundChange,
    pub reason: ChangeReason,
}

impl fmt::Display for AnalysisTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Colorize the key type
        let key_str = if let Type::Variable(var) = &self.key {
            TraceColors::format_var(var)
        } else {
            TraceColors::format_type(&self.key)
        };

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
    #[cfg(test)] debug_markers: &HashMap<char, SsaVar>,
) -> Result<TypeInferenceResult, TypeInferenceError> {
    let constraints = constraints.to_vec();
    let mut bounds = TypeBoundsMap::new();
    for c in &constraints {
        init_bounds_for_type(&c.left, &mut bounds);
        init_bounds_for_type(&c.right, &mut bounds);
    }

    for typ in [Type::Int, Type::Bool, Type::Char] {
        bounds.insert_key(typ.clone(), typ.clone(), typ.clone());
    }

    loop {
        while reach_constraint_fixed_point(&constraints, &mut bounds)? {}
        /*
        if refine_function_pointers(model, &mut bounds)? {
            continue;
        }
        */
        if refine_concrete_types(&mut bounds)? {
            continue;
        }
        if replace_truthy_with_bool(&mut bounds)? {
            continue;
        }
        break;
    }

    let result = create_partial_result(
        &bounds,
        #[cfg(test)]
        debug_markers,
    );
    Ok(result)
}

fn reach_constraint_fixed_point(
    constraints: &[Constraint],
    bounds: &mut TypeBoundsMap,
) -> Result<bool, TypeInferenceError> {
    let mut overall_changed = false;
    loop {
        let mut changed = false;
        let mut worklist = constraints.to_vec(); // Clone constraints into a worklist
        while let Some(c) = worklist.pop() {
            changed |= process_constraint(&c, &c.left, &c.right, bounds)?;
        }
        overall_changed |= changed;
        if !changed {
            break;
        }
    }
    Ok(overall_changed)
}

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
                init_bounds_for_type(func_args, bounds);

                /*
                bounds.register_new_lower(
                    fp.args,
                    tuple_type,
                    ChangeReason::IndirectFuctionParameterBinding(function_id),
                );
                */

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

fn refine_concrete_types(bounds: &mut TypeBoundsMap) -> Result<bool, TypeInferenceError> {
    let keys = bounds
        .all_keys()
        .iter()
        .filter(|k| !k.is_var_free())
        .cloned()
        .collect_vec();
    let mut changed = false;
    for key in &keys {
        if key.is_var_free() {
            continue;
        }
        let lower = bounds.lower_bound(key).unwrap().clone();
        let upper = bounds.upper_bound(key).unwrap().clone();
        if is_concrete_type(&lower) && (upper == Type::Any || upper == Type::Truthy) {
            bounds.register_new_upper(key.clone(), lower.clone(), ChangeReason::ConcreteRefinement);
            changed = true;
        }
        if is_concrete_type(&upper) && (lower == Type::Nothing || lower == Type::Truthy) {
            bounds.register_new_lower(key.clone(), upper.clone(), ChangeReason::ConcreteRefinement);
            changed = true;
        }
    }
    Ok(changed)
}

fn replace_truthy_with_bool(bounds: &mut TypeBoundsMap) -> Result<bool, TypeInferenceError> {
    let mut changed = false;
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
    Ok(changed)
}

/// Helper function for handling bound conflicts uniformly
fn handle_bound_conflict(
    constraint: &Constraint,
    type_var: &Type,
    current_bound: &Type,
    new_bound: Option<Type>,
    bound_type: BoundType,
    bounds: &mut TypeBoundsMap,
    #[cfg(test)] debug_markers: &HashMap<char, SsaVar>,
) -> Result<(bool, Type), TypeInferenceError> {
    match new_bound {
        Some(bound) => Ok((bound != *current_bound, bound)),
        None => {
            if constraint.reason == ConstraintReason::PhiAssignment {
                // Phi assignments may not be a live variable. For now,
                // return a "Conflict" type and not fail the unification.
                Ok((false, Type::Conflict))
            } else {
                // Extract SSA var from the type if possible for better error reporting
                if let Type::Variable(VariableKind::SsaVar(ssa_var)) = type_var {
                    Err(TypeInferenceError::TypeConflict {
                        ssa_var: *ssa_var,
                        bound_type,
                        left: constraint.left.clone(),
                        right: constraint.right.clone(),
                        var_type: type_var.clone(),
                        constraint: constraint.clone(),
                        partial_result: Box::new(create_partial_result(
                            bounds,
                            #[cfg(test)]
                            debug_markers,
                        )),
                    })
                } else {
                    Err(TypeInferenceError::BoundConflict {
                        bound_type,
                        left: constraint.left.clone(),
                        right: constraint.right.clone(),
                        var_type: type_var.clone(),
                        constraint: constraint.clone(),
                    })
                }
            }
        }
    }
}

fn process_constraint(
    constraint: &Constraint,
    left: &Type,
    right: &Type,
    bounds: &mut TypeBoundsMap,
) -> Result<bool, TypeInferenceError> {
    let mut changed = false;
    let left_upper = bounds.upper_bound(left).cloned().unwrap_or(left.clone());
    let left_lower = bounds.lower_bound(left).cloned().unwrap_or(left.clone());
    let right_upper = bounds.upper_bound(right).cloned().unwrap_or(right.clone());
    let right_lower = bounds.lower_bound(right).cloned().unwrap_or(right.clone());
    trace!("Processing constraint: {}", constraint);

    // Handle upper bound
    trace!(
        "glb({}, {}) = {:?}",
        left_upper,
        right_upper,
        glb(&left_upper, &right_upper)
    );
    let (upper_changed, new_left_upper) = handle_bound_conflict(
        constraint,
        left,
        &left_upper,
        glb(&left_upper, &right_upper),
        BoundType::Upper,
        bounds,
        #[cfg(test)]
        &HashMap::new(), // Pass empty map for now, fix later if needed
    )?;

    if upper_changed {
        bounds.register_new_upper(
            left.clone(),
            new_left_upper,
            ChangeReason::DecreaseUpperBoundFromConstraint {
                constraint: constraint.clone(),
                other: right.clone(),
            },
        );
        changed = true;
    }
    trace!(
        "lub({}, {}) = {:?}",
        left_lower,
        right_lower,
        lub(&left_lower, &right_lower)
    );

    // Handle lower bound
    let (lower_changed, new_right_lower) = handle_bound_conflict(
        constraint,
        right,
        &right_lower,
        lub(&left_lower, &right_lower),
        BoundType::Lower,
        bounds,
        #[cfg(test)]
        &HashMap::new(), // Pass empty map for now, fix later if needed
    )?;

    if lower_changed {
        bounds.register_new_lower(
            right.clone(),
            new_right_lower,
            ChangeReason::IncreaseLowerBoundFromConstraint {
                constraint: constraint.clone(),
                other: left.clone(),
            },
        );
        changed = true;
    }
    match (left, right) {
        (Type::Pointer(x), Type::Pointer(y)) => {
            changed |= process_constraint(constraint, x, y, bounds)?;
        }
        (x, Type::Pointer(y)) => {
            let y_upper = bounds.upper_bound(y).cloned().unwrap_or(*y.clone());
            let new_upper = Type::Pointer(Box::new(y_upper));
            if new_upper.is_strict_subtype_of(&left_upper) {
                changed |= process_constraint(constraint, x, &new_upper, bounds)?;
            }
        }
        _ => {}
    };
    Ok(changed)
}

pub(crate) fn init_bounds_for_type(typ: &Type, bounds: &mut TypeBoundsMap) -> (Type, Type) {
    match typ {
        Type::Int | Type::Bool | Type::Char => {
            bounds.insert_key(typ.clone(), typ.clone(), typ.clone())
        }
        Type::Truthy | Type::Conflict | Type::Nothing | Type::Any => (Type::Nothing, Type::Any),
        Type::Pointer(x) => {
            let (lower, upper) = init_bounds_for_type(x, bounds);
            bounds.insert_key(
                typ.clone(),
                Type::Pointer(Box::new(lower)),
                Type::Pointer(Box::new(upper)),
            )
        }
        Type::Function { args, returns } => {
            let _ = init_bounds_for_type(args, bounds);
            let _ = init_bounds_for_type(returns, bounds);
            bounds.insert_key(
                typ.clone(),
                Type::Function {
                    args: Box::new(Type::Nothing),
                    returns: Box::new(Type::Any),
                },
                Type::Function {
                    args: Box::new(Type::Any),
                    returns: Box::new(Type::Nothing),
                },
            )
        }
        Type::Tuple(ts) => {
            let mut lower = vec![];
            let mut upper = vec![];
            for t in ts {
                let (l, u) = init_bounds_for_type(t, bounds);
                lower.push(l);
                upper.push(u);
            }
            bounds.insert_key(typ.clone(), Type::Tuple(lower), Type::Tuple(upper))
        }
        Type::Variable(_) => bounds.insert_key(typ.clone(), Type::Nothing, Type::Any),
    }
}

/// Create a TypeInferenceResult from the current state of bounds
pub(crate) fn create_partial_result(
    bounds: &TypeBoundsMap,
    #[cfg(test)] debug_markers: &HashMap<char, SsaVar>,
) -> TypeInferenceResult {
    let inferred_types = bounds
        .iter()
        .filter_map({
            |(k, v)| match k {
                Type::Variable(VariableKind::SsaVar(var)) => Some((*var, v.upper.clone())), // Use upper bound as the inferred type for now
                _ => None,
            }
        })
        .collect();

    TypeInferenceResult {
        inferred_types,
        traces: bounds.traces.clone(),
        #[cfg(test)]
        debug_markers: debug_markers.clone(),
    }
}
