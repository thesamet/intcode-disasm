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
        let function_id_for_key = |&key| match key {
            VariableKind::SsaVar(var) => Some(var.origin_info.function_id),
            VariableKind::Const { origin_info, .. } => Some(origin_info.function_id),
            VariableKind::TypeVar(_) => None,
        };
        for (function_id, key, value) in self
            .bounds_map
            .iter()
            .filter_map(|(key, value)| {
                function_id_for_key(key).map(|function_id| (function_id, key, value))
            })
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
                glb,
                ChangeReason::DecreaseUpperBoundFromConstraint {
                    constraint: constraint.clone(),
                    other: constraint.right.clone(),
                },
            );
            self.add_function_pointer_constraints(u, &constraint.right, &mut result);
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
        function_address: &VariableKind,
        function_type_receiver: &Type,
        result: &mut Vec<Constraint>,
    ) {
        let VariableKind::Const { value: addr, .. } = function_address else {
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
        let callable_ub = effective_upper_bound(&function_type_receiver, &self.bounds_map);
        if callable_ub != Type::Pointer(Box::new(Type::Callable)) {
            return;
        };

        let args = self
            .indirect_function_types
            .entry(function_id)
            .or_insert_with(|| {
                // We have not processed this function pointer yet. Processing
                // ensures that the type variable of args is a subtype of a tuple
                // that corresponds to the callee's parameter SSA vars.
                trace!(
                    "Processing new function pointer {} <: {} <: {}",
                    function_address,
                    function_type_receiver,
                    callable_ub
                );
                let mut x_vars = vec![];
                for _ in 0..callee_info.parameter_entry_vars.len() {
                    let v = Type::new_var();
                    x_vars.push(v.clone());
                }
                let x = Type::Tuple(x_vars);
                init_bounds_for_type(&x, &mut self.bounds_map);
                x
            });
        let fp = Type::Pointer(Box::new(Type::Function {
            args: Box::new(args.clone()),
            returns: Box::new(Type::Int), // Placeholder return type
        }));
        // Let f be the function at the given address. We have an assignment of
        // the form "receiver = f". This means the receiver is of a type that
        // is a supertype of f. We add a constraint on a new function-pointer type fp
        // fp(X_1, X_2, ..) such that type(f) <: fp <: type(receiver) and type(addr) <: fp
        // We introduce a new function pointer variable F(X_1, X,_2, ..) with
        // the constraints that type(f) <: F <: functin_receiver
        result.push(Constraint {
            left: fp.clone(),
            right: function_type_receiver.clone(),
            addr: InstructionId::from(function_id.index()),
            function_id,
            reason: ConstraintReason::Assignment,
        });
        // Add type(addr) <: fp
        result.push(Constraint {
            left: Type::Variable(*function_address),
            right: fp,
            addr: InstructionId::from(function_id.index()),
            function_id,
            reason: ConstraintReason::Assignment,
        });

        // Ensure the args tuple type variable is correctly initialized
        let Type::Tuple(ts) = args else {
            // This should be unreachable as `args` is created as a Tuple above.
            unreachable!("args type should be a Tuple for indirect function call binding");
        };

        // For each X_i (arg of fp), add X_i <: A_i where A_i are the caller side parameters.
        // Which implies f <: fp(X_1, X_2, ...) due to contravariance.
        for (xi, (_, callee_ssa_var)) in ts.iter().zip(
            callee_info
                .parameter_entry_vars
                .iter()
                .sorted_by_key(|(k, _)| *k), // Ensure consistent parameter order
        ) {
            result.push(Constraint {
                left: xi.clone(),                         // Caller's view of the argument type
                right: Type::from_ssavar(callee_ssa_var), // Callee's view of the parameter type
                addr: InstructionId::from(function_id.index()),
                function_id,
                reason: ConstraintReason::FunctionParameterBinding,
            });
        }
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
        /*
        if upper == Type::Truthy && lower == Type::Nothing {
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
            return Ok(true);
        }
        */
        if specifity(&lower) > specifity(&upper) && is_concrete_type(&lower) {
            bounds.update_bound(
                key,
                BoundType::Upper,
                lower.clone(),
                ChangeReason::ConcreteRefinement,
            );
            return Ok(true);
        } else if specifity(&upper) > specifity(&lower) && is_concrete_type(&upper) {
            bounds.update_bound(
                key,
                BoundType::Lower,
                upper.clone(),
                ChangeReason::ConcreteRefinement,
            );
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
            );
            bounds.update_bound(
                key,
                BoundType::Lower,
                Type::Bool,
                ChangeReason::TruthyToBoolHeuristic,
            );
            return Ok(true);
        }
    }
    Ok(false)
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

fn specifity(typ: &Type) -> u32 {
    match typ {
        Type::Int | Type::Bool | Type::Char => 1,
        Type::Truthy | Type::Callable | Type::Conflict | Type::Nothing | Type::Any => 0,
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
