use colored::*;
use itertools::Itertools;
use log::{debug, info};
use std::{collections::HashMap, fmt};
use thiserror::Error;

/// Color scheme for trace and type inference visualization
pub struct TraceColors;

impl TraceColors {
    // Type colors
    pub fn var() -> Color {
        Color::BrightCyan
    }
    pub fn type_name() -> Color {
        Color::BrightMagenta
    }
    pub fn bound() -> Color {
        Color::BrightYellow
    }
    pub fn constraint() -> Color {
        Color::BrightGreen
    }
    pub fn location() -> Color {
        Color::Blue
    } // Using blue instead of bright black for better readability
    pub fn header() -> Color {
        Color::BrightBlue
    }

    // Apply colors to different elements
    pub fn format_var<T: fmt::Display>(var: T) -> ColoredString {
        format!("{}", var).color(Self::var()).bold()
    }

    pub fn format_type<T: fmt::Display>(typ: T) -> ColoredString {
        format!("{}", typ).color(Self::type_name()).bold()
    }

    pub fn format_constraint<T: fmt::Display>(constraint: T) -> ColoredString {
        format!("{}", constraint).color(Self::constraint()).bold()
    }

    pub fn format_location<T: fmt::Display>(location: T) -> ColoredString {
        format!("{}", location).color(Self::location())
    }

    pub fn format_bound<T: fmt::Display>(bound: T) -> ColoredString {
        format!("{}", bound).color(Self::bound()).bold()
    }

    pub fn format_header<T: fmt::Display>(header: T) -> ColoredString {
        format!("{}", header).color(Self::header()).bold()
    }

    pub fn format_relation(text: &str) -> ColoredString {
        text.color(Self::bound()).bold()
    }
}

use crate::disasm::v2::{
    control_flow::NextKind,
    dispatching::EventCollector,
    events::{Event, FunctionCallAnalysisComplete, ModelEventListener, TypeInferenceComplete},
    instructions::{InstructionId, InstructionKind, OperandKind},
    model::{BlockId, FunctionId, ProgramModel},
    ssa_form::{PhiFunction, SsaBlock, SsaFunction, SsaInstruction, SsaResult, SsaVar, SsaVarKind},
};

use crate::disasm::v2::control_flow::PredecessorKind;

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
        partial_result: TypeInferenceResult,
    },

    #[error("{bound_type} bound conflict: type conflict between {left} and {right} for {var_type} at {constraint}")]
    BoundConflict {
        bound_type: BoundType,
        left: Type,
        right: Type,
        var_type: Type,
        constraint: Constraint,
    },

    #[error("Type unification error: {0}")]
    Other(String),
}

/// Represents a type in the type system
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    Nothing,
    Int,
    Bool,
    Char,
    Pointer(Box<Type>),
    Function { args: Vec<Type>, returns: Vec<Type> },
    String,
    TypeVar(SsaVar),
    Truthy, // a marker type for truthy types
    Any,
    Conflict, // Represents a type that was conflicted, but hopefully it will not be needed.
}

impl Type {
    /// Returns true if this type is a subtype of the other type.
    ///
    /// In our type system, a type is a subtype of itself, and Char and Bool are subtypes of Int.
    pub fn is_subtype_of(&self, other: &Type) -> bool {
        match (self, other) {
            // A type is always a subtype of itself
            (a, b) if a == b => true,
            (Type::Nothing, _) => true,
            (_, Type::Any) => true,
            (Type::Char, Type::Int) => true,
            (Type::Bool, Type::Int) => true,
            // (Type::FunctionPointer { .. }, Type::Int) => true,
            // Pointer subtyping is covariant
            (Type::Pointer(_), Type::Int) => true,
            (Type::Pointer(_), Type::Truthy) => true,
            (Type::Function { .. }, Type::Truthy) => true,
            (Type::Int, Type::Truthy) => true,
            (Type::Bool, Type::Truthy) => true,
            (Type::Pointer(a), Type::Pointer(b)) => a.is_subtype_of(b),
            // Function pointer subtyping: contravariant args, covariant returns
            (
                Type::Function {
                    args: args1,
                    returns: returns1,
                },
                Type::Function {
                    args: args2,
                    returns: returns2,
                },
            ) => {
                if args1.len() != args2.len() || returns1.len() != returns2.len() {
                    return false;
                }
                // Check args (contravariant): arg2 must be subtype of arg1
                let args_compatible = args1
                    .iter()
                    .zip(args2.iter())
                    .all(|(a1, a2)| a2.is_subtype_of(a1));
                // Check returns (covariant): return1 must be subtype of return2
                let returns_compatible = returns1
                    .iter()
                    .zip(returns2.iter())
                    .all(|(r1, r2)| r1.is_subtype_of(r2));

                args_compatible && returns_compatible
            }
            (Type::Function { .. }, Type::Int) => true,
            _ => false,
        }
    }

    pub fn is_strict_subtype_of(&self, other: &Type) -> bool {
        self != other && self.is_subtype_of(other)
    }

    fn get_typevars(&self) -> Vec<Type> {
        match self {
            Type::TypeVar(var) => vec![Type::TypeVar(*var)],
            Type::Any => vec![],
            Type::Nothing => vec![],
            Type::Int => vec![],
            Type::Bool => vec![],
            Type::Char => vec![],
            Type::Pointer(x) => x.get_typevars(),
            Type::Function { args, returns } => args
                .iter()
                .chain(returns.iter())
                .flat_map(|x| x.get_typevars())
                .collect(),
            Type::String => vec![],
            Type::Truthy => vec![],
            Type::Conflict => vec![],
        }
    }

    fn is_var_free(&self) -> bool {
        self.get_typevars().is_empty()
    }
}

fn is_concrete_type(typ: &Type) -> bool {
    match typ {
        Type::Int | Type::Bool | Type::Char => true,
        Type::Function { args, returns } => {
            args.iter().all(is_concrete_type) && returns.iter().all(is_concrete_type)
        }
        Type::Pointer(p) => is_concrete_type(p),
        Type::String => true,
        Type::Truthy => false,
        Type::TypeVar(_) => false,
        Type::Conflict => false,
        Type::Any => false,
        Type::Nothing => false,
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Nothing => write!(f, "nothing"),
            Type::Any => write!(f, "any"),
            Type::Int => write!(f, "int"),
            Type::Bool => write!(f, "bool"),
            Type::Char => write!(f, "char"),
            Type::Pointer(t) => write!(f, "Pointer({})", t),
            Type::Truthy => write!(f, "Truthy"),
            Type::Function { args, returns } => {
                write!(f, "fn(")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ") -> ")?;
                if returns.is_empty() {
                    write!(f, "void")?;
                } else {
                    for (i, ret) in returns.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{}", ret)?;
                    }
                }
                Ok(())
            }
            Type::String => write!(f, "string"),
            Type::TypeVar(t) => write!(f, "{}", t),
            Type::Conflict => write!(f, "CONFLICT"),
        }
    }
}

/// Reason for a constraint between types
#[derive(Debug, Clone, Copy, PartialEq, Ord, PartialOrd, Eq)]
pub enum ConstraintReason {
    /// Addition operations imply integer types
    AddSecondParameterImpliesInt,

    // The addition is either numeric or pointer addition. The destination is a more
    // generic type that can contain the type of the first parameter.
    AddFirstParameterSubtypeOfDestination,

    /// Multiplication operations imply integer types
    MulImpliesInt,

    /// Comparison destination implies boolean type
    CompareDstImpliesBool,

    /// Comparison sources imply integer types
    CompareSrcImpliesInt,

    /// Output operations imply character type
    OutputImpliesChar,

    /// Input operations imply character type
    InputImpliesChar,

    /// Jump conditions imply boolean type
    JumpConditionImpliesTruthy,

    /// Both sides of a comparison must have the same type
    CompareSrcSameType,

    /// Assignment operations propagate types
    Assignment,

    /// Dereference operations imply pointer type
    Deref,

    /// Function parameter binding implies same type
    FunctionParameterBinding,

    /// Function return binding implies same type
    FunctionReturnBinding,

    /// Phi assignments propagate types
    PhiAssignment,

    /// Indirect function calls imply function pointer type
    IndirectFunctionCall,
    ImmediateIsSubtypeOfInt,
    /// Internal reason for reconciliation during unification
    Reconciliation,
}

impl fmt::Display for ConstraintReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to the Debug implementation
        write!(f, "{:?}", self)
    }
}

/// Represents a constraint between two types. The constraint implies that
/// the left type is a subtype of the right type.
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct Constraint {
    pub left: Type,
    pub right: Type,

    /// The instruction address where this constraint was generated
    pub addr: InstructionId,
    pub function_id: FunctionId,

    /// The reason for this constraint
    pub reason: ConstraintReason,
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Format the left side with appropriate color
        let left_str = if let Type::TypeVar(var) = &self.left {
            TraceColors::format_var(var)
        } else {
            TraceColors::format_type(&self.left)
        };

        // Format the right side with appropriate color
        let right_str = if let Type::TypeVar(var) = &self.right {
            TraceColors::format_var(var)
        } else {
            TraceColors::format_type(&self.right)
        };

        // Format the location and reason
        let location = TraceColors::format_location(format!("{}:{}", self.function_id, self.addr));
        let reason = TraceColors::format_constraint(&self.reason);

        write!(
            f,
            "{} {} {} {} {} {} {}",
            left_str,
            TraceColors::format_relation("<:"),
            right_str,
            TraceColors::format_location("at"),
            location,
            TraceColors::format_location("because"),
            reason
        )
    }
}

/// Type inference engine for SSA form programs
#[derive(Clone)]
pub struct TypeInferenceAnalyzer {
    /// List of constraints to solve
    constraints: Vec<Constraint>,

    /// Map from SSA variables to their types
    type_vars: HashMap<SsaVar, Type>,

    /// Debug markers for variables
    #[allow(unused)]
    debug_markers: HashMap<char, SsaVar>,

    /// Next available type variable ID
    next_type_var_id: usize,
}

#[derive(Debug, Clone)]
pub struct TypeInferenceResult {
    inferred_types: HashMap<SsaVar, Type>,
    debug_markers: HashMap<char, SsaVar>,
    pub traces: Vec<AnalysisTrace>,
}

impl TypeInferenceResult {
    pub fn get_type_for_ssavar(&self, var: &SsaVar) -> Option<&Type> {
        return self.inferred_types.get(var);
    }

    /// Get the variable associated with a debug marker
    #[cfg(test)]
    pub fn get_marked_var(&self, marker: char) -> Option<&SsaVar> {
        self.debug_markers.get(&marker)
    }

    /// Get the final type for a debug marker after unification
    #[cfg(test)]
    pub fn get_marker_type(&self, marker: char) -> Option<Type> {
        self.get_marked_var(marker)
            .and_then(|var| self.get_type_for_ssavar(var).cloned())
    }

    /// Get traces for a variable plus any related traces through constraints
    pub fn get_recursive_traces_for_ssavar(&self, type_var: Type) -> Vec<(usize, &AnalysisTrace)> {
        let mut result = Vec::new();
        let mut visited = std::collections::HashSet::new();

        self.collect_related_traces(type_var, &mut result, &mut visited);

        // Sort the traces by their original order in the trace vector
        result.sort_by_key(|(idx, _)| *idx);

        result
    }

    fn collect_related_traces<'a>(
        &'a self,
        type_key: Type,
        result: &mut Vec<(usize, &'a AnalysisTrace)>,
        visited: &mut std::collections::HashSet<Type>,
    ) {
        if !visited.insert(type_key.clone()) {
            return; // Already visited this type
        }

        // Find direct changes to this type
        for (idx, trace) in self.traces.iter().enumerate() {
            if trace.key == type_key {
                result.push((idx, trace));

                // For each trace, recursively follow any related types through constraints
                match &trace.reason {
                    ChangeReason::DecreaseUpperBoundFromConstraint {
                        constraint: _,
                        other,
                    }
                    | ChangeReason::IncreaseLowerBoundFromConstraint {
                        constraint: _,
                        other,
                    } => {
                        self.collect_related_traces(other.clone(), result, visited);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Format all traces for an SSA variable in chronological order
    pub fn format_traces_for_type(&self, typ: Type) -> String {
        let traces = self.get_recursive_traces_for_ssavar(typ.clone());
        if traces.is_empty() {
            return format!("No traces found for {}", typ);
        }

        let mut result = format!("Trace history for {}:\n", typ);
        for (idx, trace) in traces {
            result.push_str(&format!("{}. {}\n", idx + 1, trace));
        }

        result
    }
}

impl ModelEventListener for TypeInferenceAnalyzer {
    fn on_function_call_analysis_complete(
        &mut self,
        model: &mut ProgramModel,
        _: FunctionCallAnalysisComplete,
        collector: &mut EventCollector<Event>,
    ) {
        self.constraints.clear();
        info!("Starting type inference analysis");
        let Some(ssa_result) = model.get_ssa_result() else {
            panic!("SSA program not available");
        };

        self.generate_constraints_for_program(model, ssa_result);

        // Solve the constraints through unification
        match self.unify() {
            Ok(result) => {
                log::info!("Type inference completed successfully");

                // Ensure the final substitution map is fully resolved
                model.set_type_inference_result(result);

                // Signal that type inference is complete
                collector.publish(TypeInferenceComplete { completed: true });
            }
            Err(error) => {
                // If this is a type conflict with an SsaVar, output the trace history
                if let TypeInferenceError::TypeConflict {
                    ref partial_result,
                    left,
                    right,
                    ..
                } = &error
                {
                    // Format the trace history for the variable
                    let trace_history_left = partial_result.format_traces_for_type(left.clone());
                    let trace_history_right = partial_result.format_traces_for_type(right.clone());
                    log::error!(
                        "Type conflict trace history for left: {}:\n{}\nType conflict trace history for right: {}:\n{}",
                        left,
                        trace_history_left,
                        right,
                        trace_history_right,
                    );
                }

                panic!("Type inference failed: {}", error);
            }
        }
    }
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

struct TypeBoundsMap {
    bounds: HashMap<Type, TypeBounds>,
    traces: Vec<AnalysisTrace>,
}

impl TypeBoundsMap {
    fn new() -> Self {
        Self {
            bounds: HashMap::new(),
            traces: Vec::new(),
        }
    }

    fn all_keys(&self) -> Vec<Type> {
        self.bounds.keys().cloned().collect()
    }

    fn iter(&self) -> std::collections::hash_map::Iter<'_, Type, TypeBounds> {
        self.bounds.iter()
    }

    fn upper_bound(&self, key: &Type) -> Option<&Type> {
        self.bounds.get(key).map(|b| &b.upper)
    }

    fn lower_bound(&self, key: &Type) -> Option<&Type> {
        self.bounds.get(key).map(|b| &b.lower)
    }

    fn type_bound(&self, key: &Type) -> Option<&TypeBounds> {
        self.bounds.get(key)
    }

    fn insert_key(&mut self, key: Type, lower: Type, upper: Type) {
        self.bounds.insert(key, TypeBounds { lower, upper });
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

    fn register_new_upper(&mut self, key: Type, new_upper: Type, reason: ChangeReason) {
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

    fn register_new_lower(&mut self, key: Type, new_lower: Type, reason: ChangeReason) {
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
        let key_str = if let Type::TypeVar(var) = &self.key {
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

        write!(
            f,
            "{} {}: changed from [{}] to [{}]\n",
            TraceColors::format_header("Type"),
            key_str,
            old_bounds_str,
            new_bounds_str
        )?;

        match &self.reason {
            ChangeReason::DecreaseUpperBoundFromConstraint { constraint, other } => {
                let other_str = if let Type::TypeVar(var) = other {
                    TraceColors::format_var(var)
                } else {
                    TraceColors::format_type(other)
                };

                let constraint_str = format!(
                    "{} @ {}:{}",
                    TraceColors::format_constraint(&constraint.reason),
                    TraceColors::format_location(&constraint.function_id),
                    TraceColors::format_location(&constraint.addr)
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
                let other_str = if let Type::TypeVar(var) = other {
                    TraceColors::format_var(var)
                } else {
                    TraceColors::format_type(other)
                };

                let constraint_str = format!(
                    "{} @ {}:{}",
                    TraceColors::format_constraint(&constraint.reason),
                    TraceColors::format_location(&constraint.function_id),
                    TraceColors::format_location(&constraint.addr)
                );

                write!(
                    f,
                    "  {} from constraint: {} caused by {}",
                    TraceColors::format_bound("Lower bound increased"),
                    constraint_str,
                    other_str
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

impl TypeInferenceAnalyzer {
    /// Create a new type inference engine
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            type_vars: HashMap::new(),
            debug_markers: HashMap::new(),
            next_type_var_id: 0,
        }
    }

    pub fn type_for_ssavar(&self, var: &SsaVar) -> Type {
        Type::TypeVar(*var)
    }

    /// Add a constraint between two types
    pub fn add_constraint(
        &mut self,
        left: Type,
        right: Type,
        addr: InstructionId,
        function_id: FunctionId,
        reason: ConstraintReason,
    ) {
        debug!(
            "Adding constraint: {} <: {} ({:?} at {})",
            left, right, reason, addr
        );
        self.constraints.push(Constraint {
            left,
            right,
            addr,
            function_id,
            reason,
        });
    }

    /// Generate constraints for a phi function
    fn generate_constraints_for_phi(
        &mut self,
        model: &ProgramModel,
        phi: &PhiFunction,
        block_id: BlockId,
    ) {
        let result_type = self.type_for_ssavar(&phi.result);
        let result_addr = InstructionId::from(block_id.index());

        // Add constraints between each input source and the result
        for (pred_kind, input_var) in &phi.inputs {
            match pred_kind {
                PredecessorKind::FunctionCallReturns(call_info) => {
                    // This phi input represents a return value.
                    // We need to link the phi.result (caller's view of the return value)
                    // with the actual return values from the callee, if known.
                    let fca = model.get_function_call_analysis().expect("FCA missing");

                    // Find the call site info for this specific call
                    if let Some(csi) = fca.call_site_info.get(&call_info.calling_block) {
                        // Link the phi.result (caller's return read var) to the
                        // corresponding callee's return write var via the return_map.
                        for (callee_ret_write_var, caller_ret_read_var) in &csi.return_map {
                            // We are looking for the specific entry where the caller's read variable
                            // matches the input_var (which should be phi.result for this predecessor kind).
                            if caller_ret_read_var == input_var {
                                let callee_ret_write_type =
                                    self.type_for_ssavar(callee_ret_write_var);
                                let caller_ret_read_type =
                                    self.type_for_ssavar(caller_ret_read_var);

                                // Constraint: CalleeWrite <: CallerRead (propagates type from callee to caller)
                                self.add_constraint(
                                    callee_ret_write_type,
                                    caller_ret_read_type,
                                    result_addr, // Location in the caller (phi function)
                                    phi.result.function_id,
                                    ConstraintReason::FunctionReturnBinding,
                                );
                            }
                        }
                    } else {
                        log::warn!(
                            "Call site info not found for block {} during phi constraint generation for {}.",
                            call_info.calling_block, phi.result
                        );
                        // Fallback if call site info is missing? Add basic PhiAssignment?
                        // For now, we just skip adding a constraint for this specific return value.
                    }
                }
                _ => {
                    // Standard predecessor: Input <: Result
                    let input_type = self.type_for_ssavar(input_var);
                    self.add_constraint(
                        input_type,
                        result_type.clone(),
                        result_addr, // Use address of the result variable definition
                        phi.result.function_id,
                        ConstraintReason::PhiAssignment,
                    );
                }
            }
        }
    }

    /// Generate constraints for an instruction
    fn generate_constraints_for_instruction(
        &mut self,
        instruction: &SsaInstruction,
        function_id: FunctionId,
    ) {
        let instr_id = instruction.id;

        match &instruction.kind {
            InstructionKind::Assign(target, source) => {
                let dst_type = self.type_for_ssavar(target);
                let src_type = self.type_for_ssavar(source);
                if source.operand().kind.get_immediate().is_some() {
                    self.add_constraint(
                        src_type.clone(),
                        Type::Int,
                        instr_id,
                        function_id,
                        ConstraintReason::ImmediateIsSubtypeOfInt,
                    );
                }
                self.add_constraint(
                    src_type,
                    dst_type,
                    instr_id,
                    function_id,
                    ConstraintReason::Assignment,
                );
            }
            InstructionKind::Add(src1, src2, dst) => {
                let src1_type = self.type_for_ssavar(src1);
                let src2_type = self.type_for_ssavar(src2);
                let dst_type = self.type_for_ssavar(dst);
                let reason = ConstraintReason::AddSecondParameterImpliesInt;

                self.add_constraint(src1_type.clone(), Type::Int, instr_id, function_id, reason);
                self.add_constraint(src2_type, Type::Int, instr_id, function_id, reason);
                self.add_constraint(
                    src1_type,
                    dst_type,
                    instr_id,
                    function_id,
                    ConstraintReason::AddFirstParameterSubtypeOfDestination,
                );
            }
            InstructionKind::Mul(src1, src2, dst) => {
                // It's a real addition/multiplication
                let src1_type = self.type_for_ssavar(src1);
                let src2_type = self.type_for_ssavar(src2);
                let dst_type = self.type_for_ssavar(dst);
                let reason = ConstraintReason::MulImpliesInt;

                self.add_constraint(dst_type, Type::Int, instr_id, function_id, reason);
                self.add_constraint(src1_type, Type::Int, instr_id, function_id, reason);
                self.add_constraint(src2_type, Type::Int, instr_id, function_id, reason);
            }

            InstructionKind::Input(dst) => {
                let dst_type = self.type_for_ssavar(dst);
                self.add_constraint(
                    Type::Char,
                    dst_type,
                    instr_id,
                    function_id,
                    ConstraintReason::InputImpliesChar,
                );
            }

            InstructionKind::Output(src) => {
                let src_type = self.type_for_ssavar(src);
                self.add_constraint(
                    src_type,
                    Type::Char,
                    instr_id,
                    function_id,
                    ConstraintReason::OutputImpliesChar,
                );
            }

            InstructionKind::LessThan(src1, src2, dst) => {
                let src1_type = self.type_for_ssavar(src1);
                let src2_type = self.type_for_ssavar(src2);
                let dst_type = self.type_for_ssavar(dst);

                self.add_constraint(
                    dst_type,
                    Type::Bool,
                    instr_id,
                    function_id,
                    ConstraintReason::CompareDstImpliesBool,
                );
                self.add_constraint(
                    src1_type,
                    Type::Int,
                    instr_id,
                    function_id,
                    ConstraintReason::CompareSrcImpliesInt,
                );
                self.add_constraint(
                    src2_type,
                    Type::Int,
                    instr_id,
                    function_id,
                    ConstraintReason::CompareSrcImpliesInt,
                );
            }

            InstructionKind::Equals(src1, src2, dst) => {
                let src1_type = self.type_for_ssavar(src1);
                let src2_type = self.type_for_ssavar(src2);
                let dst_type = self.type_for_ssavar(dst);

                self.add_constraint(
                    Type::Bool,
                    dst_type,
                    instr_id,
                    function_id,
                    ConstraintReason::CompareDstImpliesBool,
                );
                // Sources must be compatible (unifiable). Add constraint.
                self.add_constraint(
                    src1_type.clone(),
                    src2_type.clone(),
                    instr_id,
                    function_id,
                    ConstraintReason::CompareSrcSameType,
                );
                self.add_constraint(
                    src2_type,
                    src1_type,
                    instr_id,
                    function_id,
                    ConstraintReason::CompareSrcSameType,
                );
            }

            InstructionKind::JumpIfTrue(cond, _) | InstructionKind::JumpIfFalse(cond, _) => {
                let cond_type = self.type_for_ssavar(cond);
                self.add_constraint(
                    cond_type,
                    Type::Truthy,
                    instr_id,
                    function_id,
                    ConstraintReason::JumpConditionImpliesTruthy,
                );
            }

            InstructionKind::AdjustRelativeBase(offset) => {
                // The offset operand must be an integer
                let offset_type = self.type_for_ssavar(offset);
                self.add_constraint(
                    offset_type,
                    Type::Int,
                    instr_id,
                    function_id,
                    ConstraintReason::ImmediateIsSubtypeOfInt, // Re-use reason? Or new one?
                );
            }
            InstructionKind::Halt => { /* No operands */ }
            InstructionKind::Goto(_) => { /* No operands with types */ }
            InstructionKind::Data(_) => { /* Data doesn't participate in type inference this way */
            }
        }
        instruction
            .reads()
            .iter()
            .for_each(|operand| match operand.kind {
                SsaVarKind::Deref {
                    address,
                    address_version,
                } => {
                    let mem_ssa_var = SsaVar {
                        kind: SsaVarKind::Memory(address as i128),
                        offset: operand.offset,
                        version: address_version,
                        function_id: operand.function_id,
                        debug_marker: None,
                    };
                    self.add_constraint(
                        self.type_for_ssavar(&mem_ssa_var),
                        Type::Pointer(Box::new(self.type_for_ssavar(operand))),
                        instruction.id,
                        function_id,
                        ConstraintReason::Deref,
                    );
                }
                _ => {}
            });
    }

    /// Generate constraints for control flow transitions
    fn generate_constraints_for_next(
        &mut self,
        model: &ProgramModel,
        block: &SsaBlock,
        function_id: FunctionId,
        block_id: BlockId,
    ) {
        // Use the address of the *last* instruction in the block for constraint location, if available.
        // Otherwise, use the block ID (start address).
        let location_addr = block
            .instructions
            .last()
            .map(|instr| instr.id)
            .unwrap_or_else(|| InstructionId::from(block_id.index()));

        match &block.next {
            NextKind::Condition(cond) => {
                // The condition operand must be a boolean
                let cond_type = self.type_for_ssavar(&cond.condition_operand);
                self.add_constraint(
                    cond_type,
                    Type::Truthy,
                    location_addr, // Location of the conditional jump
                    function_id,
                    ConstraintReason::JumpConditionImpliesTruthy,
                );
            }

            NextKind::FunctionCall(call) => {
                if let Some(func_addr) = call.function_addr.operand().kind.get_immediate() {
                    // --- Direct Call ---
                    let fca = model
                        .get_function_call_analysis()
                        .expect("FunctionCallAnalysis missing");
                    let callee_id = FunctionId::from(func_addr as usize);

                    let callee_info = &fca.callee_info[&callee_id];

                    // Link caller arguments to callee parameters
                    for (caller_offset, callee_param_var) in &callee_info.parameter_entry_vars {
                        if let Some(caller_arg_var) = block
                            .end_state
                            .get(&OperandKind::RelativeMemory(*caller_offset))
                        {
                            let caller_arg_type = self.type_for_ssavar(caller_arg_var);
                            let callee_param_type = self.type_for_ssavar(callee_param_var);
                            self.add_constraint(
                                caller_arg_type,   // Caller provides argument
                                callee_param_type, // Callee receives parameter
                                location_addr,
                                function_id,
                                ConstraintReason::FunctionParameterBinding,
                            );
                        } else {
                            log::warn!("Caller arg at offset {} not found in block {} end state for call to {}", caller_offset, block_id, callee_id);
                        }
                    }
                } else {
                    let fn_type = self.type_for_ssavar(&call.function_addr);
                    self.add_constraint(
                        fn_type,
                        Type::Pointer(Box::new(Type::Function {
                            args: vec![],    // Placeholder - args inferred from usage at call site
                            returns: vec![], // Placeholder - returns inferred from usage after call
                        })),
                        location_addr,
                        function_id,
                        ConstraintReason::IndirectFunctionCall,
                    );
                }
            }
            NextKind::Return => {
                // TODO: Add constraints for return values based on function analysis
            }
            _ => {}
        }
    }

    /// Generate constraints for an entire block
    fn generate_constraints_for_block(
        &mut self,
        model: &ProgramModel,
        function_id: FunctionId,
        block: &SsaBlock,
    ) {
        let block_id = block.original_id;

        // Process phi functions
        for phi in &block.phi_functions {
            self.generate_constraints_for_phi(model, phi, block_id);
        }

        // Process instructions
        for instr in &block.instructions {
            self.generate_constraints_for_instruction(instr, function_id);
        }

        // Process control flow transition (next)
        self.generate_constraints_for_next(model, block, function_id, block_id);
    }

    /// Generate constraints for a function
    fn generate_constraints_for_function(&mut self, model: &ProgramModel, function: &SsaFunction) {
        for (_, block) in &function.blocks {
            self.generate_constraints_for_block(model, function.original_id, block);
        }
    }

    /// Generate constraints for the entire program
    pub fn generate_constraints_for_program(&mut self, model: &ProgramModel, result: &SsaResult) {
        // Process each function in the program
        for (_, function) in &result.functions {
            self.generate_constraints_for_function(model, function);
        }
    }

    /// Solve the collected constraints using unification
    pub fn unify(&self) -> Result<TypeInferenceResult, TypeInferenceError> {
        let mut bounds = TypeBoundsMap::new();
        for c in &self.constraints {
            init_bounds_for_type(&c.left, &mut bounds);
            init_bounds_for_type(&c.right, &mut bounds);
        }

        for typ in [Type::Int, Type::Bool, Type::Char] {
            bounds.insert_key(typ.clone(), typ.clone(), typ.clone());
        }

        loop {
            while self.reach_constraint_fixed_point(&mut bounds)? {}
            if self.refine_concrete_types(&mut bounds)? {
                continue;
            }
            if self.replace_truthy_with_bool(&mut bounds)? {
                continue;
            }
            break;
        }

        let result = create_partial_result(&bounds, &self.debug_markers);
        Ok(result)
    }

    fn reach_constraint_fixed_point(
        &self,
        bounds: &mut TypeBoundsMap,
    ) -> Result<bool, TypeInferenceError> {
        let mut overall_changed = false;
        loop {
            let mut changed = false;
            let mut worklist = self.constraints.clone();
            while let Some(c) = worklist.pop() {
                changed |=
                    Self::process_constraint(&c, &c.left, &c.right, bounds, &self.debug_markers)?;
            }
            overall_changed |= changed;
            if !changed {
                break;
            }
        }
        Ok(overall_changed)
    }

    fn refine_concrete_types(
        &self,
        bounds: &mut TypeBoundsMap,
    ) -> Result<bool, TypeInferenceError> {
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
            let lower = bounds.lower_bound(&key).unwrap().clone();
            let upper = bounds.upper_bound(&key).unwrap().clone();
            if is_concrete_type(&lower) && (upper == Type::Any || upper == Type::Truthy) {
                bounds.register_new_upper(
                    key.clone(),
                    lower.clone(),
                    ChangeReason::ConcreteRefinement,
                );
                changed = true;
            }
            if is_concrete_type(&upper) && (lower == Type::Nothing || lower == Type::Truthy) {
                bounds.register_new_lower(
                    key.clone(),
                    upper.clone(),
                    ChangeReason::ConcreteRefinement,
                );
                changed = true;
            }
        }
        Ok(changed)
    }

    fn replace_truthy_with_bool(
        &self,
        bounds: &mut TypeBoundsMap,
    ) -> Result<bool, TypeInferenceError> {
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
                bounds.register_new_lower(
                    key.clone(),
                    Type::Bool,
                    ChangeReason::TruthyToBoolHeuristic,
                );
                bounds.register_new_upper(
                    key.clone(),
                    Type::Bool,
                    ChangeReason::TruthyToBoolHeuristic,
                );
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
        debug_markers: &HashMap<char, SsaVar>,
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
                    if let Type::TypeVar(ssa_var) = type_var {
                        return Err(TypeInferenceError::TypeConflict {
                            ssa_var: *ssa_var,
                            bound_type,
                            left: constraint.left.clone(),
                            right: constraint.right.clone(),
                            var_type: type_var.clone(),
                            constraint: constraint.clone(),
                            partial_result: create_partial_result(bounds, debug_markers),
                        });
                    } else {
                        return Err(TypeInferenceError::BoundConflict {
                            bound_type,
                            left: constraint.left.clone(),
                            right: constraint.right.clone(),
                            var_type: type_var.clone(),
                            constraint: constraint.clone(),
                        });
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
        debug_markers: &HashMap<char, SsaVar>,
    ) -> Result<bool, TypeInferenceError> {
        let mut changed = false;
        let left_upper = bounds.upper_bound(&left).cloned().unwrap_or(left.clone());
        let left_lower = bounds.lower_bound(&left).cloned().unwrap_or(left.clone());
        let right_upper = bounds.upper_bound(&right).cloned().unwrap_or(right.clone());
        let right_lower = bounds.lower_bound(&right).cloned().unwrap_or(right.clone());

        // Handle upper bound
        let (upper_changed, new_left_upper) = Self::handle_bound_conflict(
            constraint,
            left,
            &left_upper,
            glb(&left_upper, &right_upper),
            BoundType::Upper,
            bounds,
            debug_markers,
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

        // Handle lower bound
        let (lower_changed, new_right_lower) = Self::handle_bound_conflict(
            constraint,
            right,
            &right_lower,
            lub(&left_lower, &right_lower),
            BoundType::Lower,
            bounds,
            debug_markers,
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
                changed |= Self::process_constraint(constraint, x, y, bounds, debug_markers)?;
            }
            (x, Type::Pointer(y)) => {
                let y_upper = bounds.upper_bound(&y).cloned().unwrap_or(*y.clone());
                let new_upper = Type::Pointer(Box::new(y_upper));
                if new_upper.is_strict_subtype_of(&left_upper) {
                    changed |=
                        Self::process_constraint(constraint, x, &new_upper, bounds, debug_markers)?;
                }
            }
            _ => {}
        };
        Ok(changed)
    }

    /// Mark a variable with a debug character for testing
    #[cfg(test)]
    pub fn mark_var(&mut self, var: SsaVar, marker: char) {
        self.debug_markers.insert(marker, var);
    }
}

/// Create a TypeInferenceResult from the current state of bounds
fn create_partial_result(
    bounds: &TypeBoundsMap,
    debug_markers: &HashMap<char, SsaVar>,
) -> TypeInferenceResult {
    let inferred_types = bounds
        .iter()
        .filter_map({
            |(k, v)| match k {
                Type::TypeVar(var) => Some((*var, v.upper.clone())),
                _ => None,
            }
        })
        .collect();

    TypeInferenceResult {
        inferred_types,
        debug_markers: debug_markers.clone(),
        traces: bounds.traces.clone(),
    }
}

fn init_bounds_for_type(typ: &Type, bounds: &mut TypeBoundsMap) {
    if typ.is_var_free() {
        bounds.insert_key(typ.clone(), typ.clone(), typ.clone());
    } else {
        bounds.insert_key(typ.clone(), Type::Nothing, Type::Any);
    }
    match typ {
        Type::Nothing => {}
        Type::Int => {}
        Type::Bool => {}
        Type::Char => {}
        Type::Truthy => {}
        Type::Conflict => {}
        Type::Pointer(x) => init_bounds_for_type(x, bounds),
        Type::Function { args, returns } => {
            for arg in args {
                init_bounds_for_type(arg, bounds);
            }
            for ret in returns {
                init_bounds_for_type(ret, bounds);
            }
        }
        Type::String => {}
        Type::TypeVar(_) => {}
        Type::Any => {}
    }
}
/// Returns the most specific type that is a supertype of both types (Least Upper Bound).
/// Used for reconciling types during unification when subtyping is involved.
/// Returns None if the types are incompatible.
pub fn lub(a: &Type, b: &Type) -> Option<Type> {
    if a == b {
        Some(a.clone())
    } else if a.is_subtype_of(b) {
        Some(b.clone()) // b is the supertype
    } else if b.is_subtype_of(a) {
        Some(a.clone()) // a is the supertype
    } else {
        None
    }
}

/// Returns the most specific common type (Greatest Lower Bound, conceptually).
/// If one is a subtype of the other, returns the subtype.
/// Returns None if they are incompatible or unrelated.
pub fn glb(a: &Type, b: &Type) -> Option<Type> {
    if a == b {
        Some(a.clone())
    } else if a.is_subtype_of(b) {
        Some(a.clone()) // a is the subtype (more specific)
    } else if b.is_subtype_of(a) {
        Some(b.clone()) // b is the subtype (more specific)
    } else {
        None
    }
}
macro_rules! assert_marker_type {
    ($ctx:expr, $marker:expr, $expected_type:expr) => {
        let ssa_var = $ctx
            .model
            .get_ssa_result()
            .unwrap()
            .find_ssa_var_by_marker($marker);

        let actual_type = $ctx
            .model
            .get_type_inference_result()
            .unwrap()
            .get_type_for_ssavar(&ssa_var)
            .expect("No type found for SSA variable");

        assert_eq!(
            *actual_type, $expected_type,
            "Marker {} has incorrect type: expected {:?}, actual {:?}",
            $marker, $expected_type, actual_type
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::parser;
    use crate::disasm::v2::instructions::Operand;
    use crate::disasm::v2::listeners::function_call_analyzer::FunctionCallAnalyzer;
    use crate::disasm::v2::pretty_print::{pretty_print_ssa, pretty_print_type_vars};
    use crate::disasm::v2::{
        dispatching::EventPublisher,
        events::Event,
        listeners::{
            control_flow_builder::ControlFlowGraphBuilder, data_flow_analyzer::DataFlowAnalyzer,
            image_scanner::ImageScanner, ssa_converter::SsaConverter,
        },
        model::ProgramModel,
    };

    /// TestContext for type inference tests
    struct TestContext {
        model: ProgramModel,
    }

    fn init() {
        use std::io::Write;
        let _ = env_logger::builder()
            .format(|buf, record| writeln!(buf, "{}: {}", record.level(), record.args()))
            .is_test(true)
            .try_init();
    }

    impl TestContext {
        /// Create a new test context with the given assembly code
        fn new(assembly: &str) -> Self {
            // Parse the assembly code
            init();
            let binary = parser::compile(assembly);

            // Create model and event system
            let mut model = ProgramModel::new();
            let mut publisher = EventPublisher::<Event, ProgramModel>::new();

            // Setup the SSA converter and make it accessible to the model
            let ssa_converter = SsaConverter::new();

            // Create all listeners
            let image_scanner = ImageScanner::new();
            let control_flow_builder = ControlFlowGraphBuilder::new();
            let data_flow_analyzer = DataFlowAnalyzer::new();
            // Create type inference engine
            let type_inference = TypeInferenceAnalyzer::new();

            // Register listeners
            publisher.add_listener(Box::new(image_scanner));
            publisher.add_listener(Box::new(control_flow_builder));
            publisher.add_listener(Box::new(data_flow_analyzer));
            publisher.add_listener(Box::new(ssa_converter));
            publisher.add_listener(Box::new(FunctionCallAnalyzer::new()));
            publisher.add_listener(Box::new(type_inference));

            // Run the pipeline
            model.load_image(&binary, &mut publisher);
            publisher.process_events(&mut model);

            Self { model }
        }

        fn assert_type(&mut self, addr: usize, expected: Type) {
            let ti = self.model.get_type_inference_result().unwrap();

            let var = ti
                .inferred_types
                .keys()
                .filter(|var| var.operand().kind.get_memory() == Some(addr as i128))
                .max_by_key(|var| var.version)
                .unwrap_or_else(|| panic!("No type variable found for address {}", addr));

            let actual = ti.get_type_for_ssavar(var).unwrap();
            assert_eq!(
                *actual, expected,
                "Expected type {:?} but got {:?} for memory address {}",
                expected, actual, addr
            );
        }
    }

    fn memory_operand(offset: usize) -> Operand {
        Operand {
            kind: OperandKind::Memory(offset as i128),
            offset: 0,
            debug_marker: None,
        }
    }

    fn deref_operand(offset: usize) -> Operand {
        Operand {
            kind: OperandKind::Deref(offset),
            offset: 0,
            debug_marker: None,
        }
    }

    fn function_pointer(args: Vec<Type>, returns: Vec<Type>) -> Type {
        Type::Pointer(Box::new(Type::Function { args, returns }))
    }

    /// Direct API test for type inference (no assembly parsing)
    #[test]
    fn test_basic_type_inference_api() {
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        let function_id = FunctionId::from(0);

        // Create some SSA variables to infer types for
        let int_var = SsaVar::new(memory_operand(100), 1, function_id);

        let bool_var = SsaVar::new(memory_operand(101), 1, function_id);

        let char_var = SsaVar::new(memory_operand(102), 1, function_id);

        // Mark variables for easier identification in tests
        type_inference.mark_var(int_var.clone(), 'a');
        type_inference.mark_var(bool_var.clone(), 'b');
        type_inference.mark_var(char_var.clone(), 'c');

        // Get type variables for these SSA variables
        let int_type = type_inference.type_for_ssavar(&int_var);
        let bool_type = type_inference.type_for_ssavar(&bool_var);
        let char_type = type_inference.type_for_ssavar(&char_var);

        // Add constraints
        type_inference.add_constraint(
            int_type,
            Type::Int,
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::AddSecondParameterImpliesInt,
        );

        type_inference.add_constraint(
            bool_type,
            Type::Bool,
            InstructionId::from(2),
            FunctionId::from(0),
            ConstraintReason::CompareDstImpliesBool,
        );

        type_inference.add_constraint(
            char_type,
            Type::Char,
            InstructionId::from(3),
            FunctionId::from(0),
            ConstraintReason::OutputImpliesChar,
        );

        // Solve constraints
        let result = type_inference.unify().expect("Unification failed");

        // Verify types using marker functions
        let a_type = result.get_marker_type('a');
        let b_type = result.get_marker_type('b');
        let c_type = result.get_marker_type('c');

        assert_eq!(a_type, Some(Type::Int), "Variable 'a' should be an integer");
        assert_eq!(b_type, Some(Type::Bool), "Variable 'b' should be a boolean");
        assert_eq!(
            c_type,
            Some(Type::Char),
            "Variable 'c' should be a character"
        );
    }

    /// Direct API test for function pointer type inference
    #[test]
    fn test_function_pointer_types_api() {
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        let function_id = FunctionId::from(0);

        // Create an SSA variable for a function pointer
        let func_ptr_var = SsaVar::new(memory_operand(200), 1, function_id);

        // Mark variable
        type_inference.mark_var(func_ptr_var, 'a');

        // Get type variable
        let func_ptr_type = type_inference.type_for_ssavar(&func_ptr_var);

        // Add constraint for function pointer
        type_inference.add_constraint(
            func_ptr_type,
            function_pointer(vec![], vec![]),
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::IndirectFunctionCall,
        );

        // Solve constraints
        let result = type_inference.unify().expect("Unification should succeed");

        // Verify type using marker function
        let a_type = result.get_marker_type('a');

        assert_eq!(
            a_type.as_ref().unwrap(),
            &function_pointer(vec![], vec![]),
            "Variable 'a' should be a function pointer, got: {:?}",
            a_type.as_ref().unwrap()
        );
    }

    /// Direct API test for pointer type inference
    #[test]
    fn test_pointer_types_api() {
        init();
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        let function_id = FunctionId::from(0);

        // Create variables for testing pointer relationships
        let int_var = SsaVar::new(memory_operand(100), 1, function_id);

        // For a pointer variable, we use Memory kind in SSA
        let ptr_var = SsaVar::new(memory_operand(101), 1, function_id);

        // For dereferenced variables, we use the Deref kind
        let deref_var = SsaVar::new(deref_operand(101), 1, function_id);

        // Mark variables
        type_inference.mark_var(int_var.clone(), 'a');
        type_inference.mark_var(ptr_var.clone(), 'b');
        type_inference.mark_var(deref_var.clone(), 'c');

        // Get type variables
        let int_type = type_inference.type_for_ssavar(&int_var);
        let ptr_type = type_inference.type_for_ssavar(&ptr_var);
        let deref_type = type_inference.type_for_ssavar(&deref_var);

        // Add constraints
        // int_var is an integer
        type_inference.add_constraint(
            int_type.clone(),
            Type::Int,
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::AddSecondParameterImpliesInt,
        );

        // ptr_var is a pointer to int_var
        type_inference.add_constraint(
            ptr_type,
            Type::Pointer(Box::new(int_type.clone())),
            InstructionId::from(2),
            FunctionId::from(0),
            ConstraintReason::Assignment,
        );

        // deref_var gets the value of int_var through ptr_var
        type_inference.add_constraint(
            deref_type,
            int_type,
            InstructionId::from(3),
            FunctionId::from(0),
            ConstraintReason::Assignment,
        );

        // Solve constraints
        let result = type_inference.unify().expect("Unification should succeed");

        // Verify types using marker functions
        let a_type = result.get_marker_type('a');
        let b_type = result.get_marker_type('b');
        let c_type = result.get_marker_type('c');

        assert_eq!(a_type, Some(Type::Int), "Variable 'a' should be an integer");
        assert_eq!(
            b_type,
            Some(Type::Pointer(Box::new(Type::Int))),
            "Variable 'b' should be a pointer to an integer"
        );
        assert_eq!(c_type, Some(Type::Int), "Variable 'c' should be an integer");
    }

    /// Test for type conflicts
    #[test]
    fn test_type_conflict() {
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        let function_id = FunctionId::from(0);

        // Create a variable
        let var = SsaVar::new(memory_operand(100), 1, function_id);

        // Get type variable
        let var_type = type_inference.type_for_ssavar(&var);

        // Create another variable that will be unified with var_type
        let another_var = SsaVar::new(memory_operand(101), 1, function_id);
        let another_type = type_inference.type_for_ssavar(&another_var);

        // First, directly set var_type to char type
        type_inference.add_constraint(
            var_type.clone(),
            Type::Char,
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::OutputImpliesChar,
        );

        // Then, set another_type to bool type
        type_inference.add_constraint(
            another_type.clone(),
            Type::Bool,
            InstructionId::from(2),
            FunctionId::from(0),
            ConstraintReason::JumpConditionImpliesTruthy,
        );

        // Now create a constraint between the two variables
        // This should cause a conflict when unifying
        type_inference.add_constraint(
            var_type.clone(),
            another_type.clone(),
            InstructionId::from(3),
            FunctionId::from(0),
            ConstraintReason::Assignment,
        );

        // Unification should fail due to type conflict
        let result = type_inference.unify();

        assert!(
            result.is_err(),
            "Expected unification to fail with type conflict"
        );

        // Check if we get the expected error
        if let Err(err) = result {
            // The error should be a TypeConflict
            match err {
                TypeInferenceError::TypeConflict { .. } => {
                    // Test passes - expected error type
                }
                _ => {
                    panic!("Expected TypeConflict error, got: {:?}", err);
                }
            }
        }
    }

    #[test]
    fn test_type_refinement_with_subtyping() {
        init();
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        let function_id = FunctionId::from(0);

        // Create a variable
        let var = SsaVar::new(memory_operand(100), 1, function_id);

        // Get type variable
        let var_type = type_inference.type_for_ssavar(&var);

        // First, constrain it to Int from arithmetic
        type_inference.add_constraint(
            var_type.clone(),
            Type::Int,
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::AddSecondParameterImpliesInt,
        );

        // Then, constrain it to Char from I/O - this should refine the type
        type_inference.add_constraint(
            var_type.clone(),
            Type::Char,
            InstructionId::from(2),
            FunctionId::from(0),
            ConstraintReason::OutputImpliesChar,
        );

        // Solve constraints
        let result = type_inference.unify().expect("Unification should succeed");

        // Get the final type for the variable
        let final_type = result.get_type_for_ssavar(&var).unwrap();

        // The final type should be Char (the more specific type)
        assert_eq!(
            *final_type,
            Type::Char,
            "Expected type to be refined from Int to Char but got {:?}",
            final_type
        );
    }

    #[test]
    fn test_type_inference() {
        let mut ctx = TestContext::new(
            r#"
        R += 5000
        [3] = 'a [1] + [2]
        [R] = @res
        goto @f1
res:
        halt
f1:
        R += 4
        [21] = [R-1]
        if 'b [R-2] goto @f1
        R -= 4
        goto [R]

        "#,
        );
        pretty_print_ssa(&ctx.model);
        ctx.assert_type(1, Type::Int);
        assert_marker_type!(ctx, 'a', Type::Int);
        print_traces_for_marker(&ctx.model, 'b');
        assert_marker_type!(ctx, 'b', Type::Bool);
    }

    fn print_traces_for_marker(model: &ProgramModel, marker: char) {
        let ssa_var = model
            .get_ssa_result()
            .unwrap()
            .find_ssa_var_by_marker(marker);
        let typ = Type::TypeVar(ssa_var);
        println!(
            "Trace history for {}:\n{}\nType inference completed successfully",
            marker,
            model
                .get_type_inference_result()
                .unwrap()
                .format_traces_for_type(typ)
        );
    }

    #[test]
    fn test_boolean_comparison() {
        let mut ctx = TestContext::new(
            r#"
            R += 1000
            [1000] = [1001] < [1002]
            halt
        "#,
        );
        ctx.assert_type(1000, Type::Bool);
        ctx.assert_type(1001, Type::Int);
        ctx.assert_type(1002, Type::Int);
    }

    #[test]
    fn test_output_implies_char() {
        let mut ctx = TestContext::new(
            r#"
            R += 1000
            output [1001]
            halt
        "#,
        );
        ctx.assert_type(1001, Type::Char);
    }

    #[test]
    fn test_function_addr() {
        let mut ctx = TestContext::new(
            r#"
                R += 1000
                [1001] = [R-2]
                [R] = @ret
                goto [R-2]
                ret:
                halt

            "#,
        );
        ctx.assert_type(1001, function_pointer(vec![], vec![]));
    }

    #[test]
    fn test_function_addr_with_debug() {
        init();
        let ctx = TestContext::new(
            r#"
                    R += 1000
                    'a [R+2] = [R-2]
                    'b [R+2] = 15
                    'c [R+2] = [R+2] + 5
                    [R] = @ret
                    goto [R-2]
            ret:
                    halt
                "#,
        );
        pretty_print_ssa(&ctx.model);
        assert_marker_type!(ctx, 'a', function_pointer(vec![], vec![]));
        assert_marker_type!(ctx, 'b', Type::Int);
        assert_marker_type!(ctx, 'c', Type::Int);
    }

    #[test]
    fn test_link_function_params_to_argument_types() {
        let ctx = TestContext::new(
            r#"
                R += 1000
                output('d [R-3])
                'a [R+1] = 65
                [R] = @ret
                goto @print
    ret:
                halt
    print:
                R += 4
                output('b [R-3])
                R -= 4
                goto [R]
            "#,
        );
        pretty_print_type_vars(&ctx.model);
        assert_marker_type!(ctx, 'd', Type::Char);
        assert_marker_type!(ctx, 'b', Type::Char);
        assert_marker_type!(ctx, 'a', Type::Char);
    }

    #[test]
    fn test_link_function_params_to_argument_types_multi() {
        init();
        let ctx = TestContext::new(
            r#"
                R += 1000
                'a [R+1] = 65
                'b [R+2] = 66
                'c [R+3] = 67
                'd [R+4] = 68
                [R] = @ret
                goto @print
    ret:
                halt
    print:
                R += 10
                output([R-9])
                if [R-8] goto @fret
    fret:
                [R+1] = 3
                [R] = @call_ret
                goto [R-7]
    call_ret:
                ptr = [R-6]
                [R-2] = *ptr
                if [R-2] goto @done
    done:
                R -= 10
                goto [R]
            "#,
        );
        pretty_print_ssa(&ctx.model);
        assert_marker_type!(ctx, 'a', Type::Char);
        print_traces_for_marker(&ctx.model, 'b');
        assert_marker_type!(ctx, 'b', Type::Int);
        assert_marker_type!(ctx, 'c', function_pointer(vec![], vec![]));
        assert_marker_type!(ctx, 'd', Type::Pointer(Box::new(Type::Bool)));
    }

    #[test]
    fn use_function_pointer_for_conditional_jump() {
        let ctx = TestContext::new(
            r#"
                R += 1000
                'a [R-1] = [5000]
                'b [R+1] = 65
                if ![R-1] goto @ret
                [R] = @ret
                goto [R-1]
    ret:
                halt
            "#,
        );
        pretty_print_ssa(&ctx.model);

        assert_marker_type!(ctx, 'a', function_pointer(vec![], vec![]));
    }

    #[test]
    fn test_link_function_return_type_single() {
        let ctx = TestContext::new(
            r#"
                R += 1000
                'a [R-3] = @add
                'b [R+1] = 65
                'c [R+2] = 65
                'd [R+3] = 65
                [R] = @ret
                goto @add
    ret:
                'f [R+1] = [R+3]
                halt
    add:
                R += 5
                output([R-2])
                'e [R-2] = [R-3] < [R-4]
                R -= 5
                goto [R]
            "#,
        );
        pretty_print_ssa(&ctx.model);

        assert_marker_type!(ctx, 'b', Type::Int);
        assert_marker_type!(ctx, 'c', Type::Int);
        assert_marker_type!(ctx, 'd', Type::Char);
        assert_marker_type!(ctx, 'e', Type::Bool);
        assert_marker_type!(ctx, 'f', Type::Bool);
    }

    #[test]
    fn test_reconcile_truthy_with_pointer_across_functions() {
        let ctx = TestContext::new(
            r#"
                R += 1000
                'a [320] = 17
                'b [R+1] = 320
                [R] = @ret
                goto @print_char_after_pointer
    ret:
                if ![R+1] goto @end
                [R-1] = [R+1]
    end:
                halt
    print_char_after_pointer:
                R += 5
                [R-4] = 'f [R-4] + 55
                'd ptr = 'e [R-4]
                [R-1] = *ptr
                output('c [R-1])
                R -= 5
                goto [R]
            "#,
        );
        pretty_print_ssa(&ctx.model);

        /*
        print_traces_for_marker(&ctx.model, 'a');
        assert_marker_type!(ctx, 'a', Type::Char);
        */
        print_traces_for_marker(&ctx.model, 'b');
        print_traces_for_marker(&ctx.model, 'd');
        print_traces_for_marker(&ctx.model, 'e');
        print_traces_for_marker(&ctx.model, 'f');
        assert_marker_type!(ctx, 'b', Type::Pointer(Box::new(Type::Char)));
        // [R-4] <: [R+1]
        // [R-4] <: Pointer(Char)
        // [R+1] <: Truthy
    }
}
