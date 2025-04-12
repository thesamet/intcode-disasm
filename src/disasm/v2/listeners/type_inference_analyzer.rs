use itertools::Itertools;
use log::{debug, info};
use std::{collections::HashMap, fmt};

use crate::disasm::v2::{
    control_flow::NextKind,
    dispatching::{EventCollector, EventListener},
    events::{Event, TypeInferenceComplete},
    instructions::{InstructionId, InstructionKind, OperandKind},
    model::{BlockId, FunctionId, ProgramModel},
    ssa_form::{PhiFunction, SsaBlock, SsaFunction, SsaInstruction, SsaResult, SsaVar},
};

/// Represents a type in the type system
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Type {
    Nothing,
    Int,
    Bool,
    Char,
    Pointer(Box<Type>),
    FunctionPointer { args: Vec<Type>, returns: Vec<Type> },
    String,
    TypeVar(SsaVar),
    Any,
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
            (Type::Pointer(a), Type::Pointer(b)) => a.is_subtype_of(b),
            // Function pointer subtyping: contravariant args, covariant returns
            (
                Type::FunctionPointer {
                    args: args1,
                    returns: returns1,
                },
                Type::FunctionPointer {
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
            (Type::FunctionPointer { .. }, Type::Int) => true,
            _ => false,
        }
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
            Type::FunctionPointer { args, returns } => args
                .iter()
                .chain(returns.iter())
                .flat_map(|x| x.get_typevars())
                .collect(),
            Type::String => vec![],
        }
    }

    fn is_var_free(&self) -> bool {
        self.get_typevars().is_empty()
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
            Type::FunctionPointer { args, returns } => {
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
        }
    }
}

/// Reason for a constraint between types
#[derive(Debug, Clone, Copy, PartialEq, Ord, PartialOrd, Eq)]
pub enum ConstraintReason {
    /// Addition operations imply integer types
    AddImpliesInt,

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
    JumpConditionImpliesBool,

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

/// Represents a constraint between two types. The constraint implies that
/// the left type is a subtype of the right type.
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
struct Constraint {
    left: Type,
    right: Type,

    /// The instruction address where this constraint was generated
    addr: InstructionId,

    /// The reason for this constraint
    reason: ConstraintReason,
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Constraint: {} = {} at {} because {:?}",
            self.left, self.right, self.addr, self.reason
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
    #[cfg(test)]
    debug_markers: HashMap<char, SsaVar>,
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
}

impl EventListener<Event, ProgramModel> for TypeInferenceAnalyzer {
    fn on_event(
        &mut self,
        model: &mut ProgramModel,
        event: Event,
        collector: &mut EventCollector<Event>,
    ) {
        match event {
            // Start type inference after SSA conversion is complete
            Event::SsaConversionComplete(_) => {
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
                        panic!("Type inference failed: {}", error);
                    }
                }
            }
            _ => {
                // Ignore other events
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
            reason,
        });
    }

    /// Generate constraints for a phi function
    fn generate_constraints_for_phi(&mut self, phi: &PhiFunction, block_id: BlockId) {
        let result_type = self.type_for_ssavar(&phi.result);
        let result_addr = InstructionId::from(block_id.index());

        // Add constraints between each input and the result
        for (_, input_var) in &phi.inputs {
            let input_type = Type::TypeVar(*input_var);
            self.add_constraint(
                input_type,
                result_type.clone(),
                result_addr, // Use address of the result variable definition
                ConstraintReason::PhiAssignment,
            );
        }
    }

    /// Generate constraints for an instruction
    fn generate_constraints_for_instruction(
        &mut self,
        instruction: &SsaInstruction,
        _block_id: BlockId,
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
                        ConstraintReason::ImmediateIsSubtypeOfInt,
                    );
                }
                self.add_constraint(src_type, dst_type, instr_id, ConstraintReason::Assignment);
            }
            InstructionKind::Add(src1, src2, dst) | InstructionKind::Mul(src1, src2, dst) => {
                // It's a real addition/multiplication
                let src1_type = self.type_for_ssavar(src1);
                let src2_type = self.type_for_ssavar(src2);
                let dst_type = self.type_for_ssavar(dst);
                let reason = match instruction.kind {
                    InstructionKind::Add(_, _, _) => ConstraintReason::AddImpliesInt,
                    _ => ConstraintReason::MulImpliesInt,
                };

                self.add_constraint(dst_type, Type::Int, instr_id, reason);
                self.add_constraint(src1_type, Type::Int, instr_id, reason);
                self.add_constraint(src2_type, Type::Int, instr_id, reason);
            }

            InstructionKind::Input(dst) => {
                let dst_type = self.type_for_ssavar(dst);
                self.add_constraint(
                    Type::Char,
                    dst_type,
                    instr_id,
                    ConstraintReason::InputImpliesChar,
                );
            }

            InstructionKind::Output(src) => {
                let src_type = self.type_for_ssavar(src);
                self.add_constraint(
                    src_type,
                    Type::Char,
                    instr_id,
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
                    ConstraintReason::CompareDstImpliesBool,
                );
                self.add_constraint(
                    src1_type,
                    Type::Int,
                    instr_id,
                    ConstraintReason::CompareSrcImpliesInt,
                );
                self.add_constraint(
                    src2_type,
                    Type::Int,
                    instr_id,
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
                    ConstraintReason::CompareDstImpliesBool,
                );
                // Sources must be compatible (unifiable). Add constraint.
                self.add_constraint(
                    src1_type.clone(),
                    src2_type.clone(),
                    instr_id,
                    ConstraintReason::CompareSrcSameType,
                );
                self.add_constraint(
                    src2_type,
                    src1_type,
                    instr_id,
                    ConstraintReason::CompareSrcSameType,
                );
            }

            InstructionKind::JumpIfTrue(cond, _) | InstructionKind::JumpIfFalse(cond, _) => {
                let cond_type = self.type_for_ssavar(cond);
                self.add_constraint(
                    cond_type,
                    Type::Bool,
                    instr_id,
                    ConstraintReason::JumpConditionImpliesBool,
                );
            }

            InstructionKind::AdjustRelativeBase(offset) => {
                // The offset operand must be an integer
                let offset_type = self.type_for_ssavar(offset);
                self.add_constraint(
                    offset_type,
                    Type::Int,
                    instr_id,
                    ConstraintReason::AddImpliesInt, // Re-use reason? Or new one?
                );
            }
            InstructionKind::Halt => { /* No operands */ }
            InstructionKind::Goto(_) => { /* No operands with types */ }
            InstructionKind::Data(_) => { /* Data doesn't participate in type inference this way */
            }
        }
    }

    /// Generate constraints for control flow transitions
    fn generate_constraints_for_next(
        &mut self,
        model: &ProgramModel,
        block: &SsaBlock,
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
                    Type::Bool,
                    location_addr, // Location of the conditional jump
                    ConstraintReason::JumpConditionImpliesBool,
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
                        Type::FunctionPointer {
                            args: vec![],    // Placeholder - args inferred from usage at call site
                            returns: vec![], // Placeholder - returns inferred from usage after call
                        },
                        location_addr,
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
    fn generate_constraints_for_block(&mut self, model: &ProgramModel, block: &SsaBlock) {
        let block_id = block.original_id;

        // Process phi functions
        for phi in &block.phi_functions {
            self.generate_constraints_for_phi(phi, block_id);
        }

        // Process instructions
        for instr in &block.instructions {
            self.generate_constraints_for_instruction(instr, block_id);
        }

        // Process control flow transition (next)
        self.generate_constraints_for_next(model, block, block_id);
    }

    /// Generate constraints for a function
    fn generate_constraints_for_function(&mut self, model: &ProgramModel, function: &SsaFunction) {
        for (_, block) in &function.blocks {
            self.generate_constraints_for_block(model, block);
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
    pub fn unify(&self) -> Result<TypeInferenceResult, String> {
        let mut upper_bounds = HashMap::new();
        let mut lower_bounds = HashMap::new();
        for c in &self.constraints {
            init_bounds_for_type(&c.left, &mut lower_bounds, &mut upper_bounds);
            init_bounds_for_type(&c.right, &mut lower_bounds, &mut upper_bounds);
        }

        for typ in [Type::Int, Type::Bool, Type::Char] {
            upper_bounds.insert(typ.clone(), typ.clone());
            lower_bounds.insert(typ.clone(), typ.clone());
        }

        let mut changed;
        loop {
            loop {
                changed = false;
                let mut worklist = self.constraints.clone();
                while let Some(c) = worklist.pop() {
                    changed |= Self::process_constraint(
                        &c.left,
                        &c.right,
                        &mut upper_bounds,
                        &mut lower_bounds,
                    )?;
                }
                if !changed {
                    break;
                }
            }
            for (key, upper) in upper_bounds.iter_mut() {
                let lower = lower_bounds.get_mut(key).unwrap();
                if *upper == Type::Any && *lower != Type::Nothing {
                    *upper = lower.clone();
                    changed = true;
                    debug!("Setting upper bound for {}: {}", key, lower);
                } else if *lower == Type::Nothing && *upper != Type::Any {
                    *lower = upper.clone();
                    changed = true;
                    debug!("Setting lower bound for {}: {}", key, upper);
                }
            }
            if !changed {
                break;
            }
        }

        let inferred_types = upper_bounds
            .iter()
            .filter_map({
                |(k, v)| match k {
                    Type::TypeVar(ssa_var) => {
                        let v = if *v == Type::Any || *v == Type::Nothing {
                            lower_bounds[k].clone()
                        } else {
                            v.clone()
                        };
                        Some((*ssa_var, v))
                    }
                    _ => None,
                }
            })
            .collect();
        for k in upper_bounds.keys() {
            debug!(
                "bounds for {}: [{}, {}]",
                k, lower_bounds[k], upper_bounds[k]
            );
        }
        let result = TypeInferenceResult {
            inferred_types,
            #[cfg(test)]
            debug_markers: self.debug_markers.clone(),
        };
        Ok(result)
    }

    fn process_constraint(
        left: &Type,
        right: &Type,
        upper_bounds: &mut HashMap<Type, Type>,
        lower_bounds: &mut HashMap<Type, Type>,
    ) -> Result<bool, String> {
        let mut changed = false;
        let left_upper = upper_bounds.get(&left).cloned().unwrap_or(left.clone());
        let left_lower = lower_bounds.get(&left).cloned().unwrap_or(left.clone());
        let right_upper = upper_bounds.get(&right).cloned().unwrap_or(right.clone());
        let right_lower = lower_bounds.get(&right).cloned().unwrap_or(right.clone());
        let Some(new_left_upper) = glb(&left_upper, &right_upper) else {
            return Err(format!(
                "Type conflict for {} and {} for {}",
                left_upper, right_upper, left
            ));
        };
        if new_left_upper != left_upper {
            debug!(
                "Constraint: {} in [{}, {}] <: {} in [{}, {}]: new upper bound for {}: {}",
                left, left_lower, left_upper, right, right_lower, right_upper, left, new_left_upper
            );

            changed = true;
            upper_bounds.insert(left.clone(), new_left_upper.clone());
        }
        let Some(new_right_lower) = lub(&left_lower, &right_lower) else {
            return Err(format!(
                "Type conflict for {} and {} for {}",
                left_lower, right_lower, right
            ));
        };
        if new_right_lower != right_lower {
            debug!(
                "Constraint: {} in [{}, {}] <: {} in [{}, {}]: new lower bound for {}: {}",
                left,
                left_lower,
                left_upper,
                right,
                right_lower,
                right_upper,
                right,
                new_right_lower
            );

            changed = true;
            lower_bounds.insert(right.clone(), new_right_lower.clone());
        }
        match (left, right) {
            (Type::Pointer(x), Type::Pointer(y)) => {
                changed |= Self::process_constraint(x, y, upper_bounds, lower_bounds)?;
            }
            (x, Type::Pointer(y)) => {
                let y_upper = upper_bounds.get(&y).cloned().unwrap_or(*y.clone());
                let new_upper = Type::Pointer(Box::new(y_upper));
                if new_upper != left_upper {
                    debug!(
                        "Constraint: {} in [{}, {}] <: {} in [{}, {}]: recursing with new upper for x={}: {}",
                        left, left_lower, left_upper, right, right_lower, right_upper, x, new_upper
                    );
                    changed |= Self::process_constraint(x, &new_upper, upper_bounds, lower_bounds)?;
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

fn init_bounds_for_type(
    typ: &Type,
    lower_bounds: &mut HashMap<Type, Type>,
    upper_bounds: &mut HashMap<Type, Type>,
) {
    if typ.is_var_free() {
        upper_bounds.insert(typ.clone(), typ.clone());
        lower_bounds.insert(typ.clone(), typ.clone());
    } else {
        upper_bounds.insert(typ.clone(), Type::Any);
        lower_bounds.insert(typ.clone(), Type::Nothing);
    }
    match typ {
        Type::Nothing => {}
        Type::Int => {}
        Type::Bool => {}
        Type::Char => {}
        Type::Pointer(x) => init_bounds_for_type(x, lower_bounds, upper_bounds),
        Type::FunctionPointer { args, returns } => {
            for arg in args {
                init_bounds_for_type(arg, lower_bounds, upper_bounds);
            }
            for ret in returns {
                init_bounds_for_type(ret, lower_bounds, upper_bounds);
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
            ConstraintReason::AddImpliesInt,
        );

        type_inference.add_constraint(
            bool_type,
            Type::Bool,
            InstructionId::from(2),
            ConstraintReason::CompareDstImpliesBool,
        );

        type_inference.add_constraint(
            char_type,
            Type::Char,
            InstructionId::from(3),
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
            Type::FunctionPointer {
                args: vec![],
                returns: vec![],
            },
            InstructionId::from(1),
            ConstraintReason::IndirectFunctionCall,
        );

        // Solve constraints
        let result = type_inference.unify().expect("Unification should succeed");

        // Verify type using marker function
        let a_type = result.get_marker_type('a');

        assert!(
            matches!(a_type, Some(Type::FunctionPointer { .. })),
            "Variable 'a' should be a function pointer, got: {:?}",
            a_type
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
            ConstraintReason::AddImpliesInt,
        );

        // ptr_var is a pointer to int_var
        type_inference.add_constraint(
            ptr_type,
            Type::Pointer(Box::new(int_type.clone())),
            InstructionId::from(2),
            ConstraintReason::Assignment,
        );

        // deref_var gets the value of int_var through ptr_var
        type_inference.add_constraint(
            deref_type,
            int_type,
            InstructionId::from(3),
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
            ConstraintReason::OutputImpliesChar,
        );

        // Then, set another_type to bool type
        type_inference.add_constraint(
            another_type.clone(),
            Type::Bool,
            InstructionId::from(2),
            ConstraintReason::JumpConditionImpliesBool,
        );

        // Now create a constraint between the two variables
        // This should cause a conflict when unifying
        type_inference.add_constraint(
            var_type.clone(),
            another_type.clone(),
            InstructionId::from(3),
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
            // The error message should contain "Type conflict"
            assert!(
                err.contains("Type conflict"),
                "Expected error message to contain 'Type conflict', got: {}",
                err
            );
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
            ConstraintReason::AddImpliesInt,
        );

        // Then, constrain it to Char from I/O - this should refine the type
        type_inference.add_constraint(
            var_type.clone(),
            Type::Char,
            InstructionId::from(2),
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
        ctx.assert_type(1, Type::Int);
        assert_marker_type!(ctx, 'a', Type::Int);
        assert_marker_type!(ctx, 'b', Type::Bool);
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
        ctx.assert_type(
            1001,
            Type::FunctionPointer {
                args: vec![],
                returns: vec![],
            },
        );
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
        assert_marker_type!(
            ctx,
            'a',
            Type::FunctionPointer {
                args: vec![],
                returns: vec![],
            }
        );
        assert_marker_type!(ctx, 'b', Type::Int);
        assert_marker_type!(ctx, 'c', Type::Int);
    }

    #[test]
    #[ignore] // Temporarily ignore this test as it needs to be updated after SsaVar changes
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
        assert_marker_type!(ctx, 'b', Type::Bool);
        assert_marker_type!(
            ctx,
            'c',
            Type::FunctionPointer {
                args: vec![],
                returns: vec![],
            }
        );
        assert_marker_type!(ctx, 'd', Type::Pointer(Box::new(Type::Bool)));
    }

    #[test]
    #[ignore]
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

        assert_marker_type!(ctx, 'b', Type::Int);
        assert_marker_type!(ctx, 'c', Type::Int);
        assert_marker_type!(ctx, 'd', Type::Char);
        assert_marker_type!(ctx, 'e', Type::Bool);
        assert_marker_type!(ctx, 'f', Type::Bool);
    }
}
