use log::{debug, info};
use std::{collections::HashMap, fmt};

use crate::disasm::v2::{
    control_flow::NextKind,
    dispatching::{EventCollector, EventListener},
    events::{Event, TypeInferenceComplete},
    instructions::{InstructionKind, Operand, OperandKind},
    model::{BlockId, FunctionId, ProgramModel},
    ssa_form::{PhiFunction, SsaBlock, SsaFunction, SsaInstruction, SsaResult, SsaVar},
};

/// Unique identifier for a type variable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeVarId(pub FunctionId, pub usize);

impl fmt::Display for TypeVarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t{}_{}", self.0, self.1)
    }
}

/// Represents a type in the type system
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum Type {
    /// Integer type
    Int,

    /// Boolean type
    Bool,

    /// Character type
    Char,

    /// Pointer to another type
    Pointer(Box<Type>),

    /// Function pointer with argument and return types
    FunctionPointer { args: Vec<Type>, returns: Vec<Type> },

    /// String type
    #[allow(unused)]
    String,

    /// Type variable (used during inference)
    TypeVar(TypeVarId),
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Int => write!(f, "int"),
            Type::Bool => write!(f, "bool"),
            Type::Char => write!(f, "char"),
            Type::Pointer(t) => write!(f, "*{}", t),
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

impl Type {
    /// Returns true if this type is a subtype of the other type.
    ///
    /// In our type system, a type is a subtype of itself, and Char and Bool are subtypes of Int.
    pub fn is_subtype_of(&self, other: &Type) -> bool {
        match (self, other) {
            // A type is always a subtype of itself
            (a, b) if a == b => true,

            // Char and Bool are subtypes of Int
            (Type::Char, Type::Int) => true,
            (Type::Bool, Type::Int) => true,

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

            // Type variables are not involved in subtyping checks directly here
            (Type::TypeVar(_), _) | (_, Type::TypeVar(_)) => false,

            // All other cases aren't subtypes
            _ => false,
        }
    }

    /// Returns the most specific type that is a supertype of both types (Least Upper Bound).
    /// Used for reconciling types during unification when subtyping is involved.
    /// Returns None if the types are incompatible.
    pub fn least_upper_bound(a: &Type, b: &Type) -> Option<Type> {
        if a == b {
            Some(a.clone())
        } else if a.is_subtype_of(b) {
            Some(b.clone()) // b is the supertype
        } else if b.is_subtype_of(a) {
            Some(a.clone()) // a is the supertype
        } else {
            // Check for specific LUB cases like (Pointer(T1), Pointer(T2)) -> Pointer(LUB(T1, T2))
            // Or Function Pointers (more complex, requires GLB for args)
            // For now, only handle direct subtyping.
            None
        }
    }

    /// Returns the most specific common type (Greatest Lower Bound, conceptually).
    /// If one is a subtype of the other, returns the subtype.
    /// Returns None if they are incompatible or unrelated.
    pub fn most_specific_common_type(a: &Type, b: &Type) -> Option<Type> {
        if a == b {
            Some(a.clone())
        } else if a.is_subtype_of(b) {
            Some(a.clone()) // a is the subtype (more specific)
        } else if b.is_subtype_of(a) {
            Some(b.clone()) // b is the subtype (more specific)
        } else {
            // Handle structural cases if needed (e.g., *T1 and *T2 -> *GLB(T1, T2))
            // For now, only handle direct subtyping.
            None
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
    ImmediateIsInt,
    /// Internal reason for reconciliation during unification
    Reconciliation,
}

/// Represents a constraint between two types
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
struct Constraint {
    /// The left side of the constraint
    left: Type,

    /// The right side of the constraint
    right: Type,

    /// The instruction address where this constraint was generated
    addr: usize,

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
    inferred_types: HashMap<TypeVarId, Type>,
    type_vars: HashMap<SsaVar, Type>,
}

impl TypeInferenceResult {
    pub fn get_type_for_ssavar(&self, var: &SsaVar) -> Option<&Type> {
        if let Some(Type::TypeVar(id)) = self.type_vars.get(var).cloned() {
            return self.inferred_types.get(&id);
        }
        None
    }

    pub fn get_typevar_for_ssavar(&self, var: &SsaVar) -> Option<&Type> {
        if let Some(f @ Type::TypeVar(_)) = self.type_vars.get(var) {
            return Some(f);
        }
        None
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
                info!("Starting type inference analysis");
                let Some(ssa_result) = model.get_ssa_result() else {
                    panic!("SSA program not available");
                };

                self.generate_constraints_for_program(model, ssa_result);

                // Solve the constraints through unification
                match self.unify() {
                    Ok(substitution) => {
                        log::info!("Type inference completed successfully");

                        // Ensure the final substitution map is fully resolved
                        let final_types = Self::fully_substitute_map(substitution);

                        model.set_type_inference_result(TypeInferenceResult {
                            inferred_types: final_types,
                            type_vars: self.type_vars.clone(),
                        });

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

    /// Generate a fresh type variable for a given function
    fn fresh_type_var(&mut self, function_id: FunctionId) -> Type {
        let id = self.next_type_var_id;
        self.next_type_var_id += 1;
        Type::TypeVar(TypeVarId(function_id, id))
    }

    /// Get the type variable for an SSA variable, creating one if it doesn't exist.
    pub fn type_for_ssavar(&mut self, var: &SsaVar) -> Type {
        if let Some(typ) = self.type_vars.get(var) {
            return typ.clone();
        }

        let typ = self.fresh_type_var(var.function_id).clone();
        if let OperandKind::Deref(addr) = var.operand.kind {
            // First, collect all candidate variables (to avoid borrowing issues)
            let memory_var = self
                .type_vars
                .keys()
                .filter(|other_var| {
                    other_var.function_id == var.function_id
                        && other_var.operand.kind.get_memory() == Some(addr as i128)
                })
                .max_by_key(|other_var| other_var.version)
                .cloned();

            // Now process the candidates with no borrow conflicts
            if let Some(memory_var) = memory_var {
                // If we find it, add a deref constraint
                let pointer_type = self.type_for_ssavar(&memory_var).clone();
                let instr_id = 5555;
                self.add_constraint(
                    pointer_type.clone(),
                    Type::Pointer(Box::new(typ.clone())),
                    instr_id,
                    ConstraintReason::Deref,
                );
            }
        }
        self.type_vars.insert(var.clone(), typ.clone());
        typ
    }

    /// Add a constraint between two types
    pub fn add_constraint(
        &mut self,
        left: Type,
        right: Type,
        addr: usize,
        reason: ConstraintReason,
    ) {
        debug!(
            "Adding constraint: {} = {} ({:?} at {})",
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
    fn generate_constraints_for_phi(&mut self, phi: &PhiFunction, _block_id: BlockId) {
        let result_type = self.type_for_ssavar(&phi.result);
        let result_addr = phi.result.operand.offset;

        // Add constraints between each input and the result
        for (_, input_var) in &phi.inputs {
            let input_type = self.type_for_ssavar(input_var);
            self.add_constraint(
                result_type.clone(),
                input_type,
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
        let instr_id = instruction.id.index();

        match &instruction.kind {
            InstructionKind::Assign(target, source) => {
                let dst_type = self.type_for_ssavar(target);
                let src_type = self.type_for_ssavar(source);
                if source.operand.kind.get_immediate().is_some() {
                    self.add_constraint(
                        src_type.clone(),
                        Type::Int,
                        instr_id,
                        ConstraintReason::ImmediateIsInt,
                    );
                }
                self.add_constraint(dst_type, src_type, instr_id, ConstraintReason::Assignment);
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
                    dst_type,
                    Type::Char,
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
                    dst_type,
                    Type::Bool,
                    instr_id,
                    ConstraintReason::CompareDstImpliesBool,
                );
                // Sources must be compatible (unifiable). Add constraint.
                self.add_constraint(
                    src1_type,
                    src2_type,
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
            .map(|instr| instr.id.index())
            .unwrap_or_else(|| block_id.index());

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
                let callee_addr_var = &call.function_addr;
                let callee_addr_type = self.type_for_ssavar(callee_addr_var);

                if let Some(func_addr) = call.function_addr.operand.kind.get_immediate() {
                    // --- Direct Call ---
                    let fca = model
                        .get_function_call_analysis()
                        .expect("FunctionCallAnalysis missing");
                    let callee_id = FunctionId::from(func_addr as usize);

                    if let Some(callee_info) = fca.callee_info.get(&callee_id) {
                        // TODO: Infer function signature (arg/return types) and constrain callee_addr_type

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
                        // TODO: Link caller return locations to callee return vars (if any)
                        // This requires knowing return value locations (convention?)
                        // and the SSA vars for return values in the callee.

                        // Create expected function type based on analysis (if available)
                        // let expected_args = ... derive from parameter_entry_vars ...;
                        // let expected_returns = ... derive from return analysis ...;
                        // self.add_constraint(callee_addr_type, Type::FunctionPointer { args: expected_args, returns: expected_returns }, ...);
                    } else {
                        log::warn!("Callee info not found for direct call target {}", callee_id);
                        // Add a generic function pointer constraint as fallback?
                        self.add_constraint(
                            callee_addr_type,
                            Type::FunctionPointer {
                                args: vec![],
                                returns: vec![],
                            }, // Unknown signature
                            location_addr,
                            ConstraintReason::IndirectFunctionCall, // Treat as opaque call
                        );
                    }
                } else {
                    // --- Indirect Call ---
                    // The callee address variable must be a function pointer.
                    // We don't know the signature yet, unify with a generic one.
                    // Unification with specific call sites might refine this later.
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
                    // TODO: Add constraints based on arguments passed at this specific call site.
                    // e.g., if `[R+1]` is passed, `arg1_type = type_for_ssavar([R+1])`
                    // constrain `callee_addr_type = fn(arg1_type, ...) -> ...`
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

    /// Substitute type variables according to the substitution map recursively.
    /// This follows the chain `t1 -> t2 -> ... -> T`.
    pub fn substitute(t: Type, subst: &HashMap<TypeVarId, Type>) -> Type {
        match t {
            Type::Int => Type::Int,
            Type::Bool => Type::Bool,
            Type::Char => Type::Char,
            Type::Pointer(t) => Type::Pointer(Box::new(Self::substitute(*t, subst))),
            Type::FunctionPointer { args, returns } => Type::FunctionPointer {
                args: args
                    .into_iter()
                    .map(|t| Self::substitute(t, subst))
                    .collect(),
                returns: returns
                    .into_iter()
                    .map(|t| Self::substitute(t, subst))
                    .collect(),
            },
            Type::String => Type::String,
            Type::TypeVar(id) => subst
                .get(&id)
                .map(|t| Self::substitute(t.clone(), subst))
                .unwrap_or(Type::TypeVar(id)),
        }
    }

    /// Solve the collected constraints using unification
    pub fn unify(&self) -> Result<HashMap<TypeVarId, Type>, String> {
        let mut worklist = self.constraints.clone();
        let mut subst = HashMap::new();
        worklist.sort();
        worklist.reverse();

        while let Some(constraint) = worklist.pop() {
            let left = Self::substitute(constraint.left.clone(), &subst);
            let right = Self::substitute(constraint.right.clone(), &subst);

            match (&left, &right) {
                (Type::TypeVar(id), Type::TypeVar(id2)) if id == id2 => {
                    // Same type variable, nothing to do
                    continue;
                }

                (Type::TypeVar(id), _) => {
                    // If the type variable already has a substitution, we need to ensure it's compatible
                    if let Some(existing_type) = subst.get(id) {
                        if existing_type.is_subtype_of(&right) {
                            // Existing type is more specific than right, keep it
                            // No need to add a new constraint
                            debug!(
                                "unify: keeping {} as {} (more specific than {})",
                                id, existing_type, right
                            );
                        } else if right.is_subtype_of(existing_type) {
                            // Right is more specific than existing type, update substitution
                            debug!(
                                "unify: refining {} from {} to {} (more specific)",
                                id, existing_type, right
                            );
                            subst.insert(*id, right);
                        } else {
                            // Not in a subtyping relationship, add a constraint for compatibility check
                            worklist.push(Constraint {
                                left: existing_type.clone(),
                                right: right.clone(),
                                addr: constraint.addr,
                                reason: constraint.reason,
                            });
                        }
                    } else {
                        // No existing substitution, just add it
                        debug!("unify: {} => {}", id, right);
                        subst.insert(*id, right);
                    }
                }

                (_, Type::TypeVar(id)) => {
                    // If the type variable already has a substitution, we need to ensure it's compatible
                    if let Some(existing_type) = subst.get(id) {
                        if existing_type.is_subtype_of(&left) {
                            // Existing type is more specific than left, keep it
                            // No need to add a new constraint
                            debug!(
                                "unify: keeping {} as {} (more specific than {})",
                                id, existing_type, left
                            );
                        } else if left.is_subtype_of(existing_type) {
                            // Left is more specific than existing type, update substitution
                            debug!(
                                "unify: refining {} from {} to {} (more specific)",
                                id, existing_type, left
                            );
                            subst.insert(*id, left);
                        } else {
                            // Not in a subtyping relationship, add a constraint for compatibility check
                            worklist.push(Constraint {
                                left: existing_type.clone(),
                                right: left.clone(),
                                addr: constraint.addr,
                                reason: constraint.reason,
                            });
                        }
                    } else {
                        // No existing substitution, just add it
                        debug!("unify: {} => {}", id, left);
                        subst.insert(*id, left);
                    }
                }

                // --- Cases for Concrete Types ---
                (Type::Pointer(t1), Type::Pointer(t2)) => {
                    debug!("  -> Pointer: Adding constraint {} = {}", **t1, **t2);
                    // Add constraint to unify the pointed-to types
                    worklist.push(Constraint {
                        left: (**t1).clone(),
                        right: (**t2).clone(),
                        addr: constraint.addr,
                        reason: constraint.reason,
                    });
                }

                // 5. Function Pointers: fn(A1..) -> R1 = fn(A2..) -> R2
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
                    if args1.len() != args2.len() {
                        return Err(format!(
                            "Function pointer argument count mismatch: {} vs {} in ({}) = ({}) (Constraint: {})",
                            args1.len(), args2.len(), left, right, constraint
                        ));
                    }
                    if returns1.len() != returns2.len() {
                        return Err(format!(
                            "Function pointer return count mismatch: {} vs {} in ({}) = ({}) (Constraint: {})",
                            returns1.len(), returns2.len(), left, right, constraint
                        ));
                    }

                    debug!("  -> FuncPtr: Adding constraints for args and returns");
                    // Add constraints for arguments (unify corresponding types)
                    for (arg1, arg2) in args1.iter().zip(args2.iter()) {
                        worklist.push(Constraint {
                            left: arg1.clone(),
                            right: arg2.clone(),
                            addr: constraint.addr,
                            reason: constraint.reason,
                        });
                    }
                    // Add constraints for returns (unify corresponding types)
                    for (ret1, ret2) in returns1.iter().zip(returns2.iter()) {
                        worklist.push(Constraint {
                            left: ret1.clone(),
                            right: ret2.clone(),
                            addr: constraint.addr,
                            reason: constraint.reason,
                        });
                    }
                }

                // 6. Subtyping: T1 = T2 where T1 <: T2 or T2 <: T1
                // This case handles relationships between concrete types like Char = Int.
                // It confirms compatibility but doesn't generate further substitutions between them.
                // The more specific type should emerge naturally if unified with a variable elsewhere.
                (t1, t2) if t1.is_subtype_of(t2) || t2.is_subtype_of(t1) => {
                    debug!("  -> Subtype: Compatible concrete types {} and {}", t1, t2);
                    // No action needed, the relationship holds.
                }

                /*
                // 7. Conflict: Incompatible concrete types
                // This catches Int = Bool, *T = Int, fn(...) = Char, etc.
                (t1, t2) if Self::are_incompatible_concrete_types(t1, t2) => {
                    return Err(format!(
                        "Type conflict: Cannot unify {} and {} (Constraint: {})",
                        left, right, constraint
                    ));
                }
                */
                _ => {
                    // This case shouldn't normally be reached, but handle unknown cases
                    // by returning an error to be safe
                    return Err(format!(
                        "Unknown type combination: {} and {} at instruction {}",
                        left, right, constraint.addr
                    ));
                }
            }
        }

        // Final substitution pass is crucial to resolve chains like t1->t2, t2->Int
        let final_subst = Self::fully_substitute_map(subst);

        // Final occurs check on the fully substituted map
        for (id, typ) in &final_subst {
            if Self::contains_type_var(typ, *id) {
                // Check if it's just t -> t, which is harmless
                if matches!(typ, Type::TypeVar(tid) if tid == id) {
                    continue;
                }

                return Err(format!(
                    "Recursive type detected after unification: {} = {}",
                    Type::TypeVar(*id),
                    typ
                ));
            }
        }

        Ok(final_subst)
    }

    /// Applies substitutions repeatedly until the map stabilizes.
    fn fully_substitute_map(mut subst: HashMap<TypeVarId, Type>) -> HashMap<TypeVarId, Type> {
        let mut changed = true;
        while changed {
            changed = false;
            let current_subst = subst.clone(); // Use stable map for lookups in this pass

            for (_var_id, typ) in subst.iter_mut() {
                let new_type = Self::substitute(typ.clone(), &current_subst);
                if &new_type != typ {
                    *typ = new_type;
                    changed = true;
                }
            }
        }
        // Optional: Remove trivial identity substitutions (t -> t)
        subst.retain(|_id, typ| !matches!(typ, Type::TypeVar(tid) if tid == _id));
        subst
    }

    /// Determine if two types are incompatible (cannot be unified)
    fn are_incompatible_types(t1: &Type, t2: &Type) -> bool {
        match (t1, t2) {
            // Types with subtyping relationship are compatible
            _ if t1.is_subtype_of(t2) || t2.is_subtype_of(t1) => false,

            // TypeVars are handled separately in unification
            (Type::TypeVar(_), _) | (_, Type::TypeVar(_)) => false,

            // Any other combination is incompatible
            _ => true,
        }
    }

    /// Check if a type contains a specific type variable
    fn contains_type_var(typ: &Type, var_id: TypeVarId) -> bool {
        match typ {
            Type::TypeVar(id) => *id == var_id,
            Type::Pointer(inner) => Self::contains_type_var(inner, var_id),
            Type::FunctionPointer { args, returns } => {
                args.iter().any(|arg| Self::contains_type_var(arg, var_id))
                    || returns
                        .iter()
                        .any(|ret| Self::contains_type_var(ret, var_id))
            }
            _ => false,
        }
    }

    /// Mark a variable with a debug character for testing
    #[cfg(test)]
    pub fn mark_var(&mut self, var: SsaVar, marker: char) {
        self.debug_markers.insert(marker, var);
    }

    /// Get the variable associated with a debug marker
    #[cfg(test)]
    pub fn get_marked_var(&self, marker: char) -> Option<&SsaVar> {
        self.debug_markers.get(&marker)
    }

    /// Get the final type for a variable after unification
    #[cfg(test)]
    pub fn get_var_type(&self, var: &SsaVar, subst: &HashMap<TypeVarId, Type>) -> Option<Type> {
        self.type_vars.get(var).map(|initial_type| {
            // Fully substitute the initial type using the final map
            Self::substitute(initial_type.clone(), subst)
        })
    }

    /// Get the final type for a debug marker after unification
    #[cfg(test)]
    pub fn get_marker_type(&self, marker: char, subst: &HashMap<TypeVarId, Type>) -> Option<Type> {
        self.get_marked_var(marker)
            .and_then(|var| self.get_var_type(var, subst))
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
        let _ = env_logger::builder().is_test(true).try_init();
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
            println!("ti: {:?}", ti);

            let var = ti
                .type_vars
                .keys()
                .filter(|var| var.operand.kind.get_memory() == Some(addr as i128))
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
        type_inference.add_constraint(int_type, Type::Int, 1, ConstraintReason::AddImpliesInt);

        type_inference.add_constraint(
            bool_type,
            Type::Bool,
            2,
            ConstraintReason::CompareDstImpliesBool,
        );

        type_inference.add_constraint(
            char_type,
            Type::Char,
            3,
            ConstraintReason::OutputImpliesChar,
        );

        // Solve constraints
        let substitution = type_inference.unify().expect("Unification failed");

        // Verify types using marker functions
        let a_type = type_inference.get_marker_type('a', &substitution);
        let b_type = type_inference.get_marker_type('b', &substitution);
        let c_type = type_inference.get_marker_type('c', &substitution);

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
        type_inference.mark_var(func_ptr_var.clone(), 'a');

        // Get type variable
        let func_ptr_type = type_inference.type_for_ssavar(&func_ptr_var);

        // Add constraint for function pointer
        type_inference.add_constraint(
            func_ptr_type,
            Type::FunctionPointer {
                args: vec![],
                returns: vec![],
            },
            1,
            ConstraintReason::IndirectFunctionCall,
        );

        // Solve constraints
        let substitution = type_inference.unify().expect("Unification should succeed");

        // Verify type using marker function
        let a_type = type_inference.get_marker_type('a', &substitution);

        assert!(
            matches!(a_type, Some(Type::FunctionPointer { .. })),
            "Variable 'a' should be a function pointer, got: {:?}",
            a_type
        );
    }

    /// Direct API test for pointer type inference
    #[test]
    fn test_pointer_types_api() {
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
            1,
            ConstraintReason::AddImpliesInt,
        );

        // ptr_var is a pointer to int_var
        type_inference.add_constraint(
            ptr_type,
            Type::Pointer(Box::new(int_type.clone())),
            2,
            ConstraintReason::Assignment,
        );

        // deref_var gets the value of int_var through ptr_var
        type_inference.add_constraint(deref_type, int_type, 3, ConstraintReason::Assignment);

        // Solve constraints
        let substitution = type_inference.unify().expect("Unification should succeed");

        // Verify types using marker functions
        let a_type = type_inference.get_marker_type('a', &substitution);
        let b_type = type_inference.get_marker_type('b', &substitution);
        let c_type = type_inference.get_marker_type('c', &substitution);

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
            1,
            ConstraintReason::OutputImpliesChar,
        );

        // Then, set another_type to bool type
        type_inference.add_constraint(
            another_type.clone(),
            Type::Bool,
            2,
            ConstraintReason::JumpConditionImpliesBool,
        );

        // Now create a constraint between the two variables
        // This should cause a conflict when unifying
        type_inference.add_constraint(
            var_type.clone(),
            another_type.clone(),
            3,
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
            1,
            ConstraintReason::AddImpliesInt,
        );

        // Then, constrain it to Char from I/O - this should refine the type
        type_inference.add_constraint(
            var_type.clone(),
            Type::Char,
            2,
            ConstraintReason::OutputImpliesChar,
        );

        // Solve constraints
        let substitution = type_inference.unify().expect("Unification should succeed");

        // Get the final type for the variable
        let final_type = type_inference.get_var_type(&var, &substitution);

        // The final type should be Char (the more specific type)
        assert_eq!(
            final_type,
            Some(Type::Char),
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
