use log::debug;
use std::{collections::HashMap, fmt};

use crate::disasm::v2::{
    control_flow::NextKind,
    instructions::{Opcode, OperandKind},
    model::BlockId,
    ssa_form::{PhiFunction, SsaBlock, SsaFunction, SsaProgram, SsaVar},
};

use super::{instructions::InstructionId, ssa_form::SsaInstruction};

/// Unique identifier for a type variable
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeVarId(pub usize);

impl fmt::Display for TypeVarId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t{}", self.0)
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
                for (i, ret) in returns.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", ret)?;
                }
                if returns.is_empty() {
                    write!(f, "void")?;
                }
                Ok(())
            }
            Type::String => write!(f, "string"),
            Type::TypeVar(t) => write!(f, "{}", t),
        }
    }
}

/// Reason for a constraint between types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
}

/// Represents a constraint between two types
#[derive(Debug, Clone, PartialEq, Eq)]
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
pub struct TypeInference {
    /// List of constraints to solve
    constraints: Vec<Constraint>,

    /// Map from SSA variables to their types
    type_vars: HashMap<SsaVar, Type>,

    /// Debug markers for variables
    debug_markers: HashMap<char, SsaVar>,

    /// Next available type variable ID
    next_type_var_id: usize,
}

impl TypeInference {
    /// Create a new type inference engine
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            type_vars: HashMap::new(),
            debug_markers: HashMap::new(),
            next_type_var_id: 0,
        }
    }

    /// Generate a fresh type variable
    fn fresh_type_var(&mut self) -> Type {
        let id = self.next_type_var_id;
        self.next_type_var_id += 1;
        Type::TypeVar(TypeVarId(id))
    }

    /// Get the type for an SSA variable
    pub fn type_for_var(&mut self, var: &SsaVar) -> Type {
        if let Some(typ) = self.type_vars.get(var).cloned() {
            return typ;
        }

        let typ = self.fresh_type_var();
        self.type_vars.insert(var.clone(), typ.clone());

        // Special handling for dereferenced variables
        if let OperandKind::Deref(addr) = var.operand.kind {
            // First, collect all candidate variables (to avoid borrowing issues)
            let candidates: Vec<_> = self
                .type_vars
                .keys()
                .filter_map(|other_var| {
                    if let OperandKind::Memory(base_addr) = other_var.operand.kind {
                        if base_addr as usize == addr {
                            Some(other_var.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();

            // Now process the candidates with no borrow conflicts
            if let Some(other_var) = candidates.first() {
                // If we find it, add a deref constraint
                let pointer_type = self.type_for_var(other_var);
                let instr_id = 5555;
                self.add_constraint(
                    pointer_type,
                    Type::Pointer(Box::new(typ.clone())),
                    instr_id,
                    ConstraintReason::Deref,
                );
            }
        }

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
        println!(
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
    fn generate_constraints_for_phi(&mut self, phi: &PhiFunction, block_id: BlockId) {
        let result_type = self.type_for_var(&phi.result);
        let result_instr_id = 5556;

        // Add constraints between each input and the result
        for (_, input_var) in &phi.inputs {
            let input_type = self.type_for_var(input_var);
            self.add_constraint(
                result_type.clone(),
                input_type,
                result_instr_id,
                ConstraintReason::PhiAssignment,
            );
        }
    }

    /// Generate constraints for an instruction
    fn generate_constraints_for_instruction(
        &mut self,
        instruction: &SsaInstruction,
        block_id: BlockId,
    ) {
        let instr_id = instruction.id.index();

        // Infer types based on the instruction
        // We'll add type constraints based on the opcode
        if instruction.operands.len() >= 3
            && (instruction.opcode == Opcode::Add || instruction.opcode == Opcode::Mul)
        {
            // Addition or multiplication: dst = src1 + src2
            let src1 = &instruction.operands[0];
            let src2 = &instruction.operands[1];
            let dst = &instruction.operands[2];

            let src1_type = self.type_for_var(src1);
            let src2_type = self.type_for_var(src2);
            let dst_type = self.type_for_var(dst);

            self.add_constraint(
                dst_type,
                Type::Int,
                instr_id,
                ConstraintReason::AddImpliesInt,
            );
            self.add_constraint(
                src1_type,
                Type::Int,
                instr_id,
                ConstraintReason::AddImpliesInt,
            );
            self.add_constraint(
                src2_type,
                Type::Int,
                instr_id,
                ConstraintReason::AddImpliesInt,
            );
        } else if instruction.operands.len() >= 1 && instruction.opcode == Opcode::Input {
            // Input: dst = input()
            let dst = &instruction.operands[0];
            let dst_type = self.type_for_var(dst);

            self.add_constraint(
                dst_type,
                Type::Char,
                instr_id,
                ConstraintReason::InputImpliesChar,
            );
        } else if instruction.operands.len() >= 1 && instruction.opcode == Opcode::Output {
            // Output: output(src)
            let src = &instruction.operands[0];
            let src_type = self.type_for_var(src);

            self.add_constraint(
                src_type,
                Type::Char,
                instr_id,
                ConstraintReason::OutputImpliesChar,
            );
        } else if instruction.operands.len() >= 3 && instruction.opcode == Opcode::LessThan {
            // Less than: dst = src1 < src2
            let src1 = &instruction.operands[0];
            let src2 = &instruction.operands[1];
            let dst = &instruction.operands[2];

            let src1_type = self.type_for_var(src1);
            let src2_type = self.type_for_var(src2);
            let dst_type = self.type_for_var(dst);

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
        } else if instruction.operands.len() >= 3 && instruction.opcode == Opcode::Equals {
            // Equals: dst = src1 == src2
            let src1 = &instruction.operands[0];
            let src2 = &instruction.operands[1];
            let dst = &instruction.operands[2];

            let src1_type = self.type_for_var(src1);
            let src2_type = self.type_for_var(src2);
            let dst_type = self.type_for_var(dst);

            self.add_constraint(
                dst_type,
                Type::Bool,
                instr_id,
                ConstraintReason::CompareDstImpliesBool,
            );
            self.add_constraint(
                src1_type,
                src2_type,
                instr_id,
                ConstraintReason::CompareSrcSameType,
            );
        } else if instruction.operands.len() >= 2
            && (instruction.opcode == Opcode::JumpIfTrue
                || instruction.opcode == Opcode::JumpIfFalse)
        {
            // Jump conditions: JumpIf(cond, ...)
            let cond = &instruction.operands[0];
            let cond_type = self.type_for_var(cond);

            self.add_constraint(
                cond_type,
                Type::Bool,
                instr_id,
                ConstraintReason::JumpConditionImpliesBool,
            );
        }

        // Check if any operands come from function returns and add appropriate constraints
        /*
        for def in &instr.operands_from_function_returns {  // check source in operand.
            // We need to connect the return value type with its use
            for operand in &instruction.operands {
                if operand.operand == def.location {
                    // This operand comes from a function return
                    // Add appropriate constraints based on the function's return type
                    // (This is simplified - in a real implementation we'd look at the function's signature)
                    let operand_type = self.type_for_var(operand);

                    // For now, we don't have specific function return type info
                    // We could add more sophisticated handling here in the future

                    // Mark that this is a function return binding
                    debug!("Operand {:?} comes from function return {:?}", operand, def);
                }
            }
        }
        */
    }

    /// Generate constraints for control flow transitions
    fn generate_constraints_for_next(&mut self, next: &NextKind<SsaVar>, block_id: BlockId) {
        let block_id_value = block_id.index();

        match next {
            NextKind::Condition(cond) => {
                // The condition operand must be a boolean
                let cond_type = self.type_for_var(&cond.condition_operand);
                self.add_constraint(
                    cond_type,
                    Type::Bool,
                    block_id_value,
                    ConstraintReason::JumpConditionImpliesBool,
                );
            }

            NextKind::FunctionCall(call) => {
                // For function calls, add constraints for function pointer type
                if !matches!(call.function_addr.operand.kind, OperandKind::Immediate(_)) {
                    // Only add function pointer constraint for indirect calls
                    let fn_type = self.type_for_var(&call.function_addr);

                    // Create a function pointer type
                    // Note: In a real implementation, we would try to determine the actual argument
                    // and return types based on usage
                    self.add_constraint(
                        fn_type,
                        Type::FunctionPointer {
                            args: vec![],    // Placeholder - would be inferred from call site
                            returns: vec![], // Placeholder - would be inferred from usage
                        },
                        block_id_value,
                        ConstraintReason::IndirectFunctionCall,
                    );
                }

                /*
                // Process call site state for function parameters and returns
                for (op_kind, var) in call.call_site_state {
                    // These are variables that are preserved across the call
                    // We could add constraints here to model parameter passing
                    let var_type = self.type_for_var(&var);

                    // If we had information about the callee, we could add constraints
                    // between caller and callee variables
                }
                */
            }

            // Other control flow types don't add constraints
            _ => {}
        }
    }

    /// Generate constraints for an entire block
    fn generate_constraints_for_block(&mut self, block: &SsaBlock) {
        let block_id = block.original_id;

        // Process phi functions
        for phi in &block.phi_functions {
            self.generate_constraints_for_phi(phi, block_id);
        }

        // Process instructions
        for instr in &block.instructions {
            self.generate_constraints_for_instruction(instr, block_id);
        }

        // Process control flow
        self.generate_constraints_for_next(&block.next, block_id);
    }

    /// Generate constraints for a function
    fn generate_constraints_for_function(&mut self, function: &SsaFunction) {
        for (_, block) in &function.blocks {
            self.generate_constraints_for_block(block);
        }
    }

    /// Generate constraints for the entire program
    pub fn generate_constraints_for_program(&mut self, program: &SsaProgram) {
        // Process each function in the program
        for (_, function) in &program.functions {
            self.generate_constraints_for_function(function);
        }
    }

    /// Substitute type variables according to the substitution map
    pub fn substitute(t: Type, subst: &HashMap<TypeVarId, Type>) -> Type {
        println!("Subsititute: {}", t);
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
                        // Add a constraint between the existing type and the new right side
                        worklist.push(Constraint {
                            left: existing_type.clone(),
                            right: right.clone(),
                            addr: constraint.addr,
                            reason: constraint.reason,
                        });
                    } else {
                        // No existing substitution, just add it
                        debug!("unify: {} => {}", id, right);
                        subst.insert(*id, right);
                    }
                }

                (_, Type::TypeVar(id)) => {
                    // If the type variable already has a substitution, we need to ensure it's compatible
                    if let Some(existing_type) = subst.get(id) {
                        // Add a constraint between the existing type and the new left side
                        worklist.push(Constraint {
                            left: existing_type.clone(),
                            right: left.clone(),
                            addr: constraint.addr,
                            reason: constraint.reason,
                        });
                    } else {
                        // No existing substitution, just add it
                        debug!("unify: {} => {}", id, left);
                        subst.insert(*id, left);
                    }
                }

                (Type::Int, Type::Int)
                | (Type::Bool, Type::Bool)
                | (Type::Char, Type::Char)
                | (Type::String, Type::String) => {
                    // Same types, no constraint needed
                }

                (Type::Pointer(t1), Type::Pointer(t2)) => {
                    // Add constraint between the pointed-to types
                    worklist.push(Constraint {
                        left: (**t1).clone(),
                        right: (**t2).clone(),
                        addr: constraint.addr,
                        reason: constraint.reason,
                    });
                }

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
                    // Check if arities match
                    if args1.len() != args2.len() || returns1.len() != returns2.len() {
                        return Err(format!(
                            "Function pointer arity mismatch: ({:?} -> {:?}) vs ({:?} -> {:?}) at instruction {}",
                            args1, returns1, args2, returns2, constraint.addr
                        ));
                    }

                    // Add constraints for arguments
                    for (arg1, arg2) in args1.iter().zip(args2.iter()) {
                        worklist.push(Constraint {
                            left: arg1.clone(),
                            right: arg2.clone(),
                            addr: constraint.addr,
                            reason: constraint.reason,
                        });
                    }

                    // Add constraints for returns
                    for (ret1, ret2) in returns1.iter().zip(returns2.iter()) {
                        worklist.push(Constraint {
                            left: ret1.clone(),
                            right: ret2.clone(),
                            addr: constraint.addr,
                            reason: constraint.reason,
                        });
                    }
                }

                // Type conflict cases - any combination of concrete types that are different
                _ if Self::are_incompatible_types(&left, &right) => {
                    return Err(format!(
                        "Type conflict: cannot unify {} and {} at instruction {}",
                        left, right, constraint.addr
                    ));
                }

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

        // Compute final substitution by applying substitutions repeatedly
        let mut final_subst = HashMap::new();
        for (k, v) in subst.iter() {
            final_subst.insert(*k, Self::substitute(v.clone(), &subst));
        }

        // Check for cycles in the substitution, which would indicate an error
        for (id, typ) in &final_subst {
            if Self::contains_type_var(typ, *id) {
                return Err(format!("Recursive type definition for {}", id));
            }
        }

        Ok(final_subst)
    }

    /// Determine if two types are incompatible (cannot be unified)
    fn are_incompatible_types(t1: &Type, t2: &Type) -> bool {
        match (t1, t2) {
            // Same basic types are compatible
            (Type::Int, Type::Int)
            | (Type::Bool, Type::Bool)
            | (Type::Char, Type::Char)
            | (Type::String, Type::String) => false,

            // TypeVars are handled separately in unification
            (Type::TypeVar(_), _) | (_, Type::TypeVar(_)) => false,

            // Pointers are compatible with other pointers (contents checked separately)
            (Type::Pointer(_), Type::Pointer(_)) => false,

            // Function pointers are compatible with other function pointers (signatures checked separately)
            (Type::FunctionPointer { .. }, Type::FunctionPointer { .. }) => false,

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
    pub fn mark_var(&mut self, var: SsaVar, marker: char) {
        self.debug_markers.insert(marker, var);
    }

    /// Get the variable associated with a debug marker
    pub fn get_marked_var(&self, marker: char) -> Option<&SsaVar> {
        self.debug_markers.get(&marker)
    }

    /// Get the final type for a variable after unification
    pub fn get_var_type(&self, var: &SsaVar, subst: &HashMap<TypeVarId, Type>) -> Option<Type> {
        self.type_vars.get(var).map(|t| match t {
            Type::TypeVar(id) => subst.get(id).cloned().unwrap_or_else(|| t.clone()),
            _ => t.clone(),
        })
    }

    /// Get the final type for a debug marker after unification
    pub fn get_marker_type(&self, marker: char, subst: &HashMap<TypeVarId, Type>) -> Option<Type> {
        self.get_marked_var(marker)
            .and_then(|var| self.get_var_type(var, subst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::parser;
    use crate::disasm::v2::instructions::{InstructionId, Operand};
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
        type_inference: TypeInference,
        ssa_program: Option<SsaProgram>,
        markers: HashMap<char, OperandKind>,
        manual_markers: HashMap<char, SsaVar>, // Tracks manually marked variables
    }

    impl TestContext {
        /// Create a new test context with the given assembly code
        fn new(assembly: &str) -> Self {
            // Parse the assembly code
            let binary = parser::compile(assembly);

            // Create model and event system
            let mut model = ProgramModel::new();
            let mut publisher = EventPublisher::<Event, ProgramModel>::new();

            // Setup the SSA converter and make it accessible to the model
            let ssa_converter = SsaConverter::new();
            model.set_ssa_converter(ssa_converter.clone());

            // Create all listeners
            let image_scanner = ImageScanner::new();
            let control_flow_builder = ControlFlowGraphBuilder::new();
            let data_flow_analyzer = DataFlowAnalyzer::new();

            // Register listeners
            publisher.add_listener(Box::new(image_scanner));
            publisher.add_listener(Box::new(control_flow_builder));
            publisher.add_listener(Box::new(data_flow_analyzer));
            publisher.add_listener(Box::new(ssa_converter.clone()));

            // Run the pipeline
            model.load_image(&binary, &mut publisher);
            publisher.process_events(&mut model);

            // Get the SSA program
            let ssa_program = model
                .ssa_converter
                .as_ref()
                .and_then(|converter| converter.get_ssa_program().cloned());

            // Create type inference engine
            let mut type_inference = TypeInference::new();

            // Process debug markers from the assembly
            let markers = Self::extract_markers(&binary);
            let mut manual_markers = HashMap::new();

            // Mark variables with debug characters
            if let Some(ref ssa_program) = ssa_program {
                // Process each function in the SSA program
                for (_, function) in &ssa_program.functions {
                    // Generate constraints from SSA form
                    type_inference.generate_constraints_for_function(function);

                    // Find SSA variables for marked operands
                    /*
                    for (marker, operand) in &markers {
                        // Search for the SSA variable with this operand kind
                        let mut matching_vars = Vec::new();
                        for (var, _) in &function.var_defs {
                            if &var.operand == operand
                                matching_vars.push(var.clone());
                            }
                        }

                        // If we found matching variables, mark the one with the highest version
                        // (which should be the last definition)
                        if !matching_vars.is_empty() {
                            matching_vars.sort_by_key(|v| v.version);
                            let last_var = matching_vars.last().unwrap().clone();
                            type_inference.mark_var(last_var.clone(), *marker);
                            manual_markers.insert(*marker, last_var);
                        }
                    }
                    */
                }
            }

            Self {
                type_inference,
                ssa_program,
                markers,
                manual_markers,
            }
        }

        /// Extract markers from the binary
        fn extract_markers(binary: &[i128]) -> HashMap<char, OperandKind> {
            let mut markers = HashMap::new();

            // Process each instruction in the binary
            let mut i = 0;
            while i < binary.len() {
                // Find debug markers in the binary
                if i + 2 < binary.len() {
                    let instruction = binary[i];

                    // Look for debug markers in the instruction's debug info
                    // In our assembly format, debug markers might be stored in a special format
                    // For simplicity, we'll look for special negative values as indicators
                    if instruction < 0 {
                        // Try to extract marker character from negative value
                        let marker_value = (-instruction) as u8;
                        if marker_value >= 32 && marker_value <= 126 {
                            // Printable ASCII
                            let marker = marker_value as char;

                            // Next value should be an address/operand
                            let operand_value = binary[i + 1];

                            // Create an appropriate OperandKind
                            let operand_kind = if operand_value < 0 {
                                // Negative value might indicate a special operand type
                                OperandKind::RelativeMemory(operand_value.abs())
                            } else {
                                // Positive value is likely a memory address
                                OperandKind::Memory(operand_value)
                            };

                            markers.insert(marker, operand_kind);
                        }
                    }
                }

                i += 1;
            }

            markers
        }

        /// Run unification and return the result
        fn unify(&mut self) -> Result<HashMap<TypeVarId, Type>, String> {
            self.type_inference.unify()
        }

        /// Assert that a marker has the expected type
        fn assert_marker_type(&mut self, marker: char, expected_type: Type) {
            if let Some(subst) = self.unify().ok() {
                let marker_type = self.type_inference.get_marker_type(marker, &subst);

                assert!(marker_type.is_some(), "Marker {} not found", marker);
                let actual_type = marker_type.unwrap();

                assert_eq!(
                    actual_type, expected_type,
                    "Marker {} has incorrect type: expected {:?}, actual {:?}",
                    marker, expected_type, actual_type
                );
            } else {
                panic!("Unification failed");
            }
        }

        /// Create a manual test context without using assembly
        fn new_manual() -> Self {
            let mut type_inference = TypeInference::new();
            let manual_markers = HashMap::new();

            Self {
                type_inference,
                ssa_program: None,
                markers: HashMap::new(),
                manual_markers,
            }
        }

        /// Manually mark a variable with a character
        fn mark_var(&mut self, var: SsaVar, marker: char) {
            self.type_inference.mark_var(var.clone(), marker);
            self.manual_markers.insert(marker, var);
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
        let mut type_inference = TypeInference::new();

        // Create some SSA variables to infer types for
        let int_var = SsaVar::new(memory_operand(100), 1);

        let bool_var = SsaVar::new(memory_operand(101), 1);

        let char_var = SsaVar::new(memory_operand(102), 1);

        // Mark variables for easier identification in tests
        type_inference.mark_var(int_var.clone(), 'a');
        type_inference.mark_var(bool_var.clone(), 'b');
        type_inference.mark_var(char_var.clone(), 'c');

        // Get type variables for these SSA variables
        let int_type = type_inference.type_for_var(&int_var);
        let bool_type = type_inference.type_for_var(&bool_var);
        let char_type = type_inference.type_for_var(&char_var);

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
        let mut type_inference = TypeInference::new();

        // Create an SSA variable for a function pointer
        let func_ptr_var = SsaVar::new(memory_operand(200), 1);

        // Mark variable
        type_inference.mark_var(func_ptr_var.clone(), 'a');

        // Get type variable
        let func_ptr_type = type_inference.type_for_var(&func_ptr_var);

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
        let mut type_inference = TypeInference::new();

        // Create variables for testing pointer relationships
        let int_var = SsaVar::new(memory_operand(100), 1);

        // For a pointer variable, we use Memory kind in SSA
        let ptr_var = SsaVar::new(memory_operand(101), 1);

        // For dereferenced variables, we use the Deref kind
        let deref_var = SsaVar::new(deref_operand(101), 1);

        // Mark variables
        type_inference.mark_var(int_var.clone(), 'a');
        type_inference.mark_var(ptr_var.clone(), 'b');
        type_inference.mark_var(deref_var.clone(), 'c');

        // Get type variables
        let int_type = type_inference.type_for_var(&int_var);
        let ptr_type = type_inference.type_for_var(&ptr_var);
        let deref_type = type_inference.type_for_var(&deref_var);

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
        let mut type_inference = TypeInference::new();

        // Create a variable
        let var = SsaVar::new(memory_operand(100), 1);

        // Get type variable
        let var_type = type_inference.type_for_var(&var);

        // Create another variable that will be unified with var_type
        let another_var = SsaVar::new(memory_operand(101), 1);
        let another_type = type_inference.type_for_var(&another_var);

        // First, directly set var_type to int type
        type_inference.add_constraint(
            var_type.clone(),
            Type::Int,
            1,
            ConstraintReason::AddImpliesInt,
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
}
