use log::{debug, info};

use crate::disasm::v2::{
    control_flow::{NextKind, PredecessorKind},
    dispatching::EventCollector,
    events::{Event, FunctionCallAnalysisComplete, ModelEventListener, TypeInferenceComplete},
    model::{BlockId, FunctionId, ProgramModel},
    native::{NativeInstructionId, NativeInstructionKind},
    ssa_form::{
        PhiFunction, SsaBlock, SsaFunction, SsaInstruction, SsaOperand, SsaOperandKind, SsaResult,
        SsaVarKind,
    },
    type_inference::visuals::TraceColors,
};

use super::{
    constraints::{Constraint, ConstraintReason},
    solver,
    types::{Type, VariableKind},
};

/// Type inference engine for SSA form programs
#[derive(Clone)]
pub struct TypeInferenceAnalyzer {
    /// List of constraints to solve
    constraints: Vec<Constraint>,
    add_instructions: Vec<AddInstruction>,

    /// Debug markers for variables
    debug_markers: std::collections::HashMap<char, SsaOperand>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AddInstruction {
    /// The instruction ID
    pub instruction_id: NativeInstructionId,
    pub function_id: FunctionId,
    pub op1: VariableKind,
    pub op2: VariableKind,
    pub result: VariableKind,
}

impl TypeInferenceAnalyzer {
    /// Create a new type inference engine
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            add_instructions: Vec::new(),
            debug_markers: std::collections::HashMap::new(),
        }
    }

    /// Add a constraint between two types
    pub fn add_constraint(
        &mut self,
        left: Type,
        right: Type,
        addr: NativeInstructionId,
        function_id: FunctionId,
        reason: ConstraintReason,
    ) {
        let c = Constraint {
            left,
            right,
            addr,
            function_id,
            reason,
        };
        debug!("Adding constraint: {}", TraceColors::format_constraint(&c));
        self.constraints.push(c);
    }

    /// Generate constraints for a phi function
    fn generate_constraints_for_phi(
        &mut self,
        model: &ProgramModel,
        phi: &PhiFunction,
        block_id: BlockId,
    ) {
        let result_type = Type::from_ssavar(&phi.native_result);
        let result_addr = NativeInstructionId::from(block_id.index());

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
                        for (caller_ret_read_var, callee_ret_write_var) in &csi.return_map {
                            // We are looking for the specific entry where the caller's read variable
                            // matches the input_var (which should be phi.result for this predecessor kind).
                            if caller_ret_read_var == input_var {
                                let callee_ret_write_type = Type::from_ssavar(callee_ret_write_var);
                                let caller_ret_read_type = Type::from_ssavar(caller_ret_read_var);

                                // Constraint: CalleeWrite <: CallerRead (propagates type from callee to caller)
                                self.add_constraint(
                                    callee_ret_write_type,
                                    caller_ret_read_type,
                                    result_addr, // Location in the caller (phi function)
                                    phi.native_result.origin_info.function_id,
                                    ConstraintReason::FunctionReturnBinding,
                                );
                            }
                        }
                    } else {
                        log::warn!(
                            "Call site info not found for block {} during phi constraint generation for {}.",
                            call_info.calling_block, phi.native_result
                        );
                        // Fallback if call site info is missing? Add basic PhiAssignment?
                        // For now, we just skip adding a constraint for this specific return value.
                    }
                }
                _ => {
                    // Standard predecessor: Input <: Result
                    let input_type = Type::from_ssavar(input_var);
                    self.add_constraint(
                        input_type,
                        result_type.clone(),
                        result_addr, // Use address of the result variable definition
                        phi.native_result.origin_info.function_id,
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
            NativeInstructionKind::Assign(target, source) => {
                let dst_type = Type::from_ssaoperand(target);
                let src_type = Type::from_ssaoperand(source);
                if source.to_operand().kind.get_immediate().is_some() {
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
            NativeInstructionKind::Add(op1, op2, result) => {
                let op1 = VariableKind::from_ssaoperand(op1);
                let op2 = VariableKind::from_ssaoperand(op2);
                let result = VariableKind::from_ssaoperand(result);
                self.add_instructions.push(AddInstruction {
                    instruction_id: instr_id,
                    function_id,
                    op1,
                    op2,
                    result,
                });
            }
            NativeInstructionKind::Mul(src1, src2, dst) => {
                // It's a real addition/multiplication
                let src1_type = Type::from_ssaoperand(src1);
                let src2_type = Type::from_ssaoperand(src2);
                let dst_type = Type::from_ssaoperand(dst);
                let reason = ConstraintReason::MulImpliesInt;

                self.add_constraint(Type::Int, dst_type, instr_id, function_id, reason);
                self.add_constraint(Type::Int, src1_type, instr_id, function_id, reason);
                self.add_constraint(Type::Int, src2_type, instr_id, function_id, reason);
            }

            NativeInstructionKind::Input(dst) => {
                let dst_type = Type::from_ssaoperand(dst);
                self.add_constraint(
                    Type::Char,
                    dst_type,
                    instr_id,
                    function_id,
                    ConstraintReason::InputImpliesChar,
                );
            }

            NativeInstructionKind::Output(src) => {
                let src_type = Type::from_ssaoperand(src);
                self.add_constraint(
                    src_type,
                    Type::Char,
                    instr_id,
                    function_id,
                    ConstraintReason::OutputImpliesChar,
                );
            }

            NativeInstructionKind::LessThan(src1, src2, dst) => {
                let src1_type = Type::from_ssaoperand(src1);
                let src2_type = Type::from_ssaoperand(src2);
                let dst_type = Type::from_ssaoperand(dst);

                self.add_constraint(
                    Type::Bool,
                    dst_type,
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

            NativeInstructionKind::Equals(src1, src2, dst) => {
                let src1_type = Type::from_ssaoperand(src1);
                let src2_type = Type::from_ssaoperand(src2);
                let dst_type = Type::from_ssaoperand(dst);

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

            NativeInstructionKind::JumpIfTrue(cond, _)
            | NativeInstructionKind::JumpIfFalse(cond, _) => {
                let cond_type = Type::from_ssaoperand(cond);
                self.add_constraint(
                    cond_type,
                    Type::Truthy,
                    instr_id,
                    function_id,
                    ConstraintReason::JumpConditionImpliesTruthy,
                );
            }

            NativeInstructionKind::AdjustRelativeBase(offset) => {
                // The offset operand must be an integer
                let offset_type = Type::from_ssaoperand(offset);
                self.add_constraint(
                    offset_type,
                    Type::Int,
                    instr_id,
                    function_id,
                    ConstraintReason::ImmediateIsSubtypeOfInt, // Re-use reason? Or new one?
                );
            }
            NativeInstructionKind::Halt => { /* No operands */ }
            NativeInstructionKind::Goto(_) => { /* No operands with types */ }
            NativeInstructionKind::Data(_) => { /* Data doesn't participate in type inference this way */
            }
        }
        instruction.reads().iter().for_each(|operand| {
            if let SsaOperandKind::Deref(pointer) = operand.kind {
                self.add_constraint(
                    Type::from_ssavar(&pointer),
                    Type::pointer(Type::from_ssaoperand(operand)),
                    instruction.id,
                    pointer.origin_info.function_id,
                    ConstraintReason::Deref,
                );
                self.add_constraint(
                    Type::pointer(Type::from_ssaoperand(operand)),
                    Type::from_ssavar(&pointer),
                    instruction.id,
                    pointer.origin_info.function_id,
                    ConstraintReason::Deref,
                );
            }
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
            .native_instructions
            .last()
            .map(|instr| instr.id)
            .unwrap_or_else(|| NativeInstructionId::from(block_id.index()));

        match &block.native_next {
            NextKind::Condition(cond) => {
                // The condition operand must be a boolean
                let cond_type = Type::from_ssaoperand(&cond.condition_operand);
                self.add_constraint(
                    cond_type,
                    Type::Truthy,
                    location_addr, // Location of the conditional jump
                    function_id,
                    ConstraintReason::JumpConditionImpliesTruthy,
                );
            }

            NextKind::FunctionCall(call) => {
                if let Some(func_addr) = call.function_addr.to_operand().kind.get_immediate() {
                    // --- Direct Call ---
                    let fca = model
                        .get_function_call_analysis()
                        .expect("FunctionCallAnalysis missing");
                    let callee_id = FunctionId::from(func_addr as usize);

                    let callee_info = &fca.callee_info[&callee_id];

                    // Link caller arguments to callee parameters
                    for (caller_offset, callee_param_var) in &callee_info.parameter_entry_vars {
                        if let Some(caller_arg_var) = block
                            .native_end_state
                            .get(&SsaVarKind::RelativeMemory(*caller_offset))
                        {
                            let caller_arg_type = Type::from_ssavar(caller_arg_var);
                            let callee_param_type = Type::from_ssavar(callee_param_var);
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
                    // --- Indirect Call ---
                    let fn_type = Type::from_ssaoperand(&call.function_addr);
                    self.add_constraint(
                        fn_type,
                        Type::callable(),
                        location_addr,
                        function_id,
                        ConstraintReason::IndirectFunctionCall {
                            calling_block: call.calling_block,
                        },
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
        for instr in &block.native_instructions {
            self.generate_constraints_for_instruction(instr, function_id);
        }

        // Process control flow transition (next)
        self.generate_constraints_for_next(model, block, function_id, block_id);
    }

    /// Generate constraints for a function
    fn generate_constraints_for_function(&mut self, model: &ProgramModel, function: &SsaFunction) {
        for block in function.blocks.values() {
            self.generate_constraints_for_block(model, function.original_id, block);
        }
    }

    /// Generate constraints for the entire program
    pub fn generate_constraints_for_program(&mut self, model: &ProgramModel, result: &SsaResult) {
        // Process each function in the program
        for function in result.functions.values() {
            self.generate_constraints_for_function(model, function);
        }
    }

    /// Mark a variable with a debug character for testing
    #[cfg(test)]
    pub fn mark_var(&mut self, var: SsaOperand, marker: char) {
        self.debug_markers.insert(marker, var);
    }

    /// Get a slice of the generated constraints.
    #[cfg(test)]
    pub fn get_constraints(&self) -> &[Constraint] {
        &self.constraints
    }

    #[cfg(test)]
    pub fn get_add_instructions(&self) -> &[AddInstruction] {
        &self.add_instructions
    }

    /// Get the debug markers map (test only).
    #[cfg(test)]
    pub fn get_debug_markers(&self) -> &std::collections::HashMap<char, SsaOperand> {
        &self.debug_markers
    }
}

impl ModelEventListener for TypeInferenceAnalyzer {
    fn on_function_call_analysis_complete(
        &mut self,
        model: &mut ProgramModel,
        _: FunctionCallAnalysisComplete,
        collector: &mut EventCollector<Event>,
    ) -> Result<(), crate::disasm::Error> {
        self.constraints.clear();
        info!("Starting type inference analysis");
        let Some(ssa_result) = model.get_ssa_result() else {
            panic!("SSA program not available");
        };
        self.generate_constraints_for_program(model, ssa_result);

        // Solve the constraints through unification
        let solve_result = solver::unify(
            model,
            &self.constraints,
            &self.add_instructions,
            &self.debug_markers,
        )?;
        model.set_type_inference_result(solve_result);
        // Signal that type inference is complete
        collector.publish(TypeInferenceComplete { completed: true });
        Ok(())
    }
}
