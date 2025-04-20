use log::{debug, info};

use crate::disasm::v2::{
    control_flow::{NextKind, PredecessorKind},
    dispatching::EventCollector,
    events::{Event, FunctionCallAnalysisComplete, ModelEventListener, TypeInferenceComplete},
    instructions::{InstructionId, InstructionKind},
    model::{BlockId, FunctionId, ProgramModel},
    ssa_form::{
        PhiFunction, SsaBlock, SsaFunction, SsaInstruction, SsaOperand, SsaOperandKind, SsaResult,
        SsaVar, SsaVarKind,
    },
};

use super::{
    constraints::{Constraint, ConstraintReason},
    solver::{self, TypeInferenceError},
    types::Type,
};

/// Type inference engine for SSA form programs
#[derive(Clone)]
pub struct TypeInferenceAnalyzer {
    /// List of constraints to solve
    constraints: Vec<Constraint>,

    /// Debug markers for variables
    debug_markers: std::collections::HashMap<char, SsaOperand>,
}

impl TypeInferenceAnalyzer {
    /// Create a new type inference engine
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
            debug_markers: std::collections::HashMap::new(),
        }
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
        let result_type = Type::from_ssavar(&phi.result);
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
                                let callee_ret_write_type = Type::from_ssavar(callee_ret_write_var);
                                let caller_ret_read_type = Type::from_ssavar(caller_ret_read_var);

                                // Constraint: CalleeWrite <: CallerRead (propagates type from callee to caller)
                                self.add_constraint(
                                    callee_ret_write_type,
                                    caller_ret_read_type,
                                    result_addr, // Location in the caller (phi function)
                                    phi.result.origin_info.function_id,
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
                    let input_type = Type::from_ssavar(input_var);
                    self.add_constraint(
                        input_type,
                        result_type.clone(),
                        result_addr, // Use address of the result variable definition
                        phi.result.origin_info.function_id,
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
            InstructionKind::Add(src1, src2, dst) => {
                let src1_type = Type::from_ssaoperand(src1);
                let src2_type = Type::from_ssaoperand(src2);
                let dst_type = Type::from_ssaoperand(dst);
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
                let src1_type = Type::from_ssaoperand(src1);
                let src2_type = Type::from_ssaoperand(src2);
                let dst_type = Type::from_ssaoperand(dst);
                let reason = ConstraintReason::MulImpliesInt;

                self.add_constraint(dst_type, Type::Int, instr_id, function_id, reason);
                self.add_constraint(src1_type, Type::Int, instr_id, function_id, reason);
                self.add_constraint(src2_type, Type::Int, instr_id, function_id, reason);
            }

            InstructionKind::Input(dst) => {
                let dst_type = Type::from_ssaoperand(dst);
                self.add_constraint(
                    Type::Char,
                    dst_type,
                    instr_id,
                    function_id,
                    ConstraintReason::InputImpliesChar,
                );
            }

            InstructionKind::Output(src) => {
                let src_type = Type::from_ssaoperand(src);
                self.add_constraint(
                    src_type,
                    Type::Char,
                    instr_id,
                    function_id,
                    ConstraintReason::OutputImpliesChar,
                );
            }

            InstructionKind::LessThan(src1, src2, dst) => {
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

            InstructionKind::Equals(src1, src2, dst) => {
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

            InstructionKind::JumpIfTrue(cond, _) | InstructionKind::JumpIfFalse(cond, _) => {
                let cond_type = Type::from_ssaoperand(cond);
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
                let offset_type = Type::from_ssaoperand(offset);
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
        instruction.reads().iter().for_each(|operand| {
            if let SsaOperandKind::Variable(SsaVar {
                kind:
                    SsaVarKind::Deref {
                        address,
                        address_version,
                    },
                version,
                origin_info,
            }) = operand.kind
            {
                let mem_ssa_var = SsaOperand {
                    kind: SsaOperandKind::Variable(SsaVar {
                        kind: SsaVarKind::Memory(address as i128),
                        version: address_version,
                        origin_info: origin_info,
                    }),
                    origin_info: origin_info,
                };
                self.add_constraint(
                    Type::from_ssaoperand(&mem_ssa_var),
                    Type::Pointer(Box::new(Type::from_ssaoperand(operand))),
                    instruction.id,
                    origin_info.function_id,
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
            .instructions
            .last()
            .map(|instr| instr.id)
            .unwrap_or_else(|| InstructionId::from(block_id.index()));

        match &block.next {
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
                            .end_state
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
                    let fn_type = Type::from_ssaoperand(&call.function_addr);
                    self.add_constraint(
                        fn_type,
                        Type::Pointer(Box::new(Type::Callable)),
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
    ) {
        self.constraints.clear();
        info!("Starting type inference analysis");
        let Some(ssa_result) = model.get_ssa_result() else {
            panic!("SSA program not available");
        };
        self.generate_constraints_for_program(model, ssa_result);

        // Solve the constraints through unification
        let solve_result = solver::unify(model, &self.constraints, &self.debug_markers);

        match solve_result {
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


                    .. // ignore other fields
                } = &error
                {
                    log::error!("Type conflict: {}", error);
                    /*
                    // Format the trace history for the variable
                    let trace_history_var = partial_result.format_traces_for_type(key.clone());
                    let trace_history_other = partial_result.format_traces_for_type(other.clone());
                    log::error!(
                        "Type conflict trace history for var: {}:\n{}\nType conflict trace history for other: {}:\n{}",
                        var,
                        trace_history_var,
                        other:
                        trace_history_other,,
                    );
                    */
                }

                panic!("Type inference failed: {}", error);
            }
        }
    }
}
