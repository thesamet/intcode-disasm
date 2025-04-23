use crate::disasm::v2::{
    instructions::OperandKind,
    model::FunctionId,
    ssa_form::SsaVar,
    type_inference::{
        analyzer::TypeInferenceAnalyzer, constraints::ConstraintReason, solver, types::Type,
    },
};

use crate::disasm::v2::model::ProgramModel;

#[cfg(test)]
mod tests {
    use crate::disasm::v2::{
        instructions::{InstructionId, Operand},
        model::BlockId,
        ssa_form::{SsaOperand, SsaOperandKind},
    };

    use super::*;

    fn init() {
        use std::io::Write;
        let _ = env_logger::builder()
            .format(|buf, record| writeln!(buf, "{}: {}", record.level(), record.args()))
            .is_test(true)
            .try_init();
    }

    fn memory_operand(offset: usize) -> Operand {
        Operand {
            kind: OperandKind::Memory(offset),
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

    fn _relative_memory_operand(offset: i128) -> Operand {
        Operand {
            kind: OperandKind::RelativeMemory(offset),
            offset: 0,
            debug_marker: None,
        }
    }

    fn _immediate_operand(value: i128) -> Operand {
        Operand {
            kind: OperandKind::Immediate(value),
            offset: 0,
            debug_marker: None,
        }
    }

    /// Simplified test for type inference using direct API calls
    #[test]
    fn test_type_inference_basics() {
        init();
        let model = ProgramModel::new();
        let mut type_inference = TypeInferenceAnalyzer::new();

        // Create some SSA variables to infer types for
        let function_id = FunctionId::from(0);
        let int_var = SsaOperand::from_operand(&memory_operand(100), 1, function_id);
        let bool_var = SsaOperand::from_operand(&memory_operand(101), 1, function_id);
        let char_var = SsaOperand::from_operand(&memory_operand(102), 1, function_id);

        // Mark variables for testing
        type_inference.mark_var(int_var, 'a');
        type_inference.mark_var(bool_var, 'b');
        type_inference.mark_var(char_var, 'c');

        // Get type variables for these SSA variables
        let int_type = Type::from_ssaoperand(&int_var);
        let bool_type = Type::from_ssaoperand(&bool_var);
        let char_type = Type::from_ssaoperand(&char_var);

        // Add constraints
        type_inference.add_constraint(
            int_type.clone(),
            Type::Int,
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::AddRules,
        );
        type_inference.add_constraint(
            bool_type.clone(),
            Type::Bool,
            InstructionId::from(2),
            FunctionId::from(0),
            ConstraintReason::CompareDstImpliesBool,
        );
        type_inference.add_constraint(
            char_type.clone(),
            Type::Char,
            InstructionId::from(3),
            FunctionId::from(0),
            ConstraintReason::OutputImpliesChar,
        );

        // Solve constraints using solver::unify
        let result = solver::unify(
            &model,
            type_inference.get_constraints(),
            type_inference.get_add_instructions(),
            type_inference.get_debug_markers(),
        )
        .expect("Unification should succeed");

        // Verify types using the result
        let int_result = result.get_type_for_ssavar(int_var.as_variable().unwrap());
        let bool_result = result.get_type_for_ssavar(bool_var.as_variable().unwrap());
        let char_result = result.get_type_for_ssavar(char_var.as_variable().unwrap());

        assert_eq!(
            *int_result.unwrap(),
            Type::Int,
            "Variable should be an integer"
        );
        assert_eq!(
            *bool_result.unwrap(),
            Type::Bool,
            "Variable should be a boolean"
        );
        assert_eq!(
            *char_result.unwrap(),
            Type::Char,
            "Variable should be a character"
        );
    }

    #[test]
    fn test_function_pointer_types() {
        init();
        let model = ProgramModel::new();
        let mut type_inference = TypeInferenceAnalyzer::new();

        // Create an SSA variable for a function pointer
        let function_id = FunctionId::from(0);
        let func_ptr_var = SsaVar::from_operand(&memory_operand(200), 1, function_id).unwrap();

        // Get type variable
        let func_ptr_type = Type::from_ssavar(&func_ptr_var);

        // Mark variable for testing
        type_inference.mark_var(
            SsaOperand {
                kind: SsaOperandKind::Variable(func_ptr_var),
                origin_info: func_ptr_var.origin_info,
            },
            'f',
        );

        // Add constraint for function pointer
        type_inference.add_constraint(
            func_ptr_type.clone(),
            Type::Function {
                args: Box::new(Type::Tuple(vec![])),
                returns: Box::new(Type::Tuple(vec![])),
            },
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::IndirectFunctionCall {
                calling_block: BlockId::from(0),
            },
        );

        // Solve constraints using solver::unify
        let result = solver::unify(
            &model,
            type_inference.get_constraints(),
            type_inference.get_add_instructions(),
            type_inference.get_debug_markers(),
        )
        .expect("Unification should succeed");

        // Verify type
        let final_type = result.get_type_for_ssavar(&func_ptr_var);

        assert!(
            matches!(*final_type.unwrap(), Type::Function { .. }),
            "Variable should be a function pointer, got: {:?}",
            final_type
        );
    }

    #[test]
    fn test_pointer_types() {
        init();
        let mut type_inference = TypeInferenceAnalyzer::new();

        // Create variables for testing pointer relationships
        let function_id = FunctionId::from(0);
        let int_var = SsaOperand::from_operand(&memory_operand(100), 1, function_id);
        let ptr_var = SsaOperand::from_operand(&memory_operand(101), 1, function_id);
        let deref_var = SsaOperand::from_operand(&deref_operand(101), 1, function_id);

        // Mark variables for testing
        type_inference.mark_var(int_var, 'i');
        type_inference.mark_var(ptr_var, 'p');
        type_inference.mark_var(deref_var, 'd');

        // Get type variables
        let int_type = Type::from_ssaoperand(&int_var);
        let ptr_type = Type::from_ssaoperand(&ptr_var);
        let deref_type = Type::from_ssaoperand(&deref_var);

        // Add constraints
        type_inference.add_constraint(
            int_type.clone(),
            Type::Int,
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::AddRules,
        );
        type_inference.add_constraint(
            ptr_type.clone(),
            Type::Pointer(Box::new(int_type.clone())),
            InstructionId::from(2),
            FunctionId::from(0),
            ConstraintReason::Assignment,
        );
        type_inference.add_constraint(
            deref_type.clone(),
            int_type.clone(),
            InstructionId::from(3),
            FunctionId::from(0),
            ConstraintReason::Assignment,
        );

        // Solve constraints using solver::unify
        let model = ProgramModel::new();
        let result = solver::unify(
            &model,
            type_inference.get_constraints(),
            type_inference.get_add_instructions(),
            type_inference.get_debug_markers(),
        )
        .expect("Unification should succeed");

        // Verify types
        let int_result = result.get_type_for_ssavar(int_var.as_variable().unwrap());
        let ptr_result = result.get_type_for_ssavar(ptr_var.as_variable().unwrap());
        let deref_result = result.get_type_for_ssavar(deref_var.as_variable().unwrap());

        assert_eq!(
            *int_result.unwrap(),
            Type::Int,
            "int_var should be an integer"
        );
        assert_eq!(
            *ptr_result.unwrap(),
            Type::Pointer(Box::new(Type::Int)),
            "ptr_var should be a pointer to an integer"
        );
        assert_eq!(
            *deref_result.unwrap(),
            Type::Int,
            "deref_var should be an integer"
        );
    }
}
