use crate::disasm::v2::{
    instructions::OperandKind,
    listeners::type_inference_analyzer::{ConstraintReason, Type, TypeInferenceAnalyzer},
    model::FunctionId,
    ssa_form::SsaVar,
};

#[cfg(test)]
mod tests {
    use crate::disasm::v2::instructions::{InstructionId, Operand};

    use super::*;

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
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        // Create some SSA variables to infer types for
        let function_id = FunctionId::from(0);
        let int_var = SsaVar::new(memory_operand(100), 1, function_id);

        let bool_var = SsaVar::new(memory_operand(101), 1, function_id);

        let char_var = SsaVar::new(memory_operand(102), 1, function_id);

        // Get type variables for these SSA variables
        let int_type = type_inference.type_for_ssavar(&int_var);
        let bool_type = type_inference.type_for_ssavar(&bool_var);
        let char_type = type_inference.type_for_ssavar(&char_var);

        // Add constraints
        type_inference.add_constraint(
            int_type.clone(),
            Type::Int,
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::AddSecondParameterImpliesInt,
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

        // Solve constraints
        let result = type_inference.unify().expect("Unification should succeed");

        // Verify types
        let int_result = result.get_type_for_ssavar(&int_var);
        let bool_result = result.get_type_for_ssavar(&bool_var);
        let char_result = result.get_type_for_ssavar(&char_var);

        assert_eq!(
            *int_result.unwrap(),
            Type::Int,
            "Variable should b.unwrap()e an integer"
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
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        // Create an SSA variable for a function pointer
        let function_id = FunctionId::from(0);
        let func_ptr_var = SsaVar::new(memory_operand(200), 1, function_id);

        // Get type variable
        let func_ptr_type = type_inference.type_for_ssavar(&func_ptr_var);

        // Add constraint for function pointer
        type_inference.add_constraint(
            func_ptr_type.clone(),
            Type::Function {
                args: vec![],
                returns: vec![],
            },
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::IndirectFunctionCall,
        );

        // Solve constraints
        let result = type_inference.unify().expect("Unification should succeed");

        // Verify type
        let result = result.get_type_for_ssavar(&func_ptr_var);

        assert!(
            matches!(*result.unwrap(), Type::Function { .. }),
            "Variable should be a function pointer, got: {:?}",
            result
        );
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_pointer_types() {
        init();
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        // Create variables for testing pointer relationships
        let function_id = FunctionId::from(0);
        let int_var = SsaVar::new(memory_operand(100), 1, function_id);

        let ptr_var = SsaVar::new(memory_operand(101), 1, function_id);

        let deref_var = SsaVar::new(deref_operand(101), 1, function_id);

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
            ptr_type.clone(),
            Type::Pointer(Box::new(int_type.clone())),
            InstructionId::from(2),
            FunctionId::from(0),
            ConstraintReason::Assignment,
        );

        // deref_var gets the value of int_var through ptr_var
        type_inference.add_constraint(
            deref_type.clone(),
            int_type.clone(),
            InstructionId::from(3),
            FunctionId::from(0),
            ConstraintReason::Assignment,
        );

        // Solve constraints
        let result = type_inference.unify().expect("Unification should succeed");

        // Verify types
        let int_result = result.get_type_for_ssavar(&int_var);
        let ptr_result = result.get_type_for_ssavar(&ptr_var);
        let deref_result = result.get_type_for_ssavar(&deref_var);

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
