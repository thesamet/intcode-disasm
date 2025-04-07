use crate::disasm::v2::{
    instructions::OperandKind,
    listeners::type_inference_analyzer::{ConstraintReason, Type, TypeInferenceAnalyzer},
    ssa_form::SsaVar,
};

#[cfg(test)]
mod tests {
    use crate::disasm::v2::instructions::Operand;

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
        let int_var = SsaVar::new(memory_operand(100), 1);

        let bool_var = SsaVar::new(memory_operand(101), 1);

        let char_var = SsaVar::new(memory_operand(102), 1);

        // Get type variables for these SSA variables
        let int_type = type_inference.type_for_var(&int_var);
        let bool_type = type_inference.type_for_var(&bool_var);
        let char_type = type_inference.type_for_var(&char_var);

        // Add constraints
        type_inference.add_constraint(
            int_type.clone(),
            Type::Int,
            1,
            ConstraintReason::AddImpliesInt,
        );

        type_inference.add_constraint(
            bool_type.clone(),
            Type::Bool,
            2,
            ConstraintReason::CompareDstImpliesBool,
        );

        type_inference.add_constraint(
            char_type.clone(),
            Type::Char,
            3,
            ConstraintReason::OutputImpliesChar,
        );

        // Solve constraints
        let substitution = type_inference.unify().expect("Unification should succeed");

        // Verify types
        let int_result = TypeInferenceAnalyzer::substitute(int_type, &substitution);
        let bool_result = TypeInferenceAnalyzer::substitute(bool_type, &substitution);
        let char_result = TypeInferenceAnalyzer::substitute(char_type, &substitution);

        assert_eq!(int_result, Type::Int, "Variable should be an integer");
        assert_eq!(bool_result, Type::Bool, "Variable should be a boolean");
        assert_eq!(char_result, Type::Char, "Variable should be a character");
    }

    #[test]
    fn test_function_pointer_types() {
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        // Create an SSA variable for a function pointer
        let func_ptr_var = SsaVar::new(memory_operand(200), 1);

        // Get type variable
        let func_ptr_type = type_inference.type_for_var(&func_ptr_var);

        // Add constraint for function pointer
        type_inference.add_constraint(
            func_ptr_type.clone(),
            Type::FunctionPointer {
                args: vec![],
                returns: vec![],
            },
            1,
            ConstraintReason::IndirectFunctionCall,
        );

        // Solve constraints
        let substitution = type_inference.unify().expect("Unification should succeed");

        // Verify type
        let result = TypeInferenceAnalyzer::substitute(func_ptr_type, &substitution);

        assert!(
            matches!(result, Type::FunctionPointer { .. }),
            "Variable should be a function pointer, got: {:?}",
            result
        );
    }

    #[test]
    fn test_pointer_types() {
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        // Create variables for testing pointer relationships
        let int_var = SsaVar::new(memory_operand(100), 1);

        let ptr_var = SsaVar::new(memory_operand(101), 1);

        let deref_var = SsaVar::new(deref_operand(101), 1);

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
            ptr_type.clone(),
            Type::Pointer(Box::new(int_type.clone())),
            2,
            ConstraintReason::Assignment,
        );

        // deref_var gets the value of int_var through ptr_var
        type_inference.add_constraint(
            deref_type.clone(),
            int_type.clone(),
            3,
            ConstraintReason::Assignment,
        );

        // Solve constraints
        let substitution = type_inference.unify().expect("Unification should succeed");

        // Verify types
        let int_result = TypeInferenceAnalyzer::substitute(int_type, &substitution);
        let ptr_result = TypeInferenceAnalyzer::substitute(ptr_type, &substitution);
        let deref_result = TypeInferenceAnalyzer::substitute(deref_type, &substitution);

        assert_eq!(int_result, Type::Int, "int_var should be an integer");
        assert_eq!(
            ptr_result,
            Type::Pointer(Box::new(Type::Int)),
            "ptr_var should be a pointer to an integer"
        );
        assert_eq!(deref_result, Type::Int, "deref_var should be an integer");
    }
}
