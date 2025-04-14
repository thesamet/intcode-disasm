#[cfg(test)]
mod type_inference_tests {

    use crate::disasm::parser;
    use crate::disasm::v2::{
        dispatching::EventPublisher,
        events::Event,
        instructions::{InstructionId, Operand, OperandKind},
        listeners::{
            control_flow_builder::ControlFlowGraphBuilder, data_flow_analyzer::DataFlowAnalyzer,
            function_call_analyzer::FunctionCallAnalyzer, image_scanner::ImageScanner,
            ssa_converter::SsaConverter,
        },
        model::{FunctionId, ProgramModel},
        pretty_print::{pretty_print_ssa, pretty_print_with_types},
        ssa_form::SsaVar,
    };

    // Import from the parent module (type_inference)

    use crate::disasm::v2::type_inference::{
        analyzer::TypeInferenceAnalyzer, // Import the analyzer
        constraints::ConstraintReason,
        solver::{self, TypeInferenceError}, // Import solver module itself
        types::Type,
    };

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
                .expect(&format!(
                    "No type found for SSA variable marker {}",
                    $marker
                ));

            assert_eq!(
                *actual_type, $expected_type,
                "Marker {} has incorrect type: expected {:?}, actual {:?}",
                $marker, $expected_type, actual_type
            );
        };
    }

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
            let type_inference = TypeInferenceAnalyzer::new(); // Use the imported analyzer

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

        fn print_traces_for_marker(&self, marker: char) {
            let ssa_var = self
                .model
                .get_ssa_result()
                .unwrap()
                .find_ssa_var_by_marker(marker);
            let typ = Type::SsaVar(ssa_var);
            println!(
                "Trace history for {}:\n{}\nType inference completed successfully",
                marker,
                self.model
                    .get_type_inference_result()
                    .unwrap()
                    .format_traces_for_type(typ)
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
        init();
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        let function_id = FunctionId::from(0);

        // Create some SSA variables to infer types for
        let int_var = SsaVar::new(memory_operand(100), 1, function_id);
        let bool_var = SsaVar::new(memory_operand(101), 1, function_id);
        let char_var = SsaVar::new(memory_operand(102), 1, function_id);

        // Mark variables for easier identification in tests
        type_inference.mark_var(int_var, 'a');
        type_inference.mark_var(bool_var, 'b');
        type_inference.mark_var(char_var, 'c');

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

        // Solve constraints directly using the solver function
        let result = solver::unify(
            type_inference.get_constraints(),
            type_inference.get_debug_markers(),
        )
        .expect("Unification failed");

        // Verify types using marker functions
        let mut final_result = result;
        // Copy debug markers for test verification
        final_result.debug_markers.extend(
            type_inference
                .get_debug_markers()
                .iter()
                .map(|(k, v)| (*k, *v)),
        );

        let a_type = final_result.get_marker_type('a');
        let b_type = final_result.get_marker_type('b');
        let c_type = final_result.get_marker_type('c');

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
        init();
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
        let result = solver::unify(
            type_inference.get_constraints(),
            type_inference.get_debug_markers(),
        )
        .expect("Unification should succeed");

        // Verify type using marker function
        let mut final_result = result;
        final_result.debug_markers.extend(
            type_inference
                .get_debug_markers()
                .iter()
                .map(|(k, v)| (*k, *v)),
        );
        let a_type = final_result.get_marker_type('a');

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
        type_inference.mark_var(int_var, 'a');
        type_inference.mark_var(ptr_var, 'b');
        type_inference.mark_var(deref_var, 'c');

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
        let result = solver::unify(
            type_inference.get_constraints(),
            type_inference.get_debug_markers(),
        )
        .expect("Unification should succeed");

        // Verify types using marker functions
        let mut final_result = result;
        final_result.debug_markers.extend(
            type_inference
                .get_debug_markers()
                .iter()
                .map(|(k, v)| (*k, *v)),
        );
        let a_type = final_result.get_marker_type('a');
        let b_type = final_result.get_marker_type('b');
        let c_type = final_result.get_marker_type('c');

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
        init();
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
        let result = solver::unify(
            type_inference.get_constraints(),
            type_inference.get_debug_markers(),
        );

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
        let result = solver::unify(
            type_inference.get_constraints(),
            type_inference.get_debug_markers(),
        )
        .expect("Unification should succeed");

        // Get the final type for the variable
        // Need to associate the SsaVar with its type manually for testing without the full pipeline
        let final_type = result.inferred_types.get(&var).unwrap();

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
        ctx.print_traces_for_marker('b');
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
        pretty_print_with_types(&ctx.model);
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
        ctx.print_traces_for_marker('b');
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
        ctx.print_traces_for_marker('a');
        assert_marker_type!(ctx, 'a', Type::Char);
        */
        ctx.print_traces_for_marker('b');
        ctx.print_traces_for_marker('d');
        ctx.print_traces_for_marker('e');
        ctx.print_traces_for_marker('f');
        assert_marker_type!(ctx, 'b', Type::Pointer(Box::new(Type::Char)));
        // [R-4] <: [R+1]
        // [R-4] <: Pointer(Char)
        // [R+1] <: Truthy
    }
}
