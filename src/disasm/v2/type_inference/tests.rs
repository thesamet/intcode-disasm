#[cfg(test)]
mod type_inference_tests {

    use log::error;

    use crate::disasm::parser;
    use crate::disasm::v2::model::BlockId;
    use crate::disasm::v2::pretty_print::{pretty_print_ssa, pretty_print_with_types};
    use crate::disasm::v2::ssa_form::SsaOperand;
    use crate::disasm::v2::type_inference::solver;
    use crate::disasm::v2::type_inference::types::VariableKind;
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
        ssa_form::SsaVar,
    };

    // Import from the parent module (type_inference)

    use crate::disasm::v2::type_inference::{
        analyzer::TypeInferenceAnalyzer, // Import the analyzer
        constraints::ConstraintReason,
        types::Type,
    };

    macro_rules! assert_marker_type {
        ($ctx:expr, $marker:expr, $expected_type:expr) => {
            let actual_type = $ctx.get_marker_type($marker);

            assert_eq!(
                actual_type, $expected_type,
                "Marker {} has incorrect type: expected {:?}, actual {:?}",
                $marker, $expected_type, actual_type
            );
        };
    }

    macro_rules! assert_function_pointer {
        ($typ: expr) => {
            // Should be a direct Function type
            let Type::Function { .. } = $typ else {
                panic!("Not a function pointer, got {:?}", $typ);
            };
        };
    }

    macro_rules! assert_marker_is_function_pointer {
        ($ctx:expr, $marker:expr) => {
            let actual_type = $ctx.get_marker_type($marker);
            // Should be a direct Function type
            let Type::Function { .. } = actual_type else {
                panic!(
                    "Marker {} is not a function pointer, got {:?}",
                    $marker, actual_type
                );
            };
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
        /// Try to create a new test context with the given assembly code, returning errors.
        fn try_new(assembly: &str) -> Result<Self, crate::disasm::Error> {
            // Parse the assembly code
            init();
            // Assuming parser::compile returns Result<Vec<u8>, crate::disasm::Error> or compatible
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
            // Assuming model.load_image doesn't return Result or its error is handled implicitly
            model.load_image(&binary, &mut publisher);

            // Process events, mapping the v2::Error to the required disasm::Error
            // The specific mapping depends on the definition of disasm::Error.
            // Here we assume a generic way to represent the error, e.g., via String.
            // Replace this with the actual conversion mechanism (e.g., `From` trait).
            let result = publisher.process_events(&mut model);
            match result {
                Ok(_) => Ok(Self { model }),
                Err(e) => {
                    pretty_print_ssa(&model);
                    error!("{}", e);
                    Err(e)
                }
            }
        }

        fn new(assembly: &str) -> Self {
            Self::try_new(assembly).unwrap()
        }

        fn get_marker_type(&self, marker: char) -> Type {
            let ssa_var = self
                .model
                .get_ssa_result()
                .unwrap()
                .find_ssa_operand_by_marker(marker);

            self.model
                .get_type_inference_result()
                .unwrap()
                .get_type_for_ssavar(ssa_var.as_variable().unwrap())
                .unwrap_or_else(|| panic!("No type found for SSA variable marker {}", marker))
                .clone()
        }

        fn get_type_at_addr(&self, addr: usize) -> Option<&Type> {
            let ti = self.model.get_type_inference_result().unwrap();

            let var = ti
                .inferred_types
                .keys()
                .filter(|var| {
                    var.as_ssavar()
                        .is_some_and(|v| v.kind.get_memory() == Some(addr))
                })
                .max_by_key(|var| var.as_ssavar().unwrap().version)
                .unwrap_or_else(|| panic!("No type variable found for address {}", addr));

            ti.get_type_for_ssavar(var.as_ssavar().unwrap())
        }

        fn assert_type(&self, addr: usize, expected: Type) {
            let Some(actual) = self.get_type_at_addr(addr) else {
                panic!("No type found for address {}", addr);
            };
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
                .find_ssa_operand_by_marker(marker);
            let kind = VariableKind::SsaVar(*ssa_var.as_variable().unwrap());
            println!(
                "Trace history for {}:\n{}\nType inference completed successfully",
                marker,
                self.model
                    .get_type_inference_result()
                    .unwrap()
                    .format_traces_for_var(kind)
            );
        }
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

    fn function_pointer(args: &[Type], returns: &[Type]) -> Type {
        // Represent function pointers directly as Function signatures
        Type::Function {
            args: Box::new(Type::Tuple(args.to_vec())),
            returns: Box::new(Type::Tuple(returns.to_vec())),
        }
    }

    /// Direct API test for type inference (no assembly parsing)
    #[test]
    fn test_basic_type_inference_api() {
        init();
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        let function_id = FunctionId::from(0);

        // Create some SSA operands to infer types for
        let int_var = SsaOperand::from_operand(&memory_operand(100), 1, function_id);
        let bool_var = SsaOperand::from_operand(&memory_operand(101), 1, function_id);
        let char_var = SsaOperand::from_operand(&memory_operand(102), 1, function_id);

        // Mark variables for easier identification in tests
        type_inference.mark_var(int_var, 'a');
        type_inference.mark_var(bool_var, 'b');
        type_inference.mark_var(char_var, 'c');

        // Get type variables for these SSA operands
        let int_type = Type::from_ssaoperand(&int_var);
        let bool_type = Type::from_ssaoperand(&bool_var);
        let char_type = Type::from_ssaoperand(&char_var);

        // Add constraints
        type_inference.add_constraint(
            int_type,
            Type::Int,
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::AddRules,
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
        let model = ProgramModel::new();
        let result = solver::unify(
            &model,
            type_inference.get_constraints(),
            type_inference.get_add_instructions(),
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
        let func_ptr_var = SsaOperand::from_operand(&memory_operand(200), 1, function_id);

        // Mark variable
        type_inference.mark_var(func_ptr_var, 'a');

        // Get type variable
        let func_ptr_type = Type::from_ssaoperand(&func_ptr_var);

        // Add constraint for function pointer
        type_inference.add_constraint(
            func_ptr_type,
            function_pointer(&[], &[]),
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::IndirectFunctionCall {
                calling_block: BlockId::from(0),
            },
        );

        // Solve constraints
        let model = ProgramModel::new();
        let result = solver::unify(
            &model,
            type_inference.get_constraints(),
            type_inference.get_add_instructions(),
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
        let a_type = final_result.get_marker_type('a').unwrap();

        assert_function_pointer!(&a_type);
    }

    /// Direct API test for pointer type inference
    #[test]
    fn test_pointer_types_api() {
        init();
        // Create a manual type inference engine
        let mut type_inference = TypeInferenceAnalyzer::new();

        let function_id = FunctionId::from(0);

        // Create variables for testing pointer relationships
        let int_var = SsaOperand::from_operand(&memory_operand(100), 1, function_id);

        // For a pointer variable, we use Memory kind in SSA
        let ptr_var = SsaOperand::from_operand(&memory_operand(101), 1, function_id);

        // For dereferenced variables, we use the Deref kind
        let deref_var = SsaOperand::from_operand(&deref_operand(101), 1, function_id);

        // Mark variables
        type_inference.mark_var(int_var, 'a');
        type_inference.mark_var(ptr_var, 'b');
        type_inference.mark_var(deref_var, 'c');

        // Get type variables
        let int_type = Type::from_ssaoperand(&int_var);
        let ptr_type = Type::from_ssaoperand(&ptr_var);
        let deref_type = Type::from_ssaoperand(&deref_var);

        // Add constraints
        // int_var is an integer
        type_inference.add_constraint(
            int_type.clone(),
            Type::Int,
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::AddRules,
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
        let model = ProgramModel::new();
        let result = solver::unify(
            &model,
            type_inference.get_constraints(),
            type_inference.get_add_instructions(),
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
        let assembly = r#"
            R += 1000
            [R+1] = @ffunc
            [R] = @ret
            goto @foo
        ret:
            halt


        foo:
            R += 2
            [R+1] = 66
            [R] = @foo_ret
            goto [R-1]
        foo_ret:
            ptr = [R-1]
            output(*ptr)     ; deref a function pointer into a char
            R -= 2
            goto [R]

        ffunc:
            R += 2
            output([R-1])
            R -= 2
            goto [R]
            halt
        "#;

        // Create the TestContext, which runs the full analysis pipeline
        match TestContext::try_new(assembly) {
            Err(e) => {
                assert!(e.to_string().contains("Type conflict for [R-1]_0"));
            }
            Ok(ctx) => {
                pretty_print_with_types(&ctx.model);
                panic!("Expected try_new to fail.");
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
        let var = SsaVar::from_operand(&memory_operand(100), 1, function_id).unwrap();

        // Get type variable
        let var_type = Type::from_ssavar(&var);

        // First, constrain it to Int from arithmetic
        type_inference.add_constraint(
            var_type.clone(),
            Type::Int,
            InstructionId::from(1),
            FunctionId::from(0),
            ConstraintReason::AddRules,
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
        let model = ProgramModel::new();
        let result = solver::unify(
            &model,
            type_inference.get_constraints(),
            type_inference.get_add_instructions(),
            type_inference.get_debug_markers(),
        )
        .expect("Unification should succeed");

        // Get the final type for the variable
        // Need to associate the SsaVar with its type manually for testing without the full pipeline
        let final_type = result
            .inferred_types
            .get(&VariableKind::SsaVar(var))
            .unwrap();

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
        let ctx = TestContext::new(
            r#"
        R += 5000
        [503] = 'a [501] + [502]
        [503] = [503] * 9    ; forces [3] to be an int
        [R] = @res
        goto @f1
res:
        halt
f1:
        R += 4
        [521] = [R-1]
        if 'b [R-2] goto @f1
        R -= 4
        goto [R]

        "#,
        );
        pretty_print_with_types(&ctx.model);
        ctx.assert_type(501, Type::Int);
        assert_marker_type!(ctx, 'a', Type::Int);
        ctx.print_traces_for_marker('b');
        assert_marker_type!(ctx, 'b', Type::Truthy);
    }

    #[test]
    fn test_boolean_comparison() {
        let ctx = TestContext::new(
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
        let ctx = TestContext::new(
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
        let ctx = TestContext::new(
            r#"
                R += 1000
                [1001] = [R-2]
                [R] = @ret
                goto [R-2]
                ret:
                halt

            "#,
        );
        let typ = ctx.get_type_at_addr(1001).unwrap();
        assert_function_pointer!(typ);
    }

    #[test]
    fn test_function_addr_with_debug() {
        init();
        let ctx = TestContext::new(
            r#"
                    R += 1000
                    'd [R+2] = 'a [R-2]
                    'b [R+2] = 15
                    'c [R+2] = [R+2] + 5
                    [R] = @ret
                    goto [R-2]
            ret:
                    halt
                "#,
        );
        pretty_print_with_types(&ctx.model);
        ctx.print_traces_for_marker('a');
        assert_marker_is_function_pointer!(ctx, 'a');
        assert_marker_is_function_pointer!(ctx, 'd');
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
                'c [R+3] = @somefunc
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

    somefunc:
                R += 1
                R -= 1
                goto [R]
            "#,
        );
        pretty_print_with_types(&ctx.model);
        assert_marker_type!(ctx, 'a', Type::Char);
        ctx.print_traces_for_marker('b');
        assert_marker_type!(ctx, 'b', Type::Int);
        assert_marker_is_function_pointer!(ctx, 'c');
        assert_marker_type!(ctx, 'd', Type::Pointer(Box::new(Type::Truthy)));
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
        pretty_print_with_types(&ctx.model);
        assert_marker_is_function_pointer!(ctx, 'a');
    }

    #[test]
    fn test_link_function_return_type_single() {
        // This test also happens to use the same constant (65) for multiple variables
        // testing that each copy can have a different type.
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
        pretty_print_with_types(&ctx.model);
        ctx.print_traces_for_marker('b');

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
                'e [R-1] = [R+1]
    end:
                halt
    print_char_after_pointer:
                R += 5
                [R-1] = 2 * 35
                [R-4] = 'f [R-4] + [R-1]  ; forces 'f to be Pointer(char)
                'd ptr = 'e [R-4]
                [R-1] = *ptr
                output('c [R-1])
                R -= 5
                goto [R]
            "#,
        );
        pretty_print_with_types(&ctx.model);
        assert_marker_type!(ctx, 'a', Type::Int); // not smart enough yet to see it's char.
        assert_marker_type!(ctx, 'b', Type::pointer(Type::Char));
        assert_marker_type!(ctx, 'e', Type::pointer(Type::Char));
        // [R-4] <: [R+1]
        // [R-4] <: Pointer(Char)
        // [R+1] <: Truthy
    }

    #[test]
    fn test_signatures_for_indirect_calls() {
        let ctx = TestContext::new(
            r#"
            R += 1000
            'a [R+1] = 'x @op1
            [R] = @ret1
            goto @makes_indirect_call
        ret1:
            'b [R+1] = @op2
            [R] = @ret2
            goto @makes_indirect_call
        ret2:
            [R-1] = 'm [R+1] * 17
        halt

    makes_indirect_call:
            R += 4
            's [R+1] = 3
            'r [R+2] = 54
            [R] = @fret
            goto 'x [R-3]
        fret:
            [R-3] = [R+1]
            R -= 4
            goto [R]

    op1:
            R += 4
            [R-1] = [R-3] * 7
            output([R-2])
            [R-3] = 35
            R -= 4
            goto [R]

    op2:
            R += 4
            [R-1] = [R-3] * 16
            output([R-2])
            [R-3] = 35
            R -= 4
            goto [R]
            "#,
        );
        pretty_print_with_types(&ctx.model);
        ctx.print_traces_for_marker('a');
        ctx.print_traces_for_marker('x');
        assert_marker_type!(
            ctx,
            'a',
            Type::function_pointer_types(&[Type::Int, Type::Char], &[Type::Int])
        );
        assert_marker_type!(
            ctx,
            'b',
            Type::function_pointer_types(&[Type::Int, Type::Char], &[Type::Int])
        );
        assert_marker_type!(
            ctx,
            'x',
            Type::function_pointer_types(&[Type::Int, Type::Char], &[Type::Int])
        );
        assert_marker_type!(ctx, 's', Type::Int);
        assert_marker_type!(ctx, 'r', Type::Char);
        assert_marker_type!(ctx, 'm', Type::Int);
    }

    #[test]
    fn test_function_pointers_different_args() {
        let ctx = TestContext::new(
            r#"
            R += 1000
            'a [R+1] = 'x @op1
            [R] = @ret1
            goto @makes_indirect_call
        ret1:
            'b [R+1] = @op2
            [R] = @ret2
            goto @makes_indirect_call
        ret2:
            [R-1] = 'm [R+1] * 17
        halt

    makes_indirect_call:
            R += 4
            's [R+1] = 3
            'r [R+2] = 54
            [R] = @fret
            goto 'x [R-3]
        fret:
            [R-3] = [R+1]
            R -= 4
            goto [R]

    op1:
            R += 4
            [R-1] = [R-3] * 7
            output([R-2])
            [R-3] = 35
            R -= 4
            goto [R]

    op2:  ; this time op2 only takes one argument
            R += 4
            [R-1] = [R-3] * 16
            ;    output([R-2])  ; intentionally commented out
            [R-3] = 35
            R -= 4
            goto [R]
            "#,
        );
        pretty_print_with_types(&ctx.model);
    }

    #[test]
    fn test_pointer_arithmetic_case1() {
        init();
        let ctx = TestContext::new(
            r#"
            R += 1000

            ; Test case 1: If left operand is a pointer, right operand must be an integer
            'a [R+100] = 1000
            ptr_a = [R+100]
            'b [R+101] = *ptr_a        ; Define [R+100] as a pointer
            output([R+101])            ; Force [R+101] to be a char
            'c [R+102] = 5             ; Define right operand
            'q [R+103] = ptr_a + [R+102]  ; left is pointer, right must be int

            halt
            "#,
        );
        pretty_print_with_types(&ctx.model);

        // Test case 1: [R+100] is a pointer, [R+102] must be an integer, result must be a pointer
        assert_marker_type!(ctx, 'a', Type::pointer(Type::Char));
        assert_marker_type!(ctx, 'b', Type::Char);
        assert_marker_type!(ctx, 'c', Type::Int);
        assert_marker_type!(ctx, 'q', Type::pointer(Type::Char));
    }

    #[test]
    fn test_pointer_arithmetic_case2() {
        init();
        let ctx = TestContext::new(
            r#"
            R += 1000

            ; Test case 2: If right operand is a pointer, left operand must be an integer
            'd [R+200] = 2000
            ptr_b = [R+200]
            'e [R+201] = *ptr_b        ; Define [R+200] as a pointer
            output([R+201])            ; Force [R+201] to be a char
            'f [R+202] = 10            ; Define left operand
            'r [R+203] = [R+202] + ptr_b  ; right is pointer, left must be int

            halt
            "#,
        );
        pretty_print_with_types(&ctx.model);

        // Test case 2: [R+200] is a pointer, [R+202] must be an integer, result must be a pointer
        assert_marker_type!(ctx, 'd', Type::pointer(Type::Char));
        assert_marker_type!(ctx, 'e', Type::Char);
        assert_marker_type!(ctx, 'f', Type::Int);
        assert_marker_type!(ctx, 'r', Type::pointer(Type::Char));
    }

    #[test]
    fn test_pointer_arithmetic_case3() {
        init();
        let ctx = TestContext::new(
            r#"
            R += 1000

            ; Test case 3: When one operand is a known integer and the result is a pointer,
            ; the other operand must be inferred as a pointer
            'g [R+300] = 3000          ; Address value, not forced to be pointer yet
            'h [R+301] = 20            ; Will be established as an integer through its use
            'i [R+302] = [R+301] * 2   ; Force [R+301] to be an integer through multiplication
            's [R+303] = [R+300] + [R+301]  ; [R+301] is int, so [R+300] should be inferred as pointer
            ptr_sum3 = [R+303]
            'o [R+304] = *ptr_sum3     ; Force result [R+303] to be a pointer via dereferencing
            output([R+304])            ; Force [R+304] to be a char

            halt
            "#,
        );
        pretty_print_with_types(&ctx.model);

        // Test case 3: [R+301] is an integer, [R+300] must be a pointer, result is pointer
        assert_marker_type!(ctx, 'g', Type::pointer(Type::Char));
        assert_marker_type!(ctx, 'h', Type::Int);
        assert_marker_type!(ctx, 'i', Type::Int);
        assert_marker_type!(ctx, 's', Type::pointer(Type::Char));
        assert_marker_type!(ctx, 'o', Type::Char);
    }

    #[test]
    fn test_pointer_arithmetic_case4() {
        init();
        let ctx = TestContext::new(
            r#"
            R += 1000

            ; Test case 4: When one operand is a known integer and the result is a pointer,
            ; the other operand must be inferred as a pointer. Opposite operands to case 3.
            'g [R+300] = 3000          ; Address value, not forced to be pointer yet
            'h [R+301] = 20            ; Will be established as an integer through its use
            'i [R+302] = [R+301] * 2   ; Force [R+301] to be an integer through multiplication
            's [R+303] = [R+301] + [R+300]  ; [R+301] is int, so [R+300] should be inferred as pointer
            ptr_sum3 = [R+303]
            'o [R+304] = *ptr_sum3     ; Force result [R+303] to be a pointer via dereferencing
            output([R+304])            ; Force [R+304] to be a char

            halt
            "#,
        );
        pretty_print_with_types(&ctx.model);

        // Test case 3: [R+301] is an integer, [R+300] must be a pointer, result is pointer
        assert_marker_type!(ctx, 'g', Type::pointer(Type::Char));
        assert_marker_type!(ctx, 'h', Type::Int);
        assert_marker_type!(ctx, 'i', Type::Int);
        assert_marker_type!(ctx, 's', Type::pointer(Type::Char));
        assert_marker_type!(ctx, 'o', Type::Char);
    }

    #[test]
    fn test_pointer_arithmetic_case5() {
        init();
        let ctx = TestContext::new(
            r#"
            R += 1000

            ; Test case 5: When the result is a pointer, and one operand is a pointer,
            ; the other operand must be inferred as an integer
            'j [R+400] = 4000           ; Just a value that will become a pointer
            ptr_d = [R+400]             ; Store in ptr_d
            'k [R+401] = *ptr_d         ; Force ptr_d to be a pointer through dereferencing
            output([R+401])             ; Force [R+401] to be a char

            ; Define an operand we want to test (with marker to check its inferred type)
            'l [R+402] = 30             ; This value should be inferred as an integer

            ; Addition where we'll force the result to be a pointer
            't [R+403] = ptr_d + [R+402]  ; The addition (with marker on result)
            ptr_sum4 = [R+403]          ; Store for dereferencing
            'p [R+404] = *ptr_sum4      ; Force result to be a pointer
            output([R+404])             ; Force [R+404] to be a char

            halt
            "#,
        );
        pretty_print_with_types(&ctx.model);

        // Test case 4: When one operand and result are known to be pointers,
        // the other operand must be inferred as an integer
        assert_marker_type!(ctx, 'j', Type::pointer(Type::Char)); // Base address
        assert_marker_type!(ctx, 'k', Type::Char); // Dereferenced result
        assert_marker_type!(ctx, 'l', Type::Int); // This should be inferred as an integer
        assert_marker_type!(ctx, 't', Type::pointer(Type::Char)); // Result is pointer
        assert_marker_type!(ctx, 'p', Type::Char); // Dereferenced result
    }

    #[test]
    fn test_pointer_arithmetic_case6() {
        init();
        let ctx = TestContext::new(
            r#"
            R += 1000

            ; Test case 6: When the result is a pointer, and one operand is a pointer,
            ; the other operand must be inferred as an integer. Oppsite operands to case 5.
            'j [R+400] = 4000           ; Just a value that will become a pointer
            ptr_d = [R+400]             ; Store in ptr_d
            'k [R+401] = *ptr_d         ; Force ptr_d to be a pointer through dereferencing
            output([R+401])             ; Force [R+401] to be a char

            ; Define an operand we want to test (with marker to check its inferred type)
            'l [R+402] = 30             ; This value should be inferred as an integer

            ; Addition where we'll force the result to be a pointer
            't [R+403] = [R+402] + ptr_d; The addition (with marker on result)
            ptr_sum4 = [R+403]          ; Store for dereferencing
            'p [R+404] = *ptr_sum4      ; Force result to be a pointer
            output([R+404])             ; Force [R+404] to be a char

            halt
            "#,
        );
        pretty_print_with_types(&ctx.model);

        // Test case 4: When one operand and result are known to be pointers,
        // the other operand must be inferred as an integer
        assert_marker_type!(ctx, 'j', Type::pointer(Type::Char)); // Base address
        assert_marker_type!(ctx, 'k', Type::Char); // Dereferenced result
        assert_marker_type!(ctx, 'l', Type::Int); // This should be inferred as an integer
        assert_marker_type!(ctx, 't', Type::pointer(Type::Char)); // Result is pointer
        assert_marker_type!(ctx, 'p', Type::Char); // Dereferenced result
    }

    #[test]
    fn test_pointer_arithmetic_case7() {
        init();
        let ctx = TestContext::new(
            r#"
            R += 1000

            ; Test case 7: When the result is an int, all other operands must be ints.
            'a [R+700] = 100
            'b [R+701] = 20
            'c [R+702] = [R+701] + [R+700]
            'd [R+703] = [R+702] * 12
            halt
        "#,
        );
        pretty_print_with_types(&ctx.model);

        // Test case 4: When one operand and result are known to be pointers,
        // the other operand must be inferred as an integer
        assert_marker_type!(ctx, 'a', Type::Int);
        assert_marker_type!(ctx, 'b', Type::Int);
        assert_marker_type!(ctx, 'c', Type::Int);
        assert_marker_type!(ctx, 'd', Type::Int);
    }
}
