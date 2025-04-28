#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fmt::Display;

    use itertools::Itertools;
    use thiserror::Error;

    use crate::disasm::hlr::ast::{
        BinaryOperator, HlrAssignmentTarget, HlrExpression, HlrFunction, HlrProgram, HlrStatement,
        HlrVariable,
    };
    use crate::disasm::v2::dispatching::EventPublisher;
    use crate::disasm::v2::events::Event;
    use crate::disasm::v2::model::{FunctionId, ProgramModel};
    use crate::disasm::v2::type_inference::types::Type;
    struct VariableMapping {
        actual_to_expected: HashMap<String, String>,
        expected_to_actual: HashMap<String, String>,
    }

    #[derive(Error)]
    #[error("Comparison failed: {context}")]
    enum ComparisonError {
        #[error("At {context}: expected: {expected}, got: {actual}")]
        DifferentValues {
            actual: String,
            expected: String,
            context: String,
        },
        #[error("At {context}: expected: {expected}, got: {actual}")]
        UnsupportedComparison {
            actual: String,
            expected: String,
            context: String,
        },
    }

    impl std::fmt::Debug for ComparisonError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            std::fmt::Display::fmt(self, f)
        }
    }

    impl ComparisonError {
        fn new<T: Display>(actual: T, expected: T, context: &str) -> Self {
            Self::DifferentValues {
                actual: actual.to_string(),
                expected: expected.to_string(),
                context: context.to_string(),
            }
        }

        fn unsupported_comparison<T: Display>(actual: T, expected: T, context: &str) -> Self {
            Self::UnsupportedComparison {
                actual: actual.to_string(),
                expected: expected.to_string(),
                context: context.to_string(),
            }
        }
    }

    fn compare<T>(actual: T, expected: T, context: &str) -> Result<(), ComparisonError>
    where
        T: Display + PartialEq,
    {
        if expected == actual {
            Ok(())
        } else {
            Err(ComparisonError::new(expected, actual, context))
        }
    }

    type ComparisonResult = Result<(), ComparisonError>;

    impl VariableMapping {
        fn new() -> Self {
            Self {
                actual_to_expected: HashMap::new(),
                expected_to_actual: HashMap::new(),
            }
        }

        fn map_variable(
            &mut self,
            actual_name: &str,
            expected_name: &str,
            actual_type: &Type,
            expected_type: &Type,
            context: &str,
        ) -> ComparisonResult {
            compare(
                actual_type,
                expected_type,
                &format!("{}:Variable types don't match", context),
            )?;

            // Check if we already have a mapping
            if let Some(mapped_expected) = self.actual_to_expected.get(actual_name) {
                return compare(
                    mapped_expected,
                    &expected_name.to_string(),
                    &format!(
                        "{}:Variable name mapping inconsistent based on prior usage",
                        context
                    ),
                );
            }

            if let Some(mapped_actual) = self.expected_to_actual.get(expected_name) {
                return compare(
                    mapped_actual,
                    &actual_name.to_string(),
                    &format!(
                        "{}:Variable name mapping inconsistent based on prior usage",
                        context
                    ),
                );
            }

            // Create a new mapping
            self.actual_to_expected
                .insert(actual_name.to_string(), expected_name.to_string());
            self.expected_to_actual
                .insert(expected_name.to_string(), actual_name.to_string());
            Ok(())
        }
    }

    // Helper functions to create HLR structures concisely
    fn hlr_program(functions: Vec<HlrFunction>) -> HlrProgram {
        HlrProgram {
            functions,
            globals: vec![],
        }
    }

    fn hlr_function(id: usize, body: Vec<HlrStatement>) -> HlrFunction {
        HlrFunction {
            original_id: FunctionId::from(id),
            name: id.to_string(),
            args: vec![],
            return_type: vec![],
            body,
        }
    }

    fn hlr_var(name: &str, typ: Type) -> HlrVariable {
        HlrVariable {
            name: name.to_string(),
            type_info: typ,
        }
    }

    fn hlr_vardef(target: HlrVariable, expr: HlrExpression) -> HlrStatement {
        HlrStatement::VarDef(vec![target], expr)
    }

    fn hlr_assign(target: HlrAssignmentTarget, expr: HlrExpression) -> HlrStatement {
        HlrStatement::Assignment(target, expr)
    }

    fn hlr_var_target(name: &str, typ: Type) -> HlrAssignmentTarget {
        HlrAssignmentTarget::Variable(hlr_var(name, typ))
    }

    fn hlr_var_expr(name: &str, typ: Type) -> HlrExpression {
        HlrExpression::Variable(hlr_var(name, typ))
    }

    fn hlr_const(value: i128, typ: Type) -> HlrExpression {
        HlrExpression::Constant(value, typ)
    }

    fn hlr_binop(
        op: BinaryOperator,
        left: HlrExpression,
        right: HlrExpression,
        result_type: Type,
    ) -> HlrExpression {
        HlrExpression::BinaryOp {
            op,
            left: Box::new(left),
            right: Box::new(right),
            result_type,
        }
    }

    fn hlr_if(
        condition: HlrExpression,
        then_branch: Vec<HlrStatement>,
        else_branch: Vec<HlrStatement>,
    ) -> HlrStatement {
        HlrStatement::If(condition, then_branch, else_branch)
    }

    fn hlr_do_while(body: Vec<HlrStatement>, condition: HlrExpression) -> HlrStatement {
        HlrStatement::DoWhile(body, condition)
    }

    fn hlr_loop(body: Vec<HlrStatement>) -> HlrStatement {
        HlrStatement::Loop(body)
    }

    fn hlr_deref(expr: HlrExpression) -> HlrExpression {
        HlrExpression::Deref(Box::new(expr))
    }

    fn hlr_input() -> HlrExpression {
        HlrExpression::Input()
    }

    fn hlr_output(expr: HlrExpression) -> HlrStatement {
        HlrStatement::Output(expr)
    }

    fn hlr_return(exprs: Vec<HlrExpression>) -> HlrStatement {
        HlrStatement::Return(exprs)
    }

    fn hlr_function_call(func_expr: HlrExpression, args: Vec<HlrExpression>) -> HlrExpression {
        HlrExpression::FunctionCall(Box::new(func_expr), args)
    }

    // Assertion functions
    fn assert_hlr_programs_equivalent(
        actual: &HlrProgram,
        expected: &HlrProgram,
    ) -> ComparisonResult {
        compare(
            actual.functions.len(),
            expected.functions.len(),
            "Different number of functions",
        )?;

        // Create a map of function IDs to functions for both actual and expected
        let actual_funcs: HashMap<_, _> = actual
            .functions
            .iter()
            .map(|f| (f.original_id, f))
            .collect();
        let expected_funcs: HashMap<_, _> = expected
            .functions
            .iter()
            .map(|f| (f.original_id, f))
            .collect();

        // Check that both have the same set of function IDs
        compare(
            actual_funcs.keys().sorted().join(", "),
            expected_funcs.keys().sorted().join(", "),
            "Function IDs don't match",
        )?;

        // Compare functions with the same ID
        for (id, expected_func) in expected_funcs.iter() {
            let actual_func = actual_funcs.get(id).unwrap();
            let mut mapping = VariableMapping::new();
            assert_statements_equivalent(
                &actual_func.body,
                &expected_func.body,
                &mut mapping,
                &format!("Function[{}]", id),
            )?;
        }
        Ok(())
    }

    fn assert_statements_equivalent(
        actual: &[HlrStatement],
        expected: &[HlrStatement],
        mapping: &mut VariableMapping,
        context: &str,
    ) -> ComparisonResult {
        compare(
            actual.len(),
            expected.len(),
            &format!("{}: Different number of statements", context),
        )?;
        for (i, (actual_stmt, expected_stmt)) in actual.iter().zip(expected.iter()).enumerate() {
            let stmt_context = format!("{}:Statement[{}]", context, i);

            match (actual_stmt, expected_stmt) {
                (
                    HlrStatement::Assignment(actual_target, actual_expr),
                    HlrStatement::Assignment(expected_target, expected_expr),
                ) => {
                    assert_targets_equivalent(
                        actual_target,
                        expected_target,
                        mapping,
                        &format!("{}:Target", stmt_context),
                    )?;
                    assert_expressions_equivalent(
                        actual_expr,
                        expected_expr,
                        mapping,
                        &format!("{}:Expression", stmt_context),
                    )?;
                }
                (
                    HlrStatement::VarDef(actual_var, actual_expr),
                    HlrStatement::VarDef(expected_var, expected_expr),
                ) => {
                    if actual_var.len() != expected_var.len() {
                        Err(ComparisonError::unsupported_comparison(
                            format!("{:?}", actual_var),
                            format!("{:?}", expected_var),
                            &format!("{}:Variable types don't match", stmt_context),
                        ))?
                    }
                    for (i, (actual_var, expected_var)) in
                        actual_var.iter().zip(expected_var.iter()).enumerate()
                    {
                        assert_var_equivalent(
                            actual_var,
                            expected_var,
                            mapping,
                            &format!("{}:Expression[{}]", stmt_context, i),
                        )?;
                    }
                    assert_expressions_equivalent(
                        actual_expr,
                        expected_expr,
                        mapping,
                        &format!("{}:Expression", stmt_context),
                    )?;
                }
                (
                    HlrStatement::If(actual_cond, actual_then, actual_else),
                    HlrStatement::If(expected_cond, expected_then, expected_else),
                ) => {
                    assert_expressions_equivalent(
                        actual_cond,
                        expected_cond,
                        mapping,
                        &format!("{}:Condition", stmt_context),
                    )?;
                    assert_statements_equivalent(
                        actual_then,
                        expected_then,
                        mapping,
                        &format!("{}:ThenBranch", stmt_context),
                    )?;
                    assert_statements_equivalent(
                        actual_else,
                        expected_else,
                        mapping,
                        &format!("{}:ElseBranch", stmt_context),
                    )?;
                }
                (HlrStatement::Loop(actual_body), HlrStatement::Loop(expected_body)) => {
                    assert_statements_equivalent(
                        actual_body,
                        expected_body,
                        mapping,
                        &format!("{}:LoopBody", stmt_context),
                    )?;
                }
                (HlrStatement::Output(actual_expr), HlrStatement::Output(expected_expr)) => {
                    assert_expressions_equivalent(
                        actual_expr,
                        expected_expr,
                        mapping,
                        &format!("{}:Output", stmt_context),
                    )?;
                }
                (HlrStatement::Return(actual_exprs), HlrStatement::Return(expected_exprs)) => {
                    compare(
                        actual_exprs.len(),
                        expected_exprs.len(),
                        &format!("{}:Return: expression count mismatch", stmt_context),
                    )?;
                    for (j, (a, e)) in actual_exprs.iter().zip(expected_exprs.iter()).enumerate() {
                        assert_expressions_equivalent(
                            a,
                            e,
                            mapping,
                            &format!("{}:Return[{}]", stmt_context, j),
                        )?;
                    }
                    ()
                }
                (HlrStatement::Halt, HlrStatement::Halt) => {}
                (HlrStatement::Continue, HlrStatement::Continue) => {}
                (HlrStatement::Break, HlrStatement::Break) => {}
                (
                    HlrStatement::DoWhile(actual_body, actual_cond),
                    HlrStatement::DoWhile(expected_body, expected_cond),
                ) => {
                    assert_statements_equivalent(
                        actual_body,
                        expected_body,
                        mapping,
                        &format!("{}:DoWhileBody", stmt_context),
                    )?;
                    assert_expressions_equivalent(
                        actual_cond,
                        expected_cond,
                        mapping,
                        &format!("{}:DoWhileCond", stmt_context),
                    )?
                }

                _ => Err(ComparisonError::unsupported_comparison(
                    format!("{:?}", actual_stmt),
                    format!("{:?}", expected_stmt),
                    &format!("{}:Statement types don't match", stmt_context),
                ))?,
            }
        }
        Ok(())
    }

    fn assert_targets_equivalent(
        actual: &HlrAssignmentTarget,
        expected: &HlrAssignmentTarget,
        mapping: &mut VariableMapping,
        context: &str,
    ) -> ComparisonResult {
        match (actual, expected) {
            (
                HlrAssignmentTarget::Variable(actual_var),
                HlrAssignmentTarget::Variable(expected_var),
            ) => {
                assert_var_equivalent(actual_var, expected_var, mapping, context)?;
            }
            (
                HlrAssignmentTarget::Deref(actual_expr),
                HlrAssignmentTarget::Deref(expected_expr),
            ) => assert_expressions_equivalent(
                actual_expr,
                expected_expr,
                mapping,
                &format!("{}:Deref", context),
            )?,
            (HlrAssignmentTarget::Ignored, HlrAssignmentTarget::Ignored) => (),
            _ => {
                Err(ComparisonError::unsupported_comparison(
                    format!("{:?}", actual),
                    format!("{:?}", expected),
                    &format!("{}:Assignment target types don't match", context),
                ))?;
            }
        }
        Ok(())
    }

    fn assert_var_equivalent(
        actual: &HlrVariable,
        expected: &HlrVariable,
        mapping: &mut VariableMapping,
        context: &str,
    ) -> ComparisonResult {
        compare(
            &actual.type_info,
            &expected.type_info,
            &format!("{}:Variable types don't match", context),
        )?;

        mapping.map_variable(
            &actual.name,
            &expected.name,
            &actual.type_info,
            &expected.type_info,
            context,
        )?;
        Ok(())
    }

    fn assert_expressions_equivalent(
        actual: &HlrExpression,
        expected: &HlrExpression,
        mapping: &mut VariableMapping,
        context: &str,
    ) -> ComparisonResult {
        match (actual, expected) {
            (HlrExpression::Variable(actual_var), HlrExpression::Variable(expected_var)) => {
                assert_eq!(
                    &actual_var.type_info, &expected_var.type_info,
                    "{}:Variable types don't match: {:?} vs {:?}",
                    context, actual_var.type_info, expected_var.type_info
                );

                mapping.map_variable(
                    &actual_var.name,
                    &expected_var.name,
                    &actual_var.type_info,
                    &expected_var.type_info,
                    context,
                )?
            }
            (
                HlrExpression::Constant(actual_val, actual_type),
                HlrExpression::Constant(expected_val, expected_type),
            ) => {
                assert_eq!(
                    actual_val, expected_val,
                    "{}:Constant values don't match: {} vs {}",
                    context, actual_val, expected_val
                );
                compare(
                    &actual_val,
                    &expected_val,
                    &format!("{}:Constant values don't match", context),
                )?;
                compare(
                    &actual_type,
                    &expected_type,
                    &format!("{}:Constant types don't match", context),
                )?
            }
            (
                HlrExpression::BinaryOp {
                    op: actual_op,
                    left: actual_left,
                    right: actual_right,
                    result_type: actual_type,
                },
                HlrExpression::BinaryOp {
                    op: expected_op,
                    left: expected_left,
                    right: expected_right,
                    result_type: expected_type,
                },
            ) => {
                compare(
                    actual_op,
                    expected_op,
                    &format!("{}:Binary operators don't match", context),
                )?;
                compare(
                    actual_type,
                    expected_type,
                    &format!("{}:Result types don't match", context),
                )?;
                assert_expressions_equivalent(
                    actual_left,
                    expected_left,
                    mapping,
                    &format!("{}:Left", context),
                )?;
                assert_expressions_equivalent(
                    actual_right,
                    expected_right,
                    mapping,
                    &format!("{}:Right", context),
                )?
            }
            (HlrExpression::Deref(actual_expr), HlrExpression::Deref(expected_expr)) => {
                assert_expressions_equivalent(
                    actual_expr,
                    expected_expr,
                    mapping,
                    &format!("{}:Deref", context),
                )?
            }
            (HlrExpression::Input(), HlrExpression::Input()) => {}
            (
                HlrExpression::FunctionCall(actual_func, actual_args),
                HlrExpression::FunctionCall(expected_func, expected_args),
            ) => {
                assert_expressions_equivalent(
                    actual_func,
                    expected_func,
                    mapping,
                    &format!("{}:FunctionCall", context),
                )?;
                for (j, (a, e)) in actual_args.iter().zip(expected_args.iter()).enumerate() {
                    assert_expressions_equivalent(
                        a,
                        e,
                        mapping,
                        &format!("{}:Arg[{}]", context, j),
                    )?;
                }
            }
            _ => Err(ComparisonError::unsupported_comparison(
                format!("{:?}", actual),
                format!("{:?}", expected),
                &format!("{}:Expression types don't match", context),
            ))?,
        }
        Ok(())
    }

    use crate::disasm::v2::listeners::{
        control_flow_analyzer::ControlFlowStructureRecoveryListener,
        control_flow_graph_builder::ControlFlowGraphBuilder, data_flow_analyzer::DataFlowAnalyzer,
        function_call_analyzer::FunctionCallAnalyzer, image_scanner::ImageScanner,
        ssa_converter::SsaConverter, variable_analyzer::VariableAnalyzer,
    };
    use crate::disasm::v2::type_inference::TypeInferenceAnalyzer;
    use crate::disasm::{hlr::ast::pretty_print_program, v2::pretty_print::pretty_print_ssa};

    struct TestContext {
        model: ProgramModel,
    }

    impl TestContext {
        fn from_assembly(assembly: &str) -> Self {
            // Parse assembly to Intcode
            let image = crate::disasm::parser::compile(assembly);

            // Set up model and event publisher
            let mut model = ProgramModel::new();
            let mut publisher = EventPublisher::<Event, ProgramModel>::new();

            // Add all required listeners in the correct order
            publisher.add_listener(Box::new(ImageScanner::new()));
            publisher.add_listener(Box::new(ControlFlowGraphBuilder::new()));
            publisher.add_listener(Box::new(DataFlowAnalyzer::new()));
            publisher.add_listener(Box::new(SsaConverter::new()));
            publisher.add_listener(Box::new(FunctionCallAnalyzer::new()));
            publisher.add_listener(Box::new(TypeInferenceAnalyzer::new()));
            publisher.add_listener(Box::new(VariableAnalyzer::new()));
            publisher.add_listener(Box::new(ControlFlowStructureRecoveryListener::new()));

            // Load the image and process events
            model.load_image(&image, &mut publisher);
            publisher
                .process_events(&mut model)
                .expect("Failed to process events");

            TestContext { model }
        }

        fn get_hlr_program(&self) -> Option<&HlrProgram> {
            self.model.get_hlr_program()
        }
    }
    #[test]
    fn test_simple_sequential() -> ComparisonResult {
        let assembly = r#"
            R += 100           ; Initial R adjustment for main function
            [3] = 1 + 2        ; Add 1+2 -> mem[3]
            [5] = 3 + 4        ; Add 3+4 -> mem[5]
            halt               ; Halt
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program using our helper functions
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(
                    hlr_var("ptr1", Type::Any),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_const(1, Type::Int),
                        hlr_const(2, Type::Int),
                        Type::Any,
                    ),
                ),
                hlr_vardef(
                    hlr_var("ptr2", Type::Any),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_const(3, Type::Int),
                        hlr_const(4, Type::Int),
                        Type::Any,
                    ),
                ),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected)
    }

    #[test]
    fn test_if_else() -> ComparisonResult {
        let assembly = r#"
            R += 100           ; Initial R adjustment for main function
            [3] = 2 * 3        ; x = 1 + 2
            [4] = [3] == 3     ; y = (x == 3)
            if [4] goto @then  ; if y then goto label_then
            [7] = 5 * 6        ; z = 5 + 6 (else branch)
            goto @end          ; goto label_end
            then:
            [7] = 7 * 8        ; z = 7 + 8 (then branch)
            end:
            R -= 100
            goto [R]
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(
                    hlr_var("x", Type::Int),
                    hlr_binop(
                        BinaryOperator::Mul,
                        hlr_const(2, Type::Int),
                        hlr_const(3, Type::Int),
                        Type::Int,
                    ),
                ),
                hlr_vardef(
                    hlr_var("y", Type::Bool),
                    hlr_binop(
                        BinaryOperator::Equals,
                        hlr_var_expr("x", Type::Int),
                        hlr_const(3, Type::Int),
                        Type::Bool,
                    ),
                ),
                hlr_if(
                    hlr_binop(
                        BinaryOperator::NotEquals,
                        hlr_var_expr("y", Type::Bool),
                        hlr_const(0, Type::Int),
                        Type::Bool,
                    ),
                    // Then branch
                    vec![hlr_vardef(
                        hlr_var("w", Type::Int), // potential bug since we use different variables here.
                        hlr_binop(
                            BinaryOperator::Mul,
                            hlr_const(7, Type::Int),
                            hlr_const(8, Type::Int),
                            Type::Int,
                        ),
                    )],
                    // Else branch
                    vec![
                        hlr_vardef(
                            hlr_var("z", Type::Int),
                            hlr_binop(
                                BinaryOperator::Mul,
                                hlr_const(5, Type::Int),
                                hlr_const(6, Type::Int),
                                Type::Int,
                            ),
                        ),
                        hlr_return(vec![]),
                    ],
                ),
            ],
        )]);
        println!("{}", pretty_print_program(ctx.get_hlr_program().unwrap()));

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected)
    }

    #[test]
    fn test_loop() -> ComparisonResult {
        let assembly = r#"
            R += 100                  ;  0: Initial R adjustment for main function
            [R-1] = 0                 ;  2: i = 0
            loop_start:
            [R-2] = [R-1] < 10        ;  6: cond = (i < 10)
            if ![R-2] goto @loop_end  ; 10: if cond == 0 goto loop_end
            [R-1] = [R-1] + 1         ; 13: i = i + 1
            goto @loop_start          ; 17: goto loop_start
            loop_end:
            R -= 100                  ; 20
            goto [R]                  ; 21
            "#;

        let ctx = TestContext::from_assembly(assembly);
        pretty_print_ssa(&ctx.model);

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("i", Type::Int), hlr_const(0, Type::Int)),
                hlr_loop(vec![
                    hlr_vardef(
                        hlr_var("tmp", Type::Bool),
                        hlr_binop(
                            BinaryOperator::LessThan,
                            hlr_var_expr("i", Type::Int),
                            hlr_const(10, Type::Int),
                            Type::Bool,
                        ),
                    ),
                    hlr_if(
                        hlr_binop(
                            BinaryOperator::Equals,
                            hlr_var_expr("tmp", Type::Bool),
                            hlr_const(0, Type::Int),
                            Type::Bool,
                        ),
                        vec![HlrStatement::Break],
                        vec![],
                    ),
                    hlr_assign(
                        hlr_var_target("i", Type::Int),
                        hlr_binop(
                            BinaryOperator::Add,
                            hlr_var_expr("i", Type::Int),
                            hlr_const(1, Type::Int),
                            Type::Int,
                        ),
                    ),
                ]),
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected)
    }

    #[test]
    fn test_do_while() -> ComparisonResult {
        let assembly = r#"
            R += 100
            [R-1] = 0
            loop_start:
            output([R-1])
            [R-1] = [R-1] + 1
            [R-2] = [R-1] < 10
            if [R-2] goto @loop_start
            output(10)
            R -= 100
            goto [R]
            "#;

        let ctx = TestContext::from_assembly(assembly);
        pretty_print_ssa(&ctx.model);

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("i", Type::Char), hlr_const(0, Type::Int)),
                hlr_do_while(
                    vec![
                        HlrStatement::Output(hlr_var_expr("i", Type::Char)),
                        hlr_assign(
                            hlr_var_target("i", Type::Char),
                            hlr_binop(
                                BinaryOperator::Add,
                                hlr_var_expr("i", Type::Char),
                                hlr_const(1, Type::Int),
                                Type::Char,
                            ),
                        ),
                        hlr_vardef(
                            hlr_var("tmp", Type::Bool),
                            hlr_binop(
                                BinaryOperator::LessThan,
                                hlr_var_expr("i", Type::Char),
                                hlr_const(10, Type::Int),
                                Type::Bool,
                            ),
                        ),
                    ],
                    hlr_binop(
                        BinaryOperator::NotEquals,
                        hlr_var_expr("tmp", Type::Bool),
                        hlr_const(0, Type::Int),
                        Type::Bool,
                    ),
                ),
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected)
    }

    #[test]
    fn test_input_output() -> ComparisonResult {
        let assembly = r#"
            R += 100           ; Initial R adjustment for main function
            INPUT [1]          ; x = input()
            [2] = [1] + 10     ; y = x + 10
            output([2])        ; output(y)
            halt               ; Halt
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program with matching types
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("m1", Type::Int), hlr_input()),
                hlr_vardef(
                    hlr_var("m2", Type::Char),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_var_expr("m1", Type::Int),
                        hlr_const(10, Type::Int),
                        Type::Char,
                    ),
                ),
                hlr_output(hlr_var_expr("m2", Type::Char)),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected)
    }

    #[test]
    fn test_pointer_operations() -> ComparisonResult {
        let assembly = r#"
            R += 100           ; Initial R adjustment for main function
            ptr = 100          ; ptr = 100 (address)
            [R+1] = *ptr       ; x = *ptr (value at address 100)
            [R+2] = [R+1] + 5  ; y = x + 5
            halt               ; Halt
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(
                    hlr_var("ptr1", Type::Pointer(Box::new(Type::Any))),
                    hlr_const(100, Type::Int),
                ),
                hlr_vardef(
                    hlr_var("local1", Type::Any),
                    hlr_deref(hlr_var_expr("ptr1", Type::Pointer(Box::new(Type::Any)))),
                ),
                hlr_vardef(
                    hlr_var("local2", Type::Any),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_var_expr("local1", Type::Any),
                        hlr_const(5, Type::Int),
                        Type::Any,
                    ),
                ),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected)
    }

    #[test]
    fn test_function_call() -> ComparisonResult {
        let assembly = r#"
            ; Main function
            R += 100           ; Initial R adjustment for main function
            [R+1] = 5          ; Set argument
            [R] = @return_addr ; Set return address
            goto @func         ; Call function
            return_addr:
            output([R+1])      ; Output return value
            halt

            ; Function that adds 5 to its input
            func:
            R += 3             ; Adjust stack for local variables
            [R-2] = [R-2] + 5  ; result = arg + 5
            R -= 3             ; Restore stack
            goto [R]           ; Return
        "#;

        let ctx = TestContext::from_assembly(assembly);
        println!("{}", pretty_print_program(ctx.get_hlr_program().unwrap()));

        // Create expected HLR program (simplified for this test)
        let expected = hlr_program(vec![
            hlr_function(
                0,
                vec![
                    hlr_vardef(hlr_var("arg", Type::Int), hlr_const(5, Type::Int)),
                    hlr_vardef(
                        hlr_var("result", Type::Char),
                        hlr_function_call(hlr_const(16, Type::Int), vec![]),
                    ),
                    hlr_output(hlr_var_expr("result", Type::Char)),
                    HlrStatement::Halt,
                ],
            ),
            hlr_function(
                16,
                vec![
                    hlr_vardef(
                        hlr_var("arg1", Type::Char),
                        hlr_binop(
                            BinaryOperator::Add,
                            hlr_var_expr("arg1", Type::Char),
                            hlr_const(5, Type::Int),
                            Type::Char,
                        ),
                    ),
                    hlr_return(vec![hlr_var_expr("arg1", Type::Char)]),
                ],
            ),
        ]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected)
    }

    #[test]
    fn test_nested_if_else() -> ComparisonResult {
        let _assembly = r#"
            R += 100                      ; 0: Initial R adjustment for main function
            [R-1] = 10                    ; 2: x = 10
            [R-2] = [R-1] < 5             ; 6: cond1 = (x < 5)
            if ![R-2] goto @else_outer    ; 10: if !cond1 goto else_outer

            ; Then branch of outer if
            [R-3] = [R-1] < 15            ; 13: cond2 = (x < 15)
            if ![R-3] goto @else_inner    ; 17: if !cond2 goto else_inner

            ; Then branch of inner if
            [R-4] = 1                     ; 20: result = 1
            goto @end_inner               ; 24:

            else_inner:
            ; Else branch of inner if
            [R-4] = 2                     ; 27: result = 2

            end_inner:
            goto @end_outer               ; 31:

            else_outer:
            ; Else branch of outer if
            [R-4] = 3                     ; 34: result = 3

            end_outer:
            output([R-4])                 ; 38: output(result)
            R -= 100                      ; 40:
            goto [R]                      ; 42:
        "#;

        let ctx = TestContext::from_assembly(_assembly);
        println!("{}", pretty_print_program(ctx.get_hlr_program().unwrap()));

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("x", Type::Int), hlr_const(10, Type::Int)),
                hlr_vardef(
                    hlr_var("cond", Type::Bool),
                    hlr_binop(
                        BinaryOperator::LessThan,
                        hlr_var_expr("x", Type::Int),
                        hlr_const(5, Type::Int),
                        Type::Bool,
                    ),
                ),
                hlr_if(
                    // Then branch of outer if
                    hlr_binop(
                        BinaryOperator::Equals,
                        hlr_var_expr("cond", Type::Bool),
                        hlr_const(0, Type::Int),
                        Type::Bool,
                    ),
                    vec![hlr_vardef(
                        hlr_var("result", Type::Char),
                        hlr_const(3, Type::Int),
                    )],
                    vec![
                        hlr_vardef(
                            hlr_var("cond2", Type::Bool),
                            hlr_binop(
                                BinaryOperator::LessThan,
                                hlr_var_expr("x", Type::Int),
                                hlr_const(15, Type::Int),
                                Type::Bool,
                            ),
                        ),
                        hlr_if(
                            hlr_binop(
                                BinaryOperator::Equals,
                                hlr_var_expr("cond2", Type::Bool),
                                hlr_const(0, Type::Int),
                                Type::Bool,
                            ),
                            // Then branch of inner if
                            vec![hlr_assign(
                                hlr_var_target("result", Type::Char),
                                hlr_const(2, Type::Int),
                            )],
                            // Else branch of inner if
                            vec![hlr_assign(
                                hlr_var_target("result", Type::Char),
                                hlr_const(1, Type::Int),
                            )],
                        ),
                    ],
                    // Else branch of outer if
                ),
                hlr_output(hlr_var_expr("result", Type::Char)),
            ],
        )]);
        pretty_print_program(ctx.get_hlr_program().unwrap());
        /*
        assert_eq!(
            pretty_print_program(&expected),
        );
        */

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected)
    }
}
