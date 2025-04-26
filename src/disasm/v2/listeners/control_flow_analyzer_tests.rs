use std::collections::HashMap;

use crate::disasm::hlr::ast::{
    BinaryOperator, HlrAssignmentTarget, HlrExpression, HlrFunction, HlrProgram, HlrStatement,
    HlrVariable,
};
use crate::disasm::v2::dispatching::EventPublisher;
use crate::disasm::v2::events::Event;
use crate::disasm::v2::listeners::{
    control_flow_analyzer::ControlFlowStructureRecoveryListener,
    control_flow_graph_builder::ControlFlowGraphBuilder, data_flow_analyzer::DataFlowAnalyzer,
    function_call_analyzer::FunctionCallAnalyzer, image_scanner::ImageScanner,
    ssa_converter::SsaConverter, variable_analyzer::VariableAnalyzer,
};
use crate::disasm::v2::type_inference::analyzer::TypeInferenceAnalyzer;
use crate::disasm::v2::model::{FunctionId, ProgramModel};
use crate::disasm::v2::type_inference::types::Type;

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

struct VariableMapping {
    actual_to_expected: HashMap<String, String>,
    expected_to_actual: HashMap<String, String>,
}

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
    ) -> bool {
        // Types must match
        if actual_type != expected_type {
            return false;
        }

        // Check if we already have a mapping
        if let Some(mapped_expected) = self.actual_to_expected.get(actual_name) {
            return mapped_expected == expected_name;
        }

        if let Some(mapped_actual) = self.expected_to_actual.get(expected_name) {
            return mapped_actual == actual_name;
        }

        // Create a new mapping
        self.actual_to_expected
            .insert(actual_name.to_string(), expected_name.to_string());
        self.expected_to_actual
            .insert(expected_name.to_string(), actual_name.to_string());
        true
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

fn hlr_assign(target: HlrAssignmentTarget, expr: HlrExpression) -> HlrStatement {
    HlrStatement::Assignment(target, expr)
}

fn hlr_var_target(name: &str, typ: Type) -> HlrAssignmentTarget {
    HlrAssignmentTarget::Variable(hlr_var(name, typ))
}

fn hlr_deref_target(expr: HlrExpression) -> HlrAssignmentTarget {
    HlrAssignmentTarget::Deref(expr)
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

fn hlr_function_call(func_expr: HlrExpression) -> HlrExpression {
    HlrExpression::FunctionCall(Box::new(func_expr))
}

// Assertion functions
fn assert_hlr_programs_equivalent(actual: &HlrProgram, expected: &HlrProgram) {
    assert_eq!(
        actual.functions.len(),
        expected.functions.len(),
        "Different number of functions"
    );

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
    assert_eq!(
        actual_funcs.keys().collect::<Vec<_>>(),
        expected_funcs.keys().collect::<Vec<_>>(),
        "Function IDs don't match"
    );

    // Compare functions with the same ID
    for (id, expected_func) in expected_funcs.iter() {
        let actual_func = actual_funcs.get(id).unwrap();
        let mut mapping = VariableMapping::new();
        assert_statements_equivalent(
            &actual_func.body,
            &expected_func.body,
            &mut mapping,
            &format!("Function[{}]", id),
        );
    }
}

fn assert_statements_equivalent(
    actual: &[HlrStatement],
    expected: &[HlrStatement],
    mapping: &mut VariableMapping,
    context: &str,
) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "{}: Different number of statements: actual={}, expected={}",
        context,
        actual.len(),
        expected.len()
    );

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
                );
                assert_expressions_equivalent(
                    actual_expr,
                    expected_expr,
                    mapping,
                    &format!("{}:Expression", stmt_context),
                );
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
                );
                assert_statements_equivalent(
                    actual_then,
                    expected_then,
                    mapping,
                    &format!("{}:ThenBranch", stmt_context),
                );
                assert_statements_equivalent(
                    actual_else,
                    expected_else,
                    mapping,
                    &format!("{}:ElseBranch", stmt_context),
                );
            }
            (HlrStatement::Loop(actual_body), HlrStatement::Loop(expected_body)) => {
                assert_statements_equivalent(
                    actual_body,
                    expected_body,
                    mapping,
                    &format!("{}:LoopBody", stmt_context),
                );
            }
            (HlrStatement::Output(actual_expr), HlrStatement::Output(expected_expr)) => {
                assert_expressions_equivalent(
                    actual_expr,
                    expected_expr,
                    mapping,
                    &format!("{}:Output", stmt_context),
                );
            }
            (HlrStatement::Return(actual_exprs), HlrStatement::Return(expected_exprs)) => {
                assert_eq!(
                    actual_exprs.len(),
                    expected_exprs.len(),
                    "{}:Return: expression count mismatch",
                    stmt_context
                );
                for (j, (a, e)) in actual_exprs.iter().zip(expected_exprs.iter()).enumerate() {
                    assert_expressions_equivalent(
                        a,
                        e,
                        mapping,
                        &format!("{}:Return[{}]", stmt_context, j),
                    );
                }
            }
            (HlrStatement::Halt, HlrStatement::Halt) => {}
            (HlrStatement::Continue, HlrStatement::Continue) => {}
            (HlrStatement::Break, HlrStatement::Break) => {}
            _ => {
                assert!(
                    false,
                    "{}:Statement types don't match: {:?} vs {:?}",
                    stmt_context, actual_stmt, expected_stmt
                );
            }
        }
    }
}

fn assert_targets_equivalent(
    actual: &HlrAssignmentTarget,
    expected: &HlrAssignmentTarget,
    mapping: &mut VariableMapping,
    context: &str,
) {
    match (actual, expected) {
        (
            HlrAssignmentTarget::Variable(actual_var),
            HlrAssignmentTarget::Variable(expected_var),
        ) => {
            assert_eq!(
                &actual_var.type_info, &expected_var.type_info,
                "{}:Variable types don't match: {:?} vs {:?}",
                context, actual_var.type_info, expected_var.type_info
            );

            let mapped = mapping.map_variable(
                &actual_var.name,
                &expected_var.name,
                &actual_var.type_info,
                &expected_var.type_info,
            );

            assert!(
                mapped,
                "{}:Variable name mapping inconsistent: '{}' was previously mapped to a different variable than '{}'",
                context, actual_var.name, expected_var.name
            );
        }
        (
            HlrAssignmentTarget::Deref(actual_expr),
            HlrAssignmentTarget::Deref(expected_expr),
        ) => {
            assert_expressions_equivalent(
                actual_expr,
                expected_expr,
                mapping,
                &format!("{}:Deref", context),
            );
        }
        (HlrAssignmentTarget::Ignored, HlrAssignmentTarget::Ignored) => {}
        _ => {
            assert!(
                false,
                "{}:Assignment target types don't match: {:?} vs {:?}",
                context, actual, expected
            );
        }
    }
}

fn assert_expressions_equivalent(
    actual: &HlrExpression,
    expected: &HlrExpression,
    mapping: &mut VariableMapping,
    context: &str,
) {
    match (actual, expected) {
        (HlrExpression::Variable(actual_var), HlrExpression::Variable(expected_var)) => {
            assert_eq!(
                &actual_var.type_info, &expected_var.type_info,
                "{}:Variable types don't match: {:?} vs {:?}",
                context, actual_var.type_info, expected_var.type_info
            );

            let mapped = mapping.map_variable(
                &actual_var.name,
                &expected_var.name,
                &actual_var.type_info,
                &expected_var.type_info,
            );

            assert!(
                mapped,
                "{}:Variable name mapping inconsistent: '{}' was previously mapped to a different variable than '{}'",
                context, actual_var.name, expected_var.name
            );
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
            assert_eq!(
                actual_type, expected_type,
                "{}:Constant types don't match: {:?} vs {:?}",
                context, actual_type, expected_type
            );
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
            assert_eq!(
                actual_op, expected_op,
                "{}:Binary operators don't match: {:?} vs {:?}",
                context, actual_op, expected_op
            );
            assert_eq!(
                actual_type, expected_type,
                "{}:Result types don't match: {:?} vs {:?}",
                context, actual_type, expected_type
            );
            assert_expressions_equivalent(
                actual_left,
                expected_left,
                mapping,
                &format!("{}:Left", context),
            );
            assert_expressions_equivalent(
                actual_right,
                expected_right,
                mapping,
                &format!("{}:Right", context),
            );
        }
        (HlrExpression::Deref(actual_expr), HlrExpression::Deref(expected_expr)) => {
            assert_expressions_equivalent(
                actual_expr,
                expected_expr,
                mapping,
                &format!("{}:Deref", context),
            );
        }
        (HlrExpression::Input(), HlrExpression::Input()) => {}
        (HlrExpression::FunctionCall(actual_func), HlrExpression::FunctionCall(expected_func)) => {
            assert_expressions_equivalent(
                actual_func,
                expected_func,
                mapping,
                &format!("{}:FunctionCall", context),
            );
        }
        _ => {
            assert!(
                false,
                "{}:Expression types don't match: {:?} vs {:?}",
                context, actual, expected
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_sequential() {
        let assembly = r#"
            R += 100           # Initial R adjustment for main function
            [3] = 1 + 2        # Add 1+2 -> mem[3]
            [5] = 3 + 4        # Add 3+4 -> mem[5]
            halt               # Halt
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program using our helper functions
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_assign(
                    hlr_var_target("x", Type::Int),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_const(1, Type::Int),
                        hlr_const(2, Type::Int),
                        Type::Int,
                    ),
                ),
                hlr_assign(
                    hlr_var_target("y", Type::Int),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_const(3, Type::Int),
                        hlr_const(4, Type::Int),
                        Type::Int,
                    ),
                ),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected);
    }

    #[test]
    fn test_if_else() {
        let assembly = r#"
            R += 100           # Initial R adjustment for main function
            [3] = 1 + 2        # x = 1 + 2
            [4] = [3] == 3     # y = (x == 3)
            if [4] goto @then  # if y then goto label_then
            [7] = 5 + 6        # z = 5 + 6 (else branch)
            goto @end          # goto label_end
            @then:
            [7] = 7 + 8        # z = 7 + 8 (then branch)
            @end:
            halt               # Halt
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_assign(
                    hlr_var_target("x", Type::Int),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_const(1, Type::Int),
                        hlr_const(2, Type::Int),
                        Type::Int,
                    ),
                ),
                hlr_if(
                    hlr_binop(
                        BinaryOperator::Equals,
                        hlr_var_expr("x", Type::Int),
                        hlr_const(3, Type::Int),
                        Type::Bool,
                    ),
                    // Then branch
                    vec![hlr_assign(
                        hlr_var_target("z", Type::Int),
                        hlr_binop(
                            BinaryOperator::Add,
                            hlr_const(7, Type::Int),
                            hlr_const(8, Type::Int),
                            Type::Int,
                        ),
                    )],
                    // Else branch
                    vec![hlr_assign(
                        hlr_var_target("z", Type::Int),
                        hlr_binop(
                            BinaryOperator::Add,
                            hlr_const(5, Type::Int),
                            hlr_const(6, Type::Int),
                            Type::Int,
                        ),
                    )],
                ),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected);
    }

    #[test]
    fn test_loop() {
        let assembly = r#"
            R += 100           # Initial R adjustment for main function
            [1] = 0            # i = 0
            @loop_start:
            [2] = [1] < 10     # cond = (i < 10)
            if ![2] goto @loop_end  # if !cond goto loop_end
            [1] = [1] + 1      # i = i + 1
            goto @loop_start   # goto loop_start
            @loop_end:
            halt               # Halt
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_assign(hlr_var_target("i", Type::Int), hlr_const(0, Type::Int)),
                hlr_loop(vec![hlr_if(
                    hlr_binop(
                        BinaryOperator::LessThan,
                        hlr_var_expr("i", Type::Int),
                        hlr_const(10, Type::Int),
                        Type::Bool,
                    ),
                    // Then branch (loop body)
                    vec![
                        hlr_assign(
                            hlr_var_target("i", Type::Int),
                            hlr_binop(
                                BinaryOperator::Add,
                                hlr_var_expr("i", Type::Int),
                                hlr_const(1, Type::Int),
                                Type::Int,
                            ),
                        ),
                        HlrStatement::Continue,
                    ],
                    // Else branch (exit loop)
                    vec![HlrStatement::Break],
                )]),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected);
    }

    #[test]
    fn test_input_output() {
        let assembly = r#"
            R += 100           # Initial R adjustment for main function
            input([1])         # x = input()
            [2] = [1] + 10     # y = x + 10
            output([2])        # output(y)
            halt               # Halt
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_assign(hlr_var_target("x", Type::Int), hlr_input()),
                hlr_assign(
                    hlr_var_target("y", Type::Int),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_var_expr("x", Type::Int),
                        hlr_const(10, Type::Int),
                        Type::Int,
                    ),
                ),
                hlr_output(hlr_var_expr("y", Type::Int)),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected);
    }

    #[test]
    fn test_pointer_operations() {
        let assembly = r#"
            R += 100           # Initial R adjustment for main function
            ptr = 100          # ptr = 100 (address)
            [R+1] = *ptr       # x = *ptr (value at address 100)
            [R+2] = [R+1] + 5  # y = x + 5
            halt               # Halt
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_assign(
                    hlr_var_target("ptr", Type::Pointer(Box::new(Type::Int))),
                    hlr_const(100, Type::Int),
                ),
                hlr_assign(
                    hlr_var_target("x", Type::Int),
                    hlr_deref(hlr_var_expr("ptr", Type::Pointer(Box::new(Type::Int)))),
                ),
                hlr_assign(
                    hlr_var_target("y", Type::Int),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_var_expr("x", Type::Int),
                        hlr_const(5, Type::Int),
                        Type::Int,
                    ),
                ),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected);
    }

    #[test]
    fn test_function_call() {
        let assembly = r#"
            # Main function
            R += 100           # Initial R adjustment for main function
            [R+1] = 5          # Set argument
            [R] = @return_addr # Set return address
            goto @func         # Call function
            @return_addr:
            output([R+1])      # Output return value
            halt
            
            # Function that doubles its input
            @func:
            R += 3             # Adjust stack for local variables
            [R-2] = [R-4] * 2  # result = arg * 2
            [R+1] = [R-2]      # Set return value
            R -= 3             # Restore stack
            goto [R]           # Return
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program (simplified for this test)
        let expected = hlr_program(vec![
            hlr_function(
                0,
                vec![
                    hlr_assign(hlr_var_target("arg", Type::Int), hlr_const(5, Type::Int)),
                    hlr_assign(
                        HlrAssignmentTarget::Ignored,
                        hlr_function_call(hlr_var_expr("func", Type::Bool)),
                    ),
                    hlr_output(hlr_var_expr("result", Type::Int)),
                    HlrStatement::Halt,
                ],
            ),
            hlr_function(
                1,
                vec![
                    hlr_assign(
                        hlr_var_target("temp", Type::Int),
                        hlr_binop(
                            BinaryOperator::Mul,
                            hlr_var_expr("param", Type::Int),
                            hlr_const(2, Type::Int),
                            Type::Int,
                        ),
                    ),
                    hlr_return(vec![hlr_var_expr("temp", Type::Int)]),
                ],
            ),
        ]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected);
    }

    #[test]
    fn test_nested_if_else() {
        let assembly = r#"
            R += 100           # Initial R adjustment for main function
            [1] = 10           # x = 10
            [2] = [1] > 5      # cond1 = (x > 5)
            if ![2] goto @else_outer  # if !cond1 goto else_outer
            
            # Then branch of outer if
            [3] = [1] < 15     # cond2 = (x < 15)
            if ![3] goto @else_inner  # if !cond2 goto else_inner
            
            # Then branch of inner if
            [4] = 1            # result = 1
            goto @end_inner
            
            @else_inner:
            # Else branch of inner if
            [4] = 2            # result = 2
            
            @end_inner:
            goto @end_outer
            
            @else_outer:
            # Else branch of outer if
            [4] = 3            # result = 3
            
            @end_outer:
            output([4])        # output(result)
            halt
        "#;

        let ctx = TestContext::from_assembly(assembly);

        // Create expected HLR program
        let expected = hlr_program(vec![hlr_function(
            0,
            vec![
                hlr_assign(hlr_var_target("x", Type::Int), hlr_const(10, Type::Int)),
                hlr_if(
                    hlr_binop(
                        BinaryOperator::LessThan,
                        hlr_const(5, Type::Int),
                        hlr_var_expr("x", Type::Int),
                        Type::Bool,
                    ),
                    // Then branch of outer if
                    vec![hlr_if(
                        hlr_binop(
                            BinaryOperator::LessThan,
                            hlr_var_expr("x", Type::Int),
                            hlr_const(15, Type::Int),
                            Type::Bool,
                        ),
                        // Then branch of inner if
                        vec![hlr_assign(
                            hlr_var_target("result", Type::Int),
                            hlr_const(1, Type::Int),
                        )],
                        // Else branch of inner if
                        vec![hlr_assign(
                            hlr_var_target("result", Type::Int),
                            hlr_const(2, Type::Int),
                        )],
                    )],
                    // Else branch of outer if
                    vec![hlr_assign(
                        hlr_var_target("result", Type::Int),
                        hlr_const(3, Type::Int),
                    )],
                ),
                hlr_output(hlr_var_expr("result", Type::Int)),
                HlrStatement::Halt,
            ],
        )]);

        assert_hlr_programs_equivalent(ctx.get_hlr_program().unwrap(), &expected);
    }
}
