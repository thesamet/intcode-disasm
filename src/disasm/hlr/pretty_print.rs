use super::ast::{
    BinaryOperator, HlrAssignmentTarget, HlrExpression, HlrFunction, HlrProgram, HlrStatement,
    HlrVariable, UnaryOperator,
};
use crate::derive_display;
use crate::disasm::v3::common::formatting::colors::SemanticColor;
use crate::disasm::v3::common::formatting::pretty_print_framework::{
    ContextualPrettyPrint, FormattingContext,
};
use crate::disasm::v3::type_inference::Type;
use colored::Colorize;
use itertools::Itertools;

// Precedence values for operators (higher = binds tighter)
fn binary_op_precedence(op: &BinaryOperator) -> u8 {
    match op {
        BinaryOperator::Equals | BinaryOperator::NotEquals => 1,
        BinaryOperator::LessThan
        | BinaryOperator::LessThanOrEqual
        | BinaryOperator::GreaterThan
        | BinaryOperator::GreaterThanOrEqual => 2,
        BinaryOperator::Add | BinaryOperator::Sub => 3,
        BinaryOperator::Mul => 4,
    }
}

fn unary_op_precedence(_op: &UnaryOperator) -> u8 {
    5 // Highest precedence for unary operators
}

fn line(s: &str, ctx: &FormattingContext) -> String {
    let clear_to_end_code = "\x1b[K\n";
    match ctx.colors() {
        Some(colors) => format!("{}{s}{clear_to_end_code}", ctx.indent_str())
            .on_color(colors.bg_color)
            .to_string(),
        None => s.to_string(),
    }
}

// Implement ContextualPrettyPrint for binary operators
impl ContextualPrettyPrint for BinaryOperator {
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        let op_str = match self {
            BinaryOperator::Add => "+",
            BinaryOperator::Mul => "*",
            BinaryOperator::Sub => "-",
            BinaryOperator::LessThan => "<",
            BinaryOperator::LessThanOrEqual => "<=",
            BinaryOperator::Equals => "==",
            BinaryOperator::NotEquals => "!=",
            BinaryOperator::GreaterThan => ">",
            BinaryOperator::GreaterThanOrEqual => ">=",
        };
        ctx.format(op_str, SemanticColor::Operator).to_string()
    }
}

// Implement ContextualPrettyPrint for unary operators
impl ContextualPrettyPrint for UnaryOperator {
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        let op_str = match self {
            UnaryOperator::LogicalNot => "!",
            UnaryOperator::Minus => "-",
        };
        ctx.format(op_str, SemanticColor::Operator).to_string()
    }
}

// Implement ContextualPrettyPrint for variables
impl ContextualPrettyPrint for HlrVariable {
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        ctx.format(&self.name, SemanticColor::Variable).to_string()
    }
}

// Function to format a type with context
fn format_type(ty: &Type, ctx: &FormattingContext) -> String {
    match ty {
        Type::Int => ctx.format("int", SemanticColor::Type).to_string(),
        Type::Bool => ctx.format("bool", SemanticColor::Type).to_string(),
        Type::Char => ctx.format("char", SemanticColor::Type).to_string(),
        Type::Pointer(inner_ty) => {
            format!("{}{}", ctx.fmt_star(), format_type(inner_ty, ctx))
        }
        Type::Tuple(types) => {
            let types_str = types
                .iter()
                .map(|t| format_type(t, ctx))
                .join(&ctx.fmt_comma().to_string());
            format!(
                "{}Tuple{}{}{}{}",
                ctx.format("", SemanticColor::Type),
                ctx.fmt_open_paren(),
                types_str,
                ctx.fmt_close_paren(),
                ctx.format("", SemanticColor::Type)
            )
        }
        _ => ctx.format(ty.to_string(), SemanticColor::Type).to_string(),
    }
}

// Implement ContextualPrettyPrint for assignment targets
impl ContextualPrettyPrint for HlrAssignmentTarget {
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        match self {
            HlrAssignmentTarget::Variable(var) => {
                format!("{}", var.pretty_print_with_context(ctx))
            }
            HlrAssignmentTarget::Deref(expr) => {
                format!(
                    "{}{}{}",
                    ctx.fmt_star(),
                    expr.pretty_print_with_context(ctx),
                    ctx.format(" ", SemanticColor::LowPrio)
                )
            }
            HlrAssignmentTarget::Ignored => "_".to_string(),
        }
    }
}

// Remove existing Display implementation for HlrExpression from ast.rs
// This one will take precedence
#[allow(unused_imports)]
use std::fmt::Display;

// Implement ContextualPrettyPrint for expressions
impl ContextualPrettyPrint for HlrExpression {
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        match self {
            HlrExpression::Variable(var) => var.pretty_print_with_context(ctx),

            HlrExpression::Constant(val, _) => ctx
                .format(val.to_string(), SemanticColor::Constant)
                .to_string(),

            HlrExpression::BinaryOp {
                op,
                left,
                right,
                result_type: _, // Ignoring result_type for pretty printing
            } => {
                let op_prec = binary_op_precedence(op);
                let op_display = format!(" {} ", op.pretty_print_with_context(ctx));

                let left_str = left.pretty_print_with_context(&ctx.with_precedence(op_prec));
                let right_str = right.pretty_print_with_context(&ctx.with_precedence(op_prec));

                let result = format!("{}{}{}", left_str, op_display, right_str);

                // Add parentheses if needed based on precedence
                if let Some(parent_prec) = ctx.parent_precedence {
                    if parent_prec > op_prec {
                        return format!(
                            "{}{}{}",
                            ctx.fmt_open_paren(),
                            result,
                            ctx.fmt_close_paren()
                        );
                    }
                }
                result
            }

            HlrExpression::UnaryOperator { op, expr } => {
                let op_prec = unary_op_precedence(op);
                let op_str = op.pretty_print_with_context(ctx);
                let expr_str = expr.pretty_print_with_context(&ctx.with_precedence(op_prec));

                let result = format!("{}{}", op_str, expr_str);

                // Add parentheses if needed
                if let Some(parent_prec) = ctx.parent_precedence {
                    if parent_prec > op_prec {
                        return format!(
                            "{}{}{}",
                            ctx.fmt_open_paren(),
                            result,
                            ctx.fmt_close_paren()
                        );
                    }
                }
                result
            }

            HlrExpression::FunctionCall(func_expr, args) => {
                let func_name = match &**func_expr {
                    HlrExpression::Constant(id, _) => ctx
                        .format(format!("fu{}", id), SemanticColor::Function)
                        .to_string(),
                    _ => func_expr.pretty_print_with_context(ctx),
                };

                let args_str = args
                    .iter()
                    .map(|arg| arg.pretty_print_with_context(ctx))
                    .join(&ctx.fmt_comma().to_string());

                format!(
                    "{}{}{}{}",
                    func_name,
                    ctx.fmt_open_paren(),
                    args_str,
                    ctx.fmt_close_paren()
                )
            }

            HlrExpression::Input() => ctx.format("input()", SemanticColor::Keyword).to_string(),

            HlrExpression::Deref(expr) => {
                format!("{}{}", ctx.fmt_star(), expr.pretty_print_with_context(ctx))
            }

            HlrExpression::StaticFunctionReference(name) => {
                format!(
                    "{}{}",
                    ctx.fmt_ampersand(),
                    ctx.format(name, SemanticColor::Variable)
                )
            }
        }
    }
}
// Format a variable declaration with type
fn format_variable_decl(var: &HlrVariable, ctx: &FormattingContext) -> String {
    format!(
        "{}: {}",
        var.pretty_print_with_context(ctx),
        format_type(&var.type_info, ctx)
    )
}

// Implement ContextualPrettyPrint for statements
impl ContextualPrettyPrint for HlrStatement {
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        match self {
            HlrStatement::VarDef(vars, expr) => {
                let vars_formatted = if vars.len() == 1 {
                    format_variable_decl(&vars[0], ctx)
                } else {
                    let vars_str = vars
                        .iter()
                        .map(|var| format_variable_decl(var, ctx))
                        .join(&ctx.fmt_comma().to_string());

                    format!(
                        "{}{}{}",
                        ctx.fmt_open_paren(),
                        vars_str,
                        ctx.fmt_close_paren()
                    )
                };

                line(
                    &format!(
                        "{} {} {} {}{}",
                        ctx.format("let", SemanticColor::Keyword),
                        vars_formatted,
                        ctx.fmt_eq(),
                        expr.pretty_print_with_context(ctx),
                        ctx.fmt_semicolon()
                    ),
                    ctx,
                )
            }

            HlrStatement::Assignment(target, expr) => line(
                &format!(
                    "{} {} {}{}",
                    target.pretty_print_with_context(ctx),
                    ctx.fmt_eq(),
                    expr.pretty_print_with_context(ctx),
                    ctx.fmt_semicolon()
                ),
                ctx,
            ),

            HlrStatement::Loop(body) => {
                let loop_start = line(
                    &format!(
                        "{} {}",
                        ctx.format("loop", SemanticColor::Keyword),
                        ctx.fmt_open_brace()
                    ),
                    ctx,
                );

                let body_lines = body
                    .iter()
                    .map(|stmt| stmt.pretty_print_with_context(&ctx.indented()))
                    .join("");

                let loop_end = line(&format!("{}", ctx.fmt_close_brace()), ctx);

                format!("{}{}{}", loop_start, body_lines, loop_end)
            }

            HlrStatement::If(cond, true_branch, false_branch) => {
                let if_start = line(
                    &format!(
                        "{} {} {}",
                        ctx.format("if", SemanticColor::Keyword),
                        cond.pretty_print_with_context(ctx),
                        ctx.fmt_open_brace()
                    ),
                    ctx,
                );

                let true_branch_lines = true_branch
                    .iter()
                    .map(|stmt| stmt.pretty_print_with_context(&ctx.indented()))
                    .join("");

                if false_branch.is_empty() {
                    let if_end = line(&format!("{}", ctx.fmt_close_brace()), ctx);
                    format!("{}{}{}", if_start, true_branch_lines, if_end)
                } else {
                    let else_start = line(
                        &format!(
                            "{} {} {}",
                            ctx.fmt_close_brace(),
                            ctx.format("else", SemanticColor::Keyword),
                            ctx.fmt_open_brace()
                        ),
                        ctx,
                    );

                    let false_branch_lines = false_branch
                        .iter()
                        .map(|stmt| stmt.pretty_print_with_context(&ctx.indented()))
                        .join("");

                    let else_end = line(&format!("{}", ctx.fmt_close_brace()), ctx);

                    format!(
                        "{}{}{}{}{}",
                        if_start, true_branch_lines, else_start, false_branch_lines, else_end
                    )
                }
            }

            HlrStatement::While(cond, body) => {
                let while_start = line(
                    &format!(
                        "{} {} {}",
                        ctx.format("while", SemanticColor::Keyword),
                        cond.pretty_print_with_context(ctx),
                        ctx.fmt_open_brace()
                    ),
                    ctx,
                );

                let body_lines = body
                    .iter()
                    .map(|stmt| stmt.pretty_print_with_context(&ctx.indented()))
                    .join("");

                let while_end = line(&format!("{}", ctx.fmt_close_brace()), ctx);

                format!("{}{}{}", while_start, body_lines, while_end)
            }

            HlrStatement::DoWhile(body, cond) => {
                let do_start = line(
                    &format!(
                        "{} {}",
                        ctx.format("do", SemanticColor::Keyword),
                        ctx.fmt_open_brace()
                    ),
                    ctx,
                );

                let body_lines = body
                    .iter()
                    .map(|stmt| stmt.pretty_print_with_context(&ctx.indented()))
                    .join("");

                let do_end = line(
                    &format!(
                        "{} {} {}{}",
                        ctx.fmt_close_brace(),
                        ctx.format("while", SemanticColor::Keyword),
                        cond.pretty_print_with_context(ctx),
                        ctx.fmt_semicolon()
                    ),
                    ctx,
                );

                format!("{}{}{}", do_start, body_lines, do_end)
            }

            HlrStatement::Break => line(
                &format!(
                    "{}{}",
                    ctx.format("break", SemanticColor::Keyword),
                    ctx.fmt_semicolon()
                ),
                ctx,
            ),

            HlrStatement::Continue => line(
                &format!(
                    "{}{}",
                    ctx.format("continue", SemanticColor::Keyword),
                    ctx.fmt_semicolon()
                ),
                ctx,
            ),

            HlrStatement::Return(exprs) => {
                let exprs_str = match exprs.len() {
                    0 => "".to_string(),
                    1 => format!(" {}", exprs[0].pretty_print_with_context(ctx)),
                    _ => {
                        let exprs_joined = exprs
                            .iter()
                            .map(|expr| expr.pretty_print_with_context(ctx))
                            .join(&ctx.fmt_comma().to_string());

                        format!(
                            " {}{}{}",
                            ctx.fmt_open_paren(),
                            exprs_joined,
                            ctx.fmt_close_paren()
                        )
                    }
                };

                line(
                    &format!(
                        "{}{}{}",
                        ctx.format("return", SemanticColor::Keyword),
                        exprs_str,
                        ctx.fmt_semicolon()
                    ),
                    ctx,
                )
            }

            HlrStatement::Halt => line(
                &format!(
                    "{}{}",
                    ctx.format("halt", SemanticColor::Keyword),
                    ctx.fmt_semicolon()
                ),
                ctx,
            ),

            HlrStatement::Output(expr) => line(
                &format!(
                    "{}{}{}{}{}",
                    ctx.format("output", SemanticColor::Keyword),
                    ctx.fmt_open_paren(),
                    expr.pretty_print_with_context(ctx),
                    ctx.fmt_close_paren(),
                    ctx.fmt_semicolon()
                ),
                ctx,
            ),

            HlrStatement::Nop => line(
                &format!("{}", ctx.format("nop", SemanticColor::Keyword)),
                ctx,
            ),
        }
    }
}

// Format function signature with args and return type
fn format_function_signature(func: &HlrFunction, ctx: &FormattingContext) -> String {
    // Format arguments
    let args_str = func
        .args
        .iter()
        .map(|arg| {
            format!(
                "{}: {}",
                arg.pretty_print_with_context(ctx),
                format_type(&arg.type_info, ctx)
            )
        })
        .join(&ctx.fmt_comma().to_string());

    // Format return type
    let ret_str = match func.return_type.len() {
        0 => ctx.format("void", SemanticColor::Type).to_string(),
        1 => format_type(&func.return_type[0].type_info, ctx),
        _ => {
            let types_str = func
                .return_type
                .iter()
                .map(|ret| format_type(&ret.type_info, ctx))
                .join(&ctx.fmt_comma().to_string());

            format!(
                "{}{}{}",
                ctx.fmt_open_paren(),
                types_str,
                ctx.fmt_close_paren()
            )
        }
    };

    // Debug information should only be used during development
    #[cfg(test)]
    {
        eprintln!(
            "FUNC SIGNATURE: args={:?}, ret_type={:?}",
            func.args.iter().map(|a| &a.name).collect::<Vec<_>>(),
            func.return_type.iter().map(|r| &r.name).collect::<Vec<_>>()
        );
    }

    // Complete signature
    format!(
        "{} {}({}){}{} {}",
        ctx.format("function", SemanticColor::Keyword),
        ctx.format(&func.name, SemanticColor::Function),
        args_str,
        ctx.format(" -> ", SemanticColor::LowPrio),
        ret_str,
        ctx.fmt_open_brace()
    )
}

// Implement ContextualPrettyPrint for functions
impl ContextualPrettyPrint for HlrFunction {
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        let signature = format_function_signature(self, ctx);
        let signature_line = line(&signature, &ctx);

        let body_lines = self
            .body
            .iter()
            .map(|stmt| stmt.pretty_print_with_context(&ctx.indented()))
            .join("");

        let end_line = line(&format!("{}", ctx.fmt_close_brace()), ctx);

        format!("{}{}{}", signature_line, body_lines, end_line)
    }
}

// Implement ContextualPrettyPrint for programs
impl ContextualPrettyPrint for HlrProgram {
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        self.functions
            .iter()
            .sorted_by_key(|f| f.original_id)
            .map(|func| func.pretty_print_with_context(ctx))
            .join(&line("", ctx))
    }
}

// Apply the display macros
derive_display!(HlrProgram);
derive_display!(HlrFunction);
derive_display!(HlrStatement);
derive_display!(HlrExpression);
derive_display!(HlrAssignmentTarget);

// Public pretty printing functions for use in the CLI
pub fn pretty_print_hlr(program: &HlrProgram) -> String {
    program.pretty_print()
}

pub fn pretty_print_hlr_with_config(
    program: &HlrProgram,
    config: &crate::disasm::v3::common::formatting::pretty_print_framework::PrettyPrintConfig,
) -> String {
    program.pretty_print_with_config(config)
}

pub fn pretty_print_hlr_stdout(program: &HlrProgram) {
    println!("{}", pretty_print_hlr(program));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::hlr::ast::test_utils::*;
    use crate::disasm::v3::common::formatting::colors::Colors;
    use crate::disasm::v3::common::formatting::pretty_print_framework::PrettyPrintConfig;
    use crate::disasm::v3::type_inference::Type;

    #[test]
    fn test_pretty_print_program() {
        // Create variables for the function
        let x_var = hlr_var("x", Type::Int);
        let y_var = hlr_var("y", Type::Int);

        // Create a custom function
        let mut func = hlr_function(0, vec![]);
        func.name = "test_func".to_string();
        func.args = vec![x_var.clone()];
        func.return_type = vec![y_var.clone()];

        // Add statements to the function body
        func.body = vec![
            hlr_vardef(y_var.clone(), hlr_const(42, Type::Int)),
            hlr_if(
                hlr_binop(
                    BinaryOperator::LessThan,
                    hlr_var_expr("y", Type::Int),
                    hlr_const(100, Type::Int),
                    Type::Bool,
                ),
                vec![hlr_assign(
                    hlr_var_target("y", Type::Int),
                    hlr_binop(
                        BinaryOperator::Add,
                        hlr_var_expr("y", Type::Int),
                        hlr_const(1, Type::Int),
                        Type::Int,
                    ),
                )],
                vec![],
            ),
            hlr_return(vec![hlr_var_expr("y", Type::Int)]),
        ];

        let program = hlr_program(vec![func]);

        // Use nocolor() to get output without ANSI color codes for testing
        let default_output = program.nocolor();
        #[cfg(test)]
        println!("DEFAULT OUTPUT (no color):\n{}", default_output);

        // Check for function name and other elements
        assert!(default_output.contains("function test_func"));
        assert!(default_output.contains("let y: int = 42"));
        assert!(default_output.contains("if y < 100"));
        assert!(default_output.contains("y ="));
        assert!(default_output.contains("y + 1"));
        assert!(default_output.contains("return y"));

        // Test with no colors - already using nocolor above
        // No need to test the same thing twice
        assert!(default_output.contains("function test_func"));
        assert!(default_output.contains("(x: int)"));
        assert!(default_output.contains("-> int"));

        // We can still test with a theme, but don't check the output content
        let themed_config = PrettyPrintConfig::default().with_colors(Colors::blue_accent_theme());
        let _themed_output = pretty_print_hlr_with_config(&program, &themed_config);
        // Just make sure it produces output without errors
    }

    #[test]
    fn test_pretty_print_expressions() {
        // Test binary operator precedence
        let expr1 = hlr_binop(
            BinaryOperator::Add,
            hlr_const(1, Type::Int),
            hlr_binop(
                BinaryOperator::Mul,
                hlr_const(2, Type::Int),
                hlr_const(3, Type::Int),
                Type::Int,
            ),
            Type::Int,
        );

        // Use nocolor() for simpler testing
        let output = expr1.nocolor();

        // Should not add unnecessary parentheses because multiplication has higher precedence
        assert_eq!(output, "1 + 2 * 3");

        // Test with parentheses needed
        let expr2 = hlr_binop(
            BinaryOperator::Mul,
            hlr_binop(
                BinaryOperator::Add,
                hlr_const(1, Type::Int),
                hlr_const(2, Type::Int),
                Type::Int,
            ),
            hlr_const(3, Type::Int),
            Type::Int,
        );

        let output2 = expr2.nocolor();
        // Should add parentheses because addition has lower precedence
        assert_eq!(output2, "(1 + 2) * 3");
    }

    #[test]
    fn test_pretty_print_statements() {
        // Test variable declaration
        let var_def = hlr_vardef(hlr_var("x", Type::Int), hlr_const(42, Type::Int));

        // Use nocolor() for consistent testing without ANSI codes
        let output = var_def.nocolor();

        assert!(output.contains("let x: int = 42;"));

        // Test if statement
        let if_stmt = hlr_if(
            hlr_binop(
                BinaryOperator::Equals,
                hlr_var_expr("x", Type::Int),
                hlr_const(42, Type::Int),
                Type::Bool,
            ),
            vec![hlr_output(hlr_const(1, Type::Int))],
            vec![hlr_output(hlr_const(0, Type::Int))],
        );

        let output = if_stmt.nocolor();
        assert!(output.contains("if x == 42 {"));
        assert!(output.contains("output(1);"));
        assert!(output.contains("} else {"));
        assert!(output.contains("output(0);"));
    }
}
