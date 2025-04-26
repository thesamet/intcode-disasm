use std::fmt::Display;

use crate::disasm::v2::{model::FunctionId, type_inference::types::Type};

#[derive(Debug, Clone)]
pub struct HlrVariable {
    pub name: String,
    pub type_info: Type,
}

#[derive(Debug, Clone)]
pub struct HlrFunction {
    pub original_id: FunctionId,
    pub name: String,
    pub args: Vec<Type>,
    pub return_type: Vec<Type>,
    pub body: Vec<HlrStatement>,
}

#[derive(Debug, Clone)]
pub enum HlrStatement {
    Assignment(HlrVariable, HlrExpression),
    Loop(Vec<HlrStatement>),
    If(HlrExpression, Vec<HlrStatement>, Vec<HlrStatement>),
    While(HlrExpression, Vec<HlrStatement>),
    Break,
    Continue,
    Return(Vec<HlrExpression>),
    Halt,
    Output(HlrExpression),
}

#[derive(Debug, Clone)]
pub struct HlrProgram {
    pub functions: Vec<HlrFunction>,
    pub globals: Vec<HlrVariable>,
}

#[derive(Debug, Clone)]
pub enum HlrExpression {
    Variable(HlrVariable),
    Constant(i128, Type),
    BinaryOp {
        op: BinaryOperator,
        left: Box<HlrExpression>,
        right: Box<HlrExpression>,
        result_type: Type,
    },
    FunctionCall(Box<HlrExpression>),
    Tuple(Vec<HlrExpression>),
    Input(),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOperator {
    Add,
    Mul,
    Sub,
    LessThan,
    Equals,
    GreaterThan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOperator {
    LogicalNot,
    Minus,
}

use crate::disasm::code_printer::{CodePrinter, CodeWriter};
use crate::line;

pub fn pretty_print_program(program: &HlrProgram) -> String {
    let mut printer = CodePrinter::new();
    pretty_print_program_impl(&mut printer, program);
    printer.result()
}

fn pretty_print_program_impl<F>(writer: &mut F, program: &HlrProgram)
where
    F: CodeWriter,
{
    for func in &program.functions {
        pretty_print_function(writer, func);
        writer.line("")
    }
}

fn pretty_print_function<F>(writer: &mut F, func: &HlrFunction)
where
    F: CodeWriter,
{
    let args_str = func
        .args
        .iter()
        .enumerate()
        .map(|(i, arg)| format!("arg{}: {}", i, arg)) // Assuming simple arg names for now
        .collect::<Vec<_>>()
        .join(", ");

    let ret_str = func
        .return_type
        .iter()
        .enumerate()
        .map(|(i, ret)| format!("ret{}: {}", i, ret)) // Assuming simple ret names for now
        .collect::<Vec<_>>()
        .join(", ");

    let signature = if !func.args.is_empty() && !func.return_type.is_empty() {
        format!("function {}({}) -> ({}) {{", func.name, args_str, ret_str)
    } else if !func.args.is_empty() {
        format!("function {}({}) {{", func.name, args_str)
    } else if !func.return_type.is_empty() {
        format!("function {}() -> ({}) {{", func.name, ret_str)
    } else {
        format!("function {}() {{", func.name)
    };

    line!(writer, "{}", signature);
    pretty_print_statements(&mut writer.indented(), &func.body);
    line!(writer, "}}");
}

fn pretty_print_statement<F>(writer: &mut F, stmt: &HlrStatement)
where
    F: CodeWriter,
{
    match stmt {
        HlrStatement::Assignment(var, expr) => {
            line!(writer, "{} = {};", var.name, pretty_print_expression(expr));
        }
        HlrStatement::Loop(body) => {
            line!(writer, "loop {{");
            pretty_print_statements(&mut writer.indented(), body);
            line!(writer, "}}");
        }
        HlrStatement::If(cond, true_branch, false_branch) => {
            line!(writer, "if {} {{", pretty_print_expression(cond));
            pretty_print_statements(&mut writer.indented(), true_branch);
            if false_branch.is_empty() {
                line!(writer, "}}");
            } else {
                line!(writer, "}} else {{");
                pretty_print_statements(&mut writer.indented(), false_branch);
                line!(writer, "}}");
            }
        }
        HlrStatement::While(cond, body) => {
            line!(writer, "while {} {{", pretty_print_expression(cond));
            pretty_print_statements(&mut writer.indented(), body);
            line!(writer, "}}");
        }
        HlrStatement::Break => line!(writer, "break;"),
        HlrStatement::Continue => line!(writer, "continue;"),
        HlrStatement::Return(exprs) => {
            line!(writer, "return {};", pretty_print_expressions(exprs));
        }
        HlrStatement::Halt => line!(writer, "halt;"),
        HlrStatement::Output(expr) => line!(writer, "output {};", pretty_print_expression(expr)),
    }
}

fn pretty_print_statements<F>(writer: &mut F, stmts: &[HlrStatement])
where
    F: CodeWriter,
{
    for stmt in stmts {
        pretty_print_statement(writer, stmt);
    }
}

// Expressions are usually part of a line, so returning String is often simpler
// than passing the writer down. Indentation is handled by the statement printer.
fn pretty_print_expression(expr: &HlrExpression) -> String {
    match expr {
        HlrExpression::Variable(var) => var.name.clone(),
        HlrExpression::Constant(val, ty) => format!("{}: {}", val, ty),
        HlrExpression::BinaryOp {
            op,
            left,
            right,
            result_type: _, // Type hints can sometimes be omitted for brevity if desired
        } => format!(
            "({} {} {})", // Removed type hint for potentially cleaner output
            pretty_print_expression(left),
            op,
            pretty_print_expression(right),
            // result_type // Add back if type hint is desired: ": {}", result_type
        ),
        HlrExpression::FunctionCall(func_expr) => {
            // Assuming function calls take a tuple of arguments, need adjustment if call structure changes
            // For now, just printing the expression being called.
            format!("{}()", pretty_print_expression(func_expr)) // Simplified, needs args if Hlr supports them
        }
        HlrExpression::Tuple(exprs) => {
            format!("({})", pretty_print_expressions(exprs))
        }
        HlrExpression::Input() => "input()".to_string(),
    }
}

fn pretty_print_expressions(exprs: &[HlrExpression]) -> String {
    exprs
        .iter()
        .map(pretty_print_expression)
        .collect::<Vec<_>>()
        .join(", ")
}

impl Display for BinaryOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryOperator::Add => write!(f, "+"),
            BinaryOperator::Mul => write!(f, "*"),
            BinaryOperator::Sub => write!(f, "-"),
            BinaryOperator::LessThan => write!(f, "<"),
            BinaryOperator::Equals => write!(f, "=="),
            BinaryOperator::GreaterThan => write!(f, ">"),
        }
    }
}

impl Display for UnaryOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnaryOperator::LogicalNot => write!(f, "!"),
            UnaryOperator::Minus => write!(f, "-"),
        }
    }
}

impl Display for HlrVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Usually variable usage doesn't include the type, only declaration does.
        // Adjust if type annotation on usage is desired.
        write!(f, "{}", self.name)
        // write!(f, "{}: {}", self.name, self.type_info) // Use this if type is needed
    }
}
