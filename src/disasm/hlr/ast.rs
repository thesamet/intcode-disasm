use std::fmt::Display;

use itertools::Itertools;

use crate::disasm::v2::{model::FunctionId, type_inference::types::Type};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HlrVariable {
    pub name: String,
    pub type_info: Type,
}

#[derive(Debug, Clone)]
pub struct HlrFunction {
    pub original_id: FunctionId,
    pub name: String,
    pub args: Vec<HlrVariable>,
    pub return_type: Vec<HlrVariable>,
    pub body: Vec<HlrStatement>,
}

#[derive(Debug, Clone)]
pub enum HlrAssignmentTarget {
    Variable(HlrVariable),
    VariablePack(Vec<HlrVariable>),
    Deref(HlrExpression),
    Ignored,
}

#[derive(Debug, Clone)]
pub enum HlrStatement {
    VarDef(Vec<HlrVariable>, HlrExpression),
    Assignment(HlrAssignmentTarget, HlrExpression),
    Loop(Vec<HlrStatement>),
    If(HlrExpression, Vec<HlrStatement>, Vec<HlrStatement>),
    While(HlrExpression, Vec<HlrStatement>),
    DoWhile(Vec<HlrStatement>, HlrExpression),
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HlrExpression {
    Variable(HlrVariable),
    Deref(Box<HlrExpression>),
    Constant(i128, Type),
    BinaryOp {
        op: BinaryOperator,
        left: Box<HlrExpression>,
        right: Box<HlrExpression>,
        result_type: Type,
    },
    UnaryOperator {
        op: UnaryOperator,
        expr: Box<HlrExpression>,
    },
    FunctionCall(Box<HlrExpression>, Vec<HlrExpression>),
    Tuple(Vec<HlrExpression>),
    Input(),
}

impl HlrExpression {
    pub fn logical_not(&self) -> Option<Self> {
        match self {
            HlrExpression::BinaryOp {
                op,
                left,
                right,
                result_type,
            } => Some(HlrExpression::BinaryOp {
                op: op.logical_not()?,
                left: left.clone(),
                right: right.clone(),
                result_type: result_type.clone(),
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOperator {
    Add,
    Mul,
    Sub,
    LessThan,
    Equals,
    NotEquals,
    GreaterThan,
}

impl BinaryOperator {
    pub fn logical_not(&self) -> Option<Self> {
        match self {
            BinaryOperator::Equals => Some(BinaryOperator::NotEquals),
            BinaryOperator::NotEquals => Some(BinaryOperator::Equals),
            _ => None,
        }
    }
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
    for func in program.functions.iter().sorted_by_key(|f| f.original_id) {
        pretty_print_function(writer, func);
        writer.line("")
    }
}

fn pretty_print_variable(var: &HlrVariable) -> String {
    format!("{}", var.name)
}

fn pretty_print_type(ty: &Type) -> String {
    format!("{}", ty)
}

fn pretty_print_function<F>(writer: &mut F, func: &HlrFunction)
where
    F: CodeWriter,
{
    let args_str = func
        .args
        .iter()
        .map(|arg| {
            format!(
                "{}: {}",
                pretty_print_variable(arg),
                pretty_print_type(&arg.type_info)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    let ret_str = match func.return_type.len() {
        0 => "void".to_string(),
        1 => pretty_print_type(&func.return_type[0].type_info),
        _ => format!(
            "({})",
            func.return_type
                .iter()
                .map(|ret| pretty_print_type(&ret.type_info))
                .join(", ")
        ),
    };

    let signature = format!("function {}({}) -> {} {{", func.name, args_str, ret_str);

    line!(writer, "{}", signature);
    pretty_print_statements(&mut writer.indented(), &func.body);
    line!(writer, "}}");
}

fn pretty_print_statement<F>(writer: &mut F, stmt: &HlrStatement)
where
    F: CodeWriter,
{
    match stmt {
        HlrStatement::VarDef(vars, expr) => {
            let e = if vars.len() == 1 {
                format!(
                    "{}: {}",
                    pretty_print_variable(&vars[0]),
                    pretty_print_type(&vars[0].type_info),
                )
            } else {
                let vars = vars
                    .iter()
                    .map(|var| {
                        format!(
                            "{}: {}",
                            pretty_print_variable(var),
                            pretty_print_type(&var.type_info),
                        )
                    })
                    .join(", ");
                format!("({})", vars)
            };
            line!(writer, "let {} = {};", e, pretty_print_expression(expr));
        }
        HlrStatement::Assignment(target, expr) => {
            let target = match target {
                HlrAssignmentTarget::Variable(var) => format!("{} = ", var.name),
                HlrAssignmentTarget::VariablePack(..) => panic!("Not implemented"),
                HlrAssignmentTarget::Deref(expr) => {
                    format!("*{} = ", pretty_print_expression(expr))
                }
                HlrAssignmentTarget::Ignored => "".to_string(),
            };
            line!(writer, "{}{};", target, pretty_print_expression(expr));
        }
        HlrStatement::Loop(body) => {
            line!(writer, "loop {{");
            pretty_print_statements(&mut writer.indented(), body);
            line!(writer, "}}");
        }
        HlrStatement::DoWhile(body, cond) => {
            line!(writer, "do {{");
            pretty_print_statements(&mut writer.indented(), body);
            line!(writer, "}} while {};", pretty_print_expression(cond));
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
            let rets = match exprs.len() {
                0 => "".to_string(),
                1 => format!(" {}", pretty_print_expression(&exprs[0])),
                _ => format!(
                    " ({})",
                    exprs.iter().map(pretty_print_expression).join(", ")
                ),
            };
            line!(writer, "return{};", rets);
        }
        HlrStatement::Halt => line!(writer, "halt;"),
        HlrStatement::Output(expr) => line!(writer, "output({});", pretty_print_expression(expr)),
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
        HlrExpression::Constant(val, _) => format!("{}", val),
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
        ),
        HlrExpression::UnaryOperator { op, expr } => {
            format!("{}{}", op, pretty_print_expression(expr))
        }
        HlrExpression::FunctionCall(func_expr, args) => {
            let name = match **func_expr {
                HlrExpression::Constant(var, _) => format!("fu{}", var),
                _ => pretty_print_expression(func_expr),
            };
            let args = args.iter().map(pretty_print_expression).join(", ");
            format!("{}({})", name, args)
        }
        HlrExpression::Tuple(exprs) => {
            format!("({})", pretty_print_expressions(exprs))
        }
        HlrExpression::Input() => "input()".to_string(),
        HlrExpression::Deref(var_expr) => format!("*{}", pretty_print_expression(var_expr)),
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
            BinaryOperator::NotEquals => write!(f, "!="),
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
