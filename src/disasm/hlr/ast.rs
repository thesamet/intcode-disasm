use std::fmt::Display;

use colored::{Color, ColoredString, Colorize};
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HlrAssignmentTarget {
    Variable(HlrVariable),
    Deref(HlrExpression),
    Ignored,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    Nop,
}

impl Display for HlrStatement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut cp = CodePrinter::new();
        pretty_print_statement(&mut cp.single_line_mode(), self);
        f.write_str(&cp.result())
    }
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
    Input(),
}

impl Display for HlrExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&pretty_print_expression(self))
    }
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

    pub fn as_constant(&self) -> Option<i128> {
        match self {
            HlrExpression::Constant(val, _) => Some(*val),
            _ => None,
        }
    }

    pub fn as_constant_mut(&mut self) -> Option<&mut i128> {
        match self {
            HlrExpression::Constant(val, _) => Some(val),
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

struct SyntaxColors {}

impl SyntaxColors {
    fn keyword() -> Color {
        Color::TrueColor {
            r: 253,
            g: 104,
            b: 131,
        }
    }
    fn variable() -> Color {
        Color::TrueColor {
            r: 255,
            g: 241,
            b: 243,
        }
    }

    fn op_color() -> Color {
        Color::TrueColor {
            r: 253,
            g: 104,
            b: 131,
        }
    }
    fn type_color() -> Color {
        Color::TrueColor {
            r: 133,
            g: 218,
            b: 204,
        }
    }
    fn const_color() -> Color {
        Color::TrueColor {
            r: 0xa8,
            g: 0xa9,
            b: 0xeb,
        }
    }

    fn low_prio() -> Color {
        Color::TrueColor {
            r: 0x94,
            g: 0x8a,
            b: 0x8b,
        }
    }

    fn function() -> Color {
        Color::TrueColor {
            r: 173,
            g: 218,
            b: 120,
        }
    }

    fn bg_color() -> Color {
        Color::TrueColor {
            r: 44,
            g: 37,
            b: 37,
        }
    }
    fn open_paren() -> ColoredString {
        "(".to_string().color(SyntaxColors::low_prio())
    }
    fn close_paren() -> ColoredString {
        ")".to_string().color(SyntaxColors::low_prio())
    }
    fn open_brace() -> ColoredString {
        "{".to_string().color(SyntaxColors::low_prio())
    }
    fn close_brace() -> ColoredString {
        "}".to_string().color(SyntaxColors::low_prio())
    }
    fn colon() -> ColoredString {
        ":".to_string().color(SyntaxColors::low_prio())
    }
    fn comma() -> ColoredString {
        ", ".to_string().color(SyntaxColors::low_prio())
    }
    fn eq() -> ColoredString {
        "=".to_string().color(SyntaxColors::op_color())
    }
    fn semicolon() -> ColoredString {
        ";".to_string().color(SyntaxColors::low_prio())
    }
}

fn keyword(text: &str) -> ColoredString {
    text.to_string().color(SyntaxColors::keyword())
}

pub fn pretty_print_program(program: &HlrProgram) -> String {
    let mut printer = CodePrinter::new();
    pretty_print_program_impl(&mut printer, program);
    let clear_to_end_code = "\x1b[K";

    printer
        .result()
        .lines()
        .map(|line| {
            format!(
                "{}{}",
                line.on_color(SyntaxColors::bg_color()),
                clear_to_end_code.on_color(SyntaxColors::bg_color())
            )
        })
        .join("\n")
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
    format!("{}", var.name.color(SyntaxColors::variable()))
}

fn pretty_print_type(ty: &Type) -> ColoredString {
    match ty {
        Type::Int => "int".color(SyntaxColors::type_color()),
        Type::Bool => "bool".color(SyntaxColors::type_color()),
        Type::Char => "char".color(SyntaxColors::type_color()),
        Type::Pointer(ty) => {
            format!("*{}", pretty_print_type(ty)).color(SyntaxColors::type_color())
        }
        Type::Tuple(ts) => {
            let mut s = "Tuple(".to_string();
            for (_, t) in ts.iter().with_position() {
                s.push_str(&pretty_print_type(t));
                s.push_str(", ");
            }
            s.push(')');
            s.color(SyntaxColors::type_color())
        }
        _ => format!("{}", ty).color(SyntaxColors::type_color()),
    }
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
                "{}{} {}",
                pretty_print_variable(arg),
                SyntaxColors::colon(),
                pretty_print_type(&arg.type_info)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    let ret_str = match func.return_type.len() {
        0 => keyword("void").color(SyntaxColors::type_color()),
        1 => pretty_print_type(&func.return_type[0].type_info),
        _ => format!(
            "({})",
            func.return_type
                .iter()
                .map(|ret| pretty_print_type(&ret.type_info))
                .join(&SyntaxColors::comma().to_string()),
        )
        .color(SyntaxColors::low_prio()),
    };

    let var_name = &format!(
        "{} {}({}) -> {} {{",
        keyword("function"),
        func.name.color(SyntaxColors::function()),
        args_str,
        ret_str
    );
    let signature = var_name.color(SyntaxColors::low_prio());

    line!(writer, "{}", signature);
    pretty_print_statements(&mut writer.indented(), &func.body);
    line!(writer, "{}", SyntaxColors::close_brace());
}

pub fn pretty_print_statement<F>(writer: &mut F, stmt: &HlrStatement)
where
    F: CodeWriter,
{
    match stmt {
        HlrStatement::VarDef(vars, expr) => {
            let e = if vars.len() == 1 {
                format!(
                    "{}{} {}",
                    pretty_print_variable(&vars[0]),
                    SyntaxColors::colon(),
                    pretty_print_type(&vars[0].type_info),
                )
                .color(SyntaxColors::low_prio())
            } else {
                let vars = vars
                    .iter()
                    .map(|var| {
                        format!(
                            "{}{} {}",
                            pretty_print_variable(var),
                            SyntaxColors::colon(),
                            pretty_print_type(&var.type_info),
                        )
                    })
                    .join(&SyntaxColors::comma().to_string());
                format!("({})", vars).color(SyntaxColors::low_prio())
            };
            line!(
                writer,
                "{} {} {} {}{}",
                keyword("let"),
                e,
                SyntaxColors::eq(),
                pretty_print_expression(expr),
                SyntaxColors::semicolon()
            );
        }
        HlrStatement::Assignment(target, expr) => {
            let target = match target {
                HlrAssignmentTarget::Variable(var) => {
                    format!("{} {} ", pretty_print_variable(var), SyntaxColors::eq())
                }
                HlrAssignmentTarget::Deref(expr) => {
                    format!("*{} {} ", pretty_print_expression(expr), SyntaxColors::eq())
                }
                HlrAssignmentTarget::Ignored => "".to_string(),
            };
            line!(
                writer,
                "{}{}{}",
                target,
                pretty_print_expression(expr),
                SyntaxColors::semicolon()
            );
        }
        HlrStatement::Loop(body) => {
            line!(writer, "{} {}", keyword("loop"), SyntaxColors::open_brace());
            pretty_print_statements(&mut writer.indented(), body);
            line!(writer, "{}", SyntaxColors::close_brace());
        }
        HlrStatement::DoWhile(body, cond) => {
            line!(writer, "{} {}", keyword("do"), SyntaxColors::open_brace());
            pretty_print_statements(&mut writer.indented(), body);
            line!(
                writer,
                "{} {} {};",
                SyntaxColors::close_brace(),
                keyword("while"),
                pretty_print_expression(cond)
            );
        }
        HlrStatement::If(cond, true_branch, false_branch) => {
            line!(
                writer,
                "{} {} {}",
                keyword("if"),
                pretty_print_expression(cond),
                SyntaxColors::open_brace()
            );
            pretty_print_statements(&mut writer.indented(), true_branch);
            if false_branch.is_empty() {
                line!(writer, "{}", SyntaxColors::close_brace());
            } else {
                line!(
                    writer,
                    "{} {} {}",
                    SyntaxColors::close_brace(),
                    keyword("else"),
                    SyntaxColors::open_brace()
                );
                pretty_print_statements(&mut writer.indented(), false_branch);
                line!(writer, "{}", SyntaxColors::close_brace());
            }
        }
        HlrStatement::While(cond, body) => {
            line!(
                writer,
                "{} {} {}",
                keyword("while"),
                pretty_print_expression(cond),
                SyntaxColors::open_brace()
            );
            pretty_print_statements(&mut writer.indented(), body);
            line!(writer, "{}", SyntaxColors::close_brace());
        }
        HlrStatement::Break => line!(writer, "{}{}", keyword("break"), SyntaxColors::semicolon()),
        HlrStatement::Continue => line!(
            writer,
            "{}{}",
            keyword("continue"),
            SyntaxColors::semicolon()
        ),
        HlrStatement::Return(exprs) => {
            let rets = match exprs.len() {
                0 => "".to_string(),
                1 => format!(" {}", pretty_print_expression(&exprs[0])),
                _ => format!(
                    " {}{}{}",
                    SyntaxColors::open_paren(),
                    exprs
                        .iter()
                        .map(pretty_print_expression)
                        .join(&SyntaxColors::comma().to_string())
                        .color(SyntaxColors::low_prio()),
                    SyntaxColors::close_paren()
                ),
            };
            line!(
                writer,
                "{}{}{}",
                keyword("return"),
                rets,
                SyntaxColors::semicolon()
            );
        }
        HlrStatement::Halt => line!(writer, "{}{}", keyword("halt"), SyntaxColors::semicolon()),
        HlrStatement::Output(expr) => line!(
            writer,
            "{}{}{}{}{}",
            keyword("output"),
            SyntaxColors::open_paren(),
            pretty_print_expression(expr),
            SyntaxColors::close_paren(),
            SyntaxColors::semicolon()
        ),
        HlrStatement::Nop => line!(writer, "{}", keyword("nop")),
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
        HlrExpression::Variable(var) => pretty_print_variable(var),
        HlrExpression::Constant(val, _) => {
            format!("{}", val.to_string().color(SyntaxColors::const_color()))
        }
        HlrExpression::BinaryOp {
            op,
            left,
            right,
            result_type: _, // Type hints can sometimes be omitted for brevity if desired
        } => format!(
            "{}{} {} {}{}", // Removed type hint for potentially cleaner output
            SyntaxColors::open_paren(),
            pretty_print_expression(left),
            op.to_string().color(SyntaxColors::op_color()),
            pretty_print_expression(right),
            SyntaxColors::close_paren()
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

        HlrExpression::Input() => "input()".to_string(),
        HlrExpression::Deref(var_expr) => format!("*{}", pretty_print_expression(var_expr)),
    }
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

#[cfg(test)]
pub mod test_utils {
    use super::*;
    // Helper functions to create HLR structures concisely
    pub fn hlr_program(functions: Vec<HlrFunction>) -> HlrProgram {
        HlrProgram {
            functions,
            globals: vec![],
        }
    }

    pub fn hlr_function(id: usize, body: Vec<HlrStatement>) -> HlrFunction {
        HlrFunction {
            original_id: FunctionId::from(id),
            name: id.to_string(),
            args: vec![],
            return_type: vec![],
            body,
        }
    }

    pub fn hlr_var(name: &str, typ: Type) -> HlrVariable {
        HlrVariable {
            name: name.to_string(),
            type_info: typ,
        }
    }

    pub fn hlr_vardef(target: HlrVariable, expr: HlrExpression) -> HlrStatement {
        HlrStatement::VarDef(vec![target], expr)
    }

    pub fn hlr_assign(target: HlrAssignmentTarget, expr: HlrExpression) -> HlrStatement {
        HlrStatement::Assignment(target, expr)
    }

    pub fn hlr_var_target(name: &str, typ: Type) -> HlrAssignmentTarget {
        HlrAssignmentTarget::Variable(hlr_var(name, typ))
    }

    pub fn hlr_var_expr(name: &str, typ: Type) -> HlrExpression {
        HlrExpression::Variable(hlr_var(name, typ))
    }

    pub fn hlr_const(value: i128, typ: Type) -> HlrExpression {
        HlrExpression::Constant(value, typ)
    }

    pub fn hlr_binop(
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

    pub fn hlr_if(
        condition: HlrExpression,
        then_branch: Vec<HlrStatement>,
        else_branch: Vec<HlrStatement>,
    ) -> HlrStatement {
        HlrStatement::If(condition, then_branch, else_branch)
    }

    pub fn hlr_while(condition: HlrExpression, body: Vec<HlrStatement>) -> HlrStatement {
        HlrStatement::While(condition, body)
    }

    pub fn hlr_do_while(body: Vec<HlrStatement>, condition: HlrExpression) -> HlrStatement {
        HlrStatement::DoWhile(body, condition)
    }

    pub fn hlr_loop(body: Vec<HlrStatement>) -> HlrStatement {
        HlrStatement::Loop(body)
    }

    pub fn hlr_deref(expr: HlrExpression) -> HlrExpression {
        HlrExpression::Deref(Box::new(expr))
    }

    pub fn hlr_input() -> HlrExpression {
        HlrExpression::Input()
    }

    pub fn hlr_output(expr: HlrExpression) -> HlrStatement {
        HlrStatement::Output(expr)
    }

    pub fn hlr_return(exprs: Vec<HlrExpression>) -> HlrStatement {
        HlrStatement::Return(exprs)
    }

    pub fn hlr_function_call(func_expr: HlrExpression, args: Vec<HlrExpression>) -> HlrExpression {
        HlrExpression::FunctionCall(Box::new(func_expr), args)
    }
}
