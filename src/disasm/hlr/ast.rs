use std::collections::HashMap;
use std::fmt::Display;

use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VariableId(usize);

impl VariableId {
    pub fn fresh() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        VariableId(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Scope {
    Local,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HlrVariable {
    pub name: String,
    pub type_info: Type,
    pub scope: Scope,
}

impl HlrVariable {
    pub fn new(name: String, type_info: Type) -> Self {
        Self {
            name,
            type_info,
            scope: Scope::Local,
        }
    }
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

pub type HlrGlobals = HashMap<usize, (HlrVariable, HlrExpression)>;

#[derive(Debug, Clone)]
pub struct HlrProgram {
    pub functions: Vec<HlrFunction>,
    pub globals: HlrGlobals,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HlrExpression {
    Variable(HlrVariable),
    Deref(Box<HlrExpression>),
    Constant(i128, Type),
    StaticFunctionReference(String),
    StaticCustomType(CustomTypeId, String, usize),
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
    String(String),
    FunctionCall(Box<HlrExpression>, Vec<HlrExpression>),
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
                op: op.logical_not(),
                left: left.clone(),
                right: right.clone(),
                result_type: result_type.clone(),
            }),
            _ => None,
        }
    }

    pub fn negate_inplace(&mut self) {
        if let HlrExpression::BinaryOp { op, .. } = self {
            *op = op.logical_not()
        } else {
            let mut original = HlrExpression::Input();
            std::mem::swap(self, &mut original);
            *self = HlrExpression::UnaryOperator {
                op: UnaryOperator::LogicalNot,
                expr: Box::new(original),
            };
        }
    }

    pub fn as_constant(&self) -> Option<i128> {
        match self {
            HlrExpression::Constant(val, _) => Some(*val),
            _ => None,
        }
    }

    pub fn as_binary_op(&self) -> Option<(BinaryOperator, &HlrExpression, &HlrExpression)> {
        match self {
            HlrExpression::BinaryOp {
                op, left, right, ..
            } => Some((*op, left.as_ref(), right.as_ref())),
            _ => None,
        }
    }

    pub fn as_constant_mut(&mut self) -> Option<&mut i128> {
        match self {
            HlrExpression::Constant(val, _) => Some(val),
            _ => None,
        }
    }

    pub fn as_unary_minus(&self) -> Option<&HlrExpression> {
        match self {
            HlrExpression::UnaryOperator {
                op: UnaryOperator::Minus,
                expr,
            } => Some(expr),
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
    LessThanOrEqual,
    Equals,
    NotEquals,
    GreaterThan,
    GreaterThanOrEqual,
}

impl BinaryOperator {
    pub fn logical_not(&self) -> Self {
        match self {
            BinaryOperator::Equals => BinaryOperator::NotEquals,
            BinaryOperator::NotEquals => BinaryOperator::Equals,
            BinaryOperator::GreaterThan => BinaryOperator::LessThanOrEqual,
            BinaryOperator::LessThan => BinaryOperator::GreaterThanOrEqual,
            BinaryOperator::GreaterThanOrEqual => BinaryOperator::LessThan,
            BinaryOperator::LessThanOrEqual => BinaryOperator::GreaterThan,
            _ => panic!("Cannot logical not non-logical operator"),
        }
    }
    pub fn is_logical_operator(&self) -> bool {
        matches!(
            self,
            BinaryOperator::Equals
                | BinaryOperator::NotEquals
                | BinaryOperator::GreaterThan
                | BinaryOperator::LessThan
                | BinaryOperator::GreaterThanOrEqual
                | BinaryOperator::LessThanOrEqual
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOperator {
    LogicalNot,
    Minus,
}

use crate::disasm::symbol_renaming::CustomTypeId;
use crate::disasm::v3::type_inference::Type;
use crate::disasm::v3::FunctionId;

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
            BinaryOperator::LessThanOrEqual => write!(f, "<="),
            BinaryOperator::GreaterThanOrEqual => write!(f, ">="),
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
            globals: HlrGlobals::new(),
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
            scope: Scope::Local,
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
