use crate::disasm::hlr::ast::{HlrExpression, HlrStatement};

use super::ast::HlrFunction;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum HlrNode<'a> {
    Block(&'a mut Vec<HlrStatement>),
    Statement(&'a mut HlrStatement),
    Expression(&'a mut HlrExpression),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum HlrVisitEvent<'a> {
    Enter(HlrNode<'a>),
    Finish(HlrNode<'a>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum HlrVisitControlFlow {
    Continue,
    #[allow(dead_code)]
    Prune,
}

macro_rules! do_control {
    ($nf: expr, $e:expr, $c:stmt) => {
        match $nf(HlrVisitEvent::Enter($e)) {
            HlrVisitControlFlow::Continue => {
                $c();
            }
            HlrVisitControlFlow::Prune => (),
        }
        match $nf(HlrVisitEvent::Finish($e)) {
            HlrVisitControlFlow::Continue => (),
            HlrVisitControlFlow::Prune => {
                panic!("Pruned while visiting {:?}", $e);
            }
        }
    };
}
pub fn visit_function<F>(func: &mut HlrFunction, mut visitor: F)
where
    F: FnMut(HlrVisitEvent) -> HlrVisitControlFlow,
{
    visit_block(&mut func.body, &mut visitor);
}

fn visit_block<F>(block: &mut Vec<HlrStatement>, visitor: &mut F)
where
    F: FnMut(HlrVisitEvent) -> HlrVisitControlFlow,
{
    do_control!(visitor, HlrNode::Block(block), {
        for stmt in block.iter_mut() {
            visit_statement(stmt, visitor);
        }
    });
}

fn visit_statement<F>(stmt: &mut HlrStatement, visitor: &mut F)
where
    F: FnMut(HlrVisitEvent) -> HlrVisitControlFlow,
{
    do_control!(visitor, HlrNode::Statement(stmt), {
        match stmt {
            HlrStatement::VarDef(_, expr) => visit_expression(expr, visitor),
            HlrStatement::Loop(body) => visit_block(body, visitor),
            HlrStatement::Assignment(_, expr) => visit_expression(expr, visitor),
            HlrStatement::If(cond, then_branch, else_branch) => {
                visit_expression(cond, visitor);
                visit_block(then_branch, visitor);
                visit_block(else_branch, visitor);
            }
            HlrStatement::While(cond, body) => {
                visit_expression(cond, visitor);
                visit_block(body, visitor);
            }
            HlrStatement::DoWhile(body, cond) => {
                visit_block(body, visitor);
                visit_expression(cond, visitor);
            }
            HlrStatement::Return(exprs) => {
                for expr in exprs {
                    visit_expression(expr, visitor);
                }
            }
            HlrStatement::Output(expr) => visit_expression(expr, visitor),
            HlrStatement::Break | HlrStatement::Continue | HlrStatement::Halt => (),
        }
    });
}

fn visit_expression<F>(expr: &mut HlrExpression, visitor: &mut F)
where
    F: FnMut(HlrVisitEvent) -> HlrVisitControlFlow,
{
    do_control!(visitor, HlrNode::Expression(expr), {
        match expr {
            HlrExpression::Variable(_) => (),
            HlrExpression::Deref(inner) => visit_expression(inner, visitor),
            HlrExpression::Constant(_, _) => (),
            HlrExpression::BinaryOp {
                op: _,
                left,
                right,
                result_type: _,
            } => {
                visit_expression(left, visitor);
                visit_expression(right, visitor);
            }
            HlrExpression::UnaryOperator { op: _, expr: inner } => {
                visit_expression(inner, visitor);
            }
            HlrExpression::FunctionCall(func, args) => {
                visit_expression(func, visitor);
                for arg in args {
                    visit_expression(arg, visitor);
                }
            }
            HlrExpression::Input() => (),
        }
    });
}
