use crate::disasm::hlr::ast::{HlrAssignmentTarget, HlrExpression, HlrStatement};

use super::ast::HlrFunction;

#[derive(PartialEq, Eq, Hash)]
enum HlrNode<'a> {
    Block(&'a Vec<HlrStatement>),
    Statement(&'a mut HlrStatement),
    Expression(&'a mut HlrExpression),
}

enum HlrVisitEvent<T>
where
    T: Sized,
{
    Enter(T),
    Exit(T),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
enum HlrVisitControlFlow {
    Continue,
    Prune,
}

macro_rules! do_control {
    ($e:expr, $c:stmt) => {
        match $e {
            HlrVisitControlFlow::Continue => {
                $c();
                ()
            }
            HlrVisitControlFlow::Prune => (),
        }
    };
}

type BlockVisitEvent<'a> = HlrVisitEvent<&'a mut Vec<HlrStatement>>;
type StatementVisitEvent<'a> = HlrVisitEvent<&'a mut HlrStatement>;
type ExpressionVisitEvent<'a> = HlrVisitEvent<&'a mut HlrExpression>;

fn visit_function<'a, BF, SF, EF>(func: &'a mut HlrFunction, bf: BF, sf: SF, ef: EF)
where
    BF: FnMut(BlockVisitEvent<'_>) -> HlrVisitControlFlow,
    SF: FnMut(StatementVisitEvent<'_>) -> HlrVisitControlFlow,
    EF: FnMut(ExpressionVisitEvent<'_>) -> HlrVisitControlFlow,
{
    visit_block(&mut func.body, bf, sf, ef);
}

fn visit_block<'a, BF, SF, EF>(block: &'a mut Vec<HlrStatement>, mut bf: BF, mut sf: SF, mut ef: EF)
where
    BF: FnMut(BlockVisitEvent<'_>) -> HlrVisitControlFlow,
    SF: FnMut(StatementVisitEvent<'_>) -> HlrVisitControlFlow,
    EF: FnMut(ExpressionVisitEvent<'_>) -> HlrVisitControlFlow,
{
    do_control!(bf(HlrVisitEvent::Enter(block)), {
        for stmt in block.iter_mut() {
            visit_statement(stmt, &mut bf, &mut sf, &mut ef);
        }
    });
    bf(HlrVisitEvent::Exit(block));
}

fn visit_statement<'a, BF, SF, EF>(
    stmt: &'a mut HlrStatement,
    bf: &mut BF,
    sf: &mut SF,
    ef: &mut EF,
) where
    BF: FnMut(BlockVisitEvent<'a>) -> HlrVisitControlFlow,
    SF: FnMut(StatementVisitEvent<'a>) -> HlrVisitControlFlow,
    EF: FnMut(ExpressionVisitEvent<'a>) -> HlrVisitControlFlow,
{
}

fn dodo(f: &mut HlrFunction) {
    visit_function(
        f,
        |e| match e {
            HlrVisitEvent::Enter(block) => {
                block.clear();
                HlrVisitControlFlow::Continue
            }
            _ => HlrVisitControlFlow::Continue,
        },
        |_| HlrVisitControlFlow::Continue,
        |_| HlrVisitControlFlow::Continue,
    );
}

/// Trait for visiting expressions in the HLR AST
pub trait ExpressionVisitor {
    /// Visit an expression and potentially transform it
    fn visit_expression(&mut self, expr: &HlrExpression) -> HlrExpression;

    /// Called when entering a nested expression (like inside a binary op)
    fn enter_expression(&mut self, _expr: &HlrExpression) {}

    /// Called when exiting a nested expression
    fn exit_expression(&mut self, _expr: &HlrExpression) {}
}

/// Trait for visiting statements in the HLR AST
pub trait StatementVisitor {
    /// Visit a statement and potentially transform it
    fn visit_statement(&mut self, stmt: &HlrStatement) -> Option<HlrStatement>;

    /// Called when entering a nested statement block (like inside an if)
    fn enter_block(&mut self) {}

    /// Called when exiting a nested statement block
    fn exit_block(&mut self) {}

    /// Visit an expression within a statement
    fn visit_expression(&mut self, expr: &HlrExpression) -> HlrExpression;
}

/// Apply a visitor to an expression
pub fn traverse_expression<V: ExpressionVisitor>(
    expr: &HlrExpression,
    visitor: &mut V,
) -> HlrExpression {
    visitor.enter_expression(expr);

    let result = match expr {
        HlrExpression::Variable(_) => visitor.visit_expression(expr),
        HlrExpression::Deref(inner) => {
            let new_inner = traverse_expression(inner, visitor);
            if **inner == new_inner {
                expr.clone()
            } else {
                HlrExpression::Deref(Box::new(new_inner))
            }
        }
        HlrExpression::Constant(_, _) => visitor.visit_expression(expr),
        HlrExpression::BinaryOp {
            op,
            left,
            right,
            result_type,
        } => {
            let new_left = traverse_expression(left, visitor);
            let new_right = traverse_expression(right, visitor);

            if **left == new_left && **right == new_right {
                visitor.visit_expression(expr)
            } else {
                HlrExpression::BinaryOp {
                    op: *op,
                    left: Box::new(new_left),
                    right: Box::new(new_right),
                    result_type: result_type.clone(),
                }
            }
        }
        HlrExpression::UnaryOperator { op, expr: inner } => {
            let new_inner = traverse_expression(inner, visitor);
            if **inner == new_inner {
                expr.clone()
            } else {
                HlrExpression::UnaryOperator {
                    op: *op,
                    expr: Box::new(new_inner),
                }
            }
        }
        HlrExpression::FunctionCall(func, args) => {
            let new_func = traverse_expression(func, visitor);
            let new_args = args
                .iter()
                .map(|arg| traverse_expression(arg, visitor))
                .collect::<Vec<_>>();

            let changed =
                **func != new_func || args.iter().zip(new_args.iter()).any(|(a, b)| a != b);

            if changed {
                HlrExpression::FunctionCall(Box::new(new_func), new_args)
            } else {
                visitor.visit_expression(expr)
            }
        }
        HlrExpression::Tuple(elements) => {
            let new_elements = elements
                .iter()
                .map(|elem| traverse_expression(elem, visitor))
                .collect::<Vec<_>>();

            let changed = elements
                .iter()
                .zip(new_elements.iter())
                .any(|(a, b)| a != b);

            if changed {
                HlrExpression::Tuple(new_elements)
            } else {
                visitor.visit_expression(expr)
            }
        }
        HlrExpression::Input() => visitor.visit_expression(expr),
    };

    visitor.exit_expression(expr);
    result
}

/// Apply a visitor to a statement
pub fn traverse_statement<V: StatementVisitor>(
    stmt: &HlrStatement,
    visitor: &mut V,
) -> Option<HlrStatement> {
    match stmt {
        HlrStatement::VarDef(vars, expr) => {
            let new_expr = visitor.visit_expression(expr);
            if *expr == new_expr {
                visitor.visit_statement(stmt)
            } else {
                Some(HlrStatement::VarDef(vars.clone(), new_expr))
            }
        }
        HlrStatement::Assignment(target, expr) => {
            let new_expr = visitor.visit_expression(expr);
            let new_target = match target {
                HlrAssignmentTarget::Deref(deref_expr) => {
                    let new_deref = visitor.visit_expression(deref_expr);
                    if *deref_expr == new_deref {
                        target.clone()
                    } else {
                        HlrAssignmentTarget::Deref(new_deref)
                    }
                }
                _ => target.clone(),
            };

            if *expr == new_expr {
                visitor.visit_statement(stmt)
            } else {
                Some(HlrStatement::Assignment(new_target, new_expr))
            }
        }
        HlrStatement::Loop(body) => {
            visitor.enter_block();
            let new_body = traverse_statements(body, visitor);
            visitor.exit_block();

            Some(HlrStatement::Loop(new_body))
        }
        HlrStatement::If(cond, then_branch, else_branch) => {
            let new_cond = visitor.visit_expression(cond);

            visitor.enter_block();
            let new_then = traverse_statements(then_branch, visitor);
            visitor.exit_block();

            visitor.enter_block();
            let new_else = traverse_statements(else_branch, visitor);
            visitor.exit_block();

            // Since Vec<HlrStatement> might not implement PartialEq, we'll just create a new statement
            // This is a simplification - in a real implementation, you might want to check if anything changed
            Some(HlrStatement::If(new_cond, new_then, new_else))
        }
        HlrStatement::While(cond, body) => {
            let new_cond = visitor.visit_expression(cond);

            visitor.enter_block();
            let new_body = traverse_statements(body, visitor);
            visitor.exit_block();

            // Since Vec<HlrStatement> might not implement PartialEq, we'll just create a new statement
            Some(HlrStatement::While(new_cond, new_body))
        }
        HlrStatement::DoWhile(body, cond) => {
            visitor.enter_block();
            let new_body = traverse_statements(body, visitor);
            visitor.exit_block();

            let new_cond = visitor.visit_expression(cond);

            // Since Vec<HlrStatement> might not implement PartialEq, we'll just create a new statement
            Some(HlrStatement::DoWhile(new_body, new_cond))
        }
        HlrStatement::Return(exprs) => {
            let new_exprs = exprs
                .iter()
                .map(|expr| visitor.visit_expression(expr))
                .collect::<Vec<_>>();

            let changed = exprs.iter().zip(new_exprs.iter()).any(|(a, b)| a != b);

            if changed {
                Some(HlrStatement::Return(new_exprs))
            } else {
                visitor.visit_statement(stmt)
            }
        }
        HlrStatement::Output(expr) => {
            let new_expr = visitor.visit_expression(expr);
            if *expr == new_expr {
                visitor.visit_statement(stmt)
            } else {
                Some(HlrStatement::Output(new_expr))
            }
        }
        _ => visitor.visit_statement(stmt),
    }
}

/// Apply a visitor to a list of statements
pub fn traverse_statements<V: StatementVisitor>(
    stmts: &[HlrStatement],
    visitor: &mut V,
) -> Vec<HlrStatement> {
    let mut result = Vec::new();

    for stmt in stmts {
        if let Some(new_stmt) = traverse_statement(stmt, visitor) {
            result.push(new_stmt);
        }
    }

    result
}

/// Apply a function to all expressions in an expression tree
pub fn map_expressions<F>(expr: &HlrExpression, f: &mut F) -> HlrExpression
where
    F: FnMut(&HlrExpression) -> Option<HlrExpression>,
{
    struct MapVisitor<'a, F> {
        f: &'a mut F,
    }

    impl<'a, F> ExpressionVisitor for MapVisitor<'a, F>
    where
        F: FnMut(&HlrExpression) -> Option<HlrExpression>,
    {
        fn visit_expression(&mut self, expr: &HlrExpression) -> HlrExpression {
            if let Some(new_expr) = (self.f)(expr) {
                new_expr
            } else {
                expr.clone()
            }
        }
    }

    let mut visitor = MapVisitor { f };
    traverse_expression(expr, &mut visitor)
}

/// Execute a function for each expression in an expression tree
pub fn for_each_expression<F>(expr: &HlrExpression, f: &mut F)
where
    F: FnMut(&HlrExpression),
{
    struct ForEachVisitor<'a, F> {
        f: &'a mut F,
    }

    impl<'a, F> ExpressionVisitor for ForEachVisitor<'a, F>
    where
        F: FnMut(&HlrExpression),
    {
        fn visit_expression(&mut self, expr: &HlrExpression) -> HlrExpression {
            (self.f)(expr);
            expr.clone()
        }
    }

    let mut visitor = ForEachVisitor { f };
    traverse_expression(expr, &mut visitor);
}

/// Apply a function to all statements in a statement list
pub fn map_statements<F, E>(
    stmts: &[HlrStatement],
    expr_visitor: &mut E,
    f: &mut F,
) -> Vec<HlrStatement>
where
    F: FnMut(&HlrStatement, &mut E) -> Option<HlrStatement>,
    E: ExpressionVisitor,
{
    struct MapVisitor<'a, F, E> {
        f: &'a mut F,
        expr_visitor: &'a mut E,
    }

    impl<'a, F, E> StatementVisitor for MapVisitor<'a, F, E>
    where
        F: FnMut(&HlrStatement, &mut E) -> Option<HlrStatement>,
        E: ExpressionVisitor,
    {
        fn visit_statement(&mut self, stmt: &HlrStatement) -> Option<HlrStatement> {
            (self.f)(stmt, self.expr_visitor)
        }

        fn visit_expression(&mut self, expr: &HlrExpression) -> HlrExpression {
            traverse_expression(expr, self.expr_visitor)
        }
    }

    let mut visitor = MapVisitor { f, expr_visitor };
    traverse_statements(stmts, &mut visitor)
}

/// Execute a function for each statement in a statement list
pub fn for_each_statement<F>(stmts: &[HlrStatement], f: &mut F)
where
    F: FnMut(&HlrStatement),
{
    struct ForEachVisitor<'a, F> {
        f: &'a mut F,
    }

    impl<'a, F> StatementVisitor for ForEachVisitor<'a, F>
    where
        F: FnMut(&HlrStatement),
    {
        fn visit_statement(&mut self, stmt: &HlrStatement) -> Option<HlrStatement> {
            (self.f)(stmt);
            Some(stmt.clone())
        }

        fn visit_expression(&mut self, expr: &HlrExpression) -> HlrExpression {
            expr.clone()
        }
    }

    let mut visitor = ForEachVisitor { f };
    traverse_statements(stmts, &mut visitor);
}
