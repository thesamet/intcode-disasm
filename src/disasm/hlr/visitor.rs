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

// Control flow enum for HLR traversals.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Control {
    // Chooses to continue the traversal as normal.
    Continue,

    // All the descendants of the node will be skipped. However, the finish
    // event will still be fired for the node. It will cause a panic to return
    // Prune for a node's Finish event.
    Prune,
}

pub trait ControlFlow {
    // Returns whether the traversal should prune the node.
    fn should_prune(&self) -> bool;

    // Returns a control flow object that represents continuing the traversal.
    fn continuing() -> Self;
}

impl ControlFlow for Control {
    fn should_prune(&self) -> bool {
        match self {
            Control::Continue => false,
            Control::Prune => true,
        }
    }
    fn continuing() -> Self {
        Control::Continue
    }
}

impl ControlFlow for () {
    fn should_prune(&self) -> bool {
        false
    }
    fn continuing() -> Self {}
}

macro_rules! do_control {
    ($nf: expr, $e:expr, $c:stmt) => {{
        let control = $nf(HlrVisitEvent::Enter($e));
        if !control.should_prune() {
            $c
        }
        let control = $nf(HlrVisitEvent::Finish($e));
        assert!(!control.should_prune());
    }};
}

pub fn visit_function<C, F>(func: &mut HlrFunction, mut visitor: F)
where
    C: ControlFlow,
    F: FnMut(HlrVisitEvent) -> C,
{
    visit_block(&mut func.body, &mut visitor);
}

fn visit_block<C, F>(block: &mut Vec<HlrStatement>, visitor: &mut F)
where
    C: ControlFlow,
    F: FnMut(HlrVisitEvent) -> C,
{
    do_control!(visitor, HlrNode::Block(block), {
        for stmt in block.iter_mut() {
            visit_statement(stmt, visitor);
        }
    });
}

fn visit_statement<C, F>(stmt: &mut HlrStatement, visitor: &mut F)
where
    C: ControlFlow,
    F: FnMut(HlrVisitEvent) -> C,
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
            HlrStatement::Break
            | HlrStatement::Continue
            | HlrStatement::Halt
            | HlrStatement::Nop => (),
        }
    });
}

fn visit_expression<C, F>(expr: &mut HlrExpression, visitor: &mut F)
where
    C: ControlFlow,
    F: FnMut(HlrVisitEvent) -> C,
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
            HlrExpression::StaticFunctionReference(_) => (),
        }
    });
}

// Visitor that provides a location for each node in the HLR AST.

// Identified locations of the construct. The generate objects are meant to be
// opaque, however the are guaranteed to:
// 1. Be unique for each node in the HLR AST.
// 2. Sortable in DFS order.
// 3. Provide identical values for successive runs over the same HLR AST.
#[derive(Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct BlockLocation {
    pub block_id: usize,
}

impl std::fmt::Debug for BlockLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Block({})", self.block_id)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct StatementLocation {
    pub block_location: BlockLocation,
    pub statement_id: usize,
}

impl std::fmt::Debug for StatementLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Statement({}/{})",
            self.block_location.block_id, self.statement_id
        )
    }
}

impl StatementLocation {
    pub fn get_containing_block(&self) -> BlockLocation {
        self.block_location
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ExpressionLocation {
    pub containing_statement: StatementLocation,
    pub expression_id: usize,
}

impl std::fmt::Debug for ExpressionLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Expression({}/{}/{})",
            self.get_containing_block().block_id,
            self.get_containing_statement().statement_id,
            self.expression_id
        )
    }
}

impl ExpressionLocation {
    pub fn get_containing_statement(&self) -> StatementLocation {
        self.containing_statement
    }

    pub fn get_containing_block(&self) -> BlockLocation {
        self.containing_statement.get_containing_block()
    }
}

#[allow(unused_variables)]
/// A visitor trait for traversing the High-Level Representation (HLR) of a function's abstract syntax tree.
///
/// This trait allows custom traversal and analysis of HLR functions with fine-grained control over the visit process.
///
/// # Generic Parameters
/// - `C`: Control flow type that determines how traversal proceeds (e.g., continue or prune)
/// - `R`: Return type computed at the end of the traversal
///
/// # Control Flow
/// Each method returns a `C` value that can:
/// - Continue the traversal normally with `Control::Continue`
/// - Skip descendant nodes with `Control::Prune`
///
/// Methods are called in a depth-first order for each node type:
/// 1. `enter_*` method is called before processing child nodes
/// 2. Child nodes are processed
/// 3. `finish_*` method is called after processing child nodes
///
/// # Example Use Cases
/// - Static analysis
/// - Code transformation
/// - Collecting metrics about the AST structure
pub trait HlrFunctionVisitor<C, R>
where
    C: ControlFlow,
{
    fn visit(self, func: &mut HlrFunction) -> R
    where
        Self: Sized,
    {
        visit(func, self)
    }

    fn visit_with_default(func: &mut HlrFunction) -> R
    where
        Self: Sized + Default,
    {
        Self::visit(Self::default(), func)
    }

    fn start(&mut self, func: &mut HlrFunction) -> C {
        C::continuing()
    }

    /// Called when entering a block of statements, before processing its contents
    fn enter_block(&mut self, location: BlockLocation, block: &mut Vec<HlrStatement>) -> C {
        C::continuing()
    }

    /// Called after processing all statements in a block
    fn finish_block(&mut self, location: BlockLocation, block: &mut Vec<HlrStatement>) -> C {
        C::continuing()
    }

    /// Called when entering a statement, before processing its contents
    fn enter_statement(&mut self, location: StatementLocation, stmt: &mut HlrStatement) -> C {
        C::continuing()
    }

    /// Called after processing a statement's contents
    fn finish_statement(&mut self, location: StatementLocation, stmt: &mut HlrStatement) -> C {
        C::continuing()
    }

    /// Called when entering an expression, before processing its contents
    fn enter_expression(&mut self, location: ExpressionLocation, expr: &mut HlrExpression) -> C {
        C::continuing()
    }

    /// Called after processing an expression's contents
    fn finish_expression(&mut self, location: ExpressionLocation, expr: &mut HlrExpression) -> C {
        C::continuing()
    }

    /// Final method called to compute and return a result after traversal is complete
    fn finish(self) -> R;
}

fn visit<C, R, F>(func: &mut HlrFunction, mut visitor: F) -> R
where
    C: ControlFlow,
    F: HlrFunctionVisitor<C, R>,
{
    let mut next_block_id = 0;
    let mut next_statement_id = 0;
    let mut next_expression_id = 0;
    // Stacks to track current locations
    let mut block_stack: Vec<BlockLocation> = Vec::new();
    let mut statement_stack: Vec<StatementLocation> = Vec::new();
    let mut expression_stack: Vec<ExpressionLocation> = Vec::new();
    visitor.start(func);

    visit_function(func, |event| match event {
        HlrVisitEvent::Enter(node) => match node {
            HlrNode::Block(block) => {
                let block_location = BlockLocation {
                    block_id: next_block_id,
                };
                next_block_id += 1;
                block_stack.push(block_location);
                visitor.enter_block(block_location, block)
            }
            HlrNode::Statement(stmt) => {
                let block_location = *block_stack.last().unwrap();
                let statement_location = StatementLocation {
                    block_location,
                    statement_id: next_statement_id,
                };
                next_statement_id += 1;
                statement_stack.push(statement_location);
                visitor.enter_statement(statement_location, stmt)
            }
            HlrNode::Expression(expr) => {
                let containing_statement = *statement_stack.last().unwrap();
                let expression_location = ExpressionLocation {
                    containing_statement,
                    expression_id: next_expression_id,
                };
                next_expression_id += 1;
                expression_stack.push(expression_location);
                visitor.enter_expression(expression_location, expr)
            }
        },
        HlrVisitEvent::Finish(node) => match node {
            HlrNode::Block(block) => {
                let block_location = block_stack.pop().unwrap();
                visitor.finish_block(block_location, block)
            }
            HlrNode::Statement(stmt) => {
                let statement_location = statement_stack.pop().unwrap();
                visitor.finish_statement(statement_location, stmt)
            }
            HlrNode::Expression(expr) => {
                let expression_location = expression_stack.pop().unwrap();
                visitor.finish_expression(expression_location, expr)
            }
        },
    });
    visitor.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::{
        hlr::ast::{test_utils, HlrStatement},
        v3::type_inference::Type,
    };
    use test_utils::*;

    #[derive(Debug, PartialEq)]
    enum VisitedNode {
        Block,
        Statement(String),
        Expression(String),
    }

    #[test]
    fn test_basic_visitor() {
        let mut func = hlr_function(
            0,
            vec![hlr_vardef(
                hlr_var("x", Type::Int),
                hlr_const(42, Type::Int),
            )],
        );

        let mut visited = Vec::new();

        visit_function(&mut func, |event| {
            if let HlrVisitEvent::Enter(node) = event {
                match node {
                    HlrNode::Block(_) => visited.push(VisitedNode::Block),
                    HlrNode::Statement(stmt) => {
                        if let HlrStatement::VarDef(vars, _) = stmt {
                            if !vars.is_empty() {
                                visited.push(VisitedNode::Statement(vars[0].name.clone()))
                            }
                        }
                    }
                    HlrNode::Expression(expr) => {
                        if let HlrExpression::Constant(val, _) = expr {
                            visited.push(VisitedNode::Expression(format!("Constant({})", val)))
                        }
                    }
                }
            }
            Control::Continue
        });

        assert_eq!(visited.len(), 3);
        assert_eq!(visited[0], VisitedNode::Block);
        assert_eq!(visited[1], VisitedNode::Statement("x".to_string()));
        assert_eq!(
            visited[2],
            VisitedNode::Expression("Constant(42)".to_string())
        );
    }

    #[test]
    fn test_complex_visitor() {
        let mut func = hlr_function(
            0,
            vec![hlr_if(
                hlr_const(1, Type::Bool),
                vec![hlr_vardef(
                    hlr_var("then", Type::Int),
                    hlr_const(10, Type::Int),
                )],
                vec![hlr_vardef(
                    hlr_var("else", Type::Int),
                    hlr_const(20, Type::Int),
                )],
            )],
        );

        let mut visited = Vec::new();

        visit_function(&mut func, |event| {
            if let HlrVisitEvent::Enter(node) = event {
                match node {
                    HlrNode::Statement(stmt) => match stmt {
                        HlrStatement::VarDef(vars, _) => {
                            if !vars.is_empty() {
                                visited.push(VisitedNode::Statement(vars[0].name.clone()))
                            }
                        }
                        HlrStatement::If(_, _, _) => {
                            visited.push(VisitedNode::Statement("if".to_string()))
                        }
                        _ => {}
                    },
                    HlrNode::Expression(HlrExpression::Constant(val, _)) => {
                        visited.push(VisitedNode::Expression(format!("Constant({})", val)))
                    }
                    _ => {}
                }
            }
            Control::Continue
        });

        assert_eq!(visited.len(), 6);
        assert_eq!(visited[0], VisitedNode::Statement("if".to_string()));
        assert_eq!(
            visited[1],
            VisitedNode::Expression("Constant(1)".to_string())
        );
        assert_eq!(visited[2], VisitedNode::Statement("then".to_string()));
        assert_eq!(
            visited[3],
            VisitedNode::Expression("Constant(10)".to_string())
        );
        assert_eq!(visited[4], VisitedNode::Statement("else".to_string()));
        assert_eq!(
            visited[5],
            VisitedNode::Expression("Constant(20)".to_string())
        );
    }

    #[test]
    fn test_visitor_pruning() {
        let mut func = hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("first", Type::Int), hlr_const(1, Type::Int)),
                hlr_vardef(hlr_var("second", Type::Int), hlr_const(2, Type::Int)),
            ],
        );

        let mut visited = Vec::new();
        let mut statement_exits = Vec::new();

        visit_function(&mut func, |event| {
            match event {
                HlrVisitEvent::Enter(HlrNode::Statement(stmt)) => match stmt {
                    HlrStatement::VarDef(vars, _) => {
                        if !vars.is_empty() {
                            // Prune after seeing the first variable
                            if vars[0].name == "first" {
                                return Control::Prune;
                            }
                        }
                        return Control::Continue;
                    }
                    _ => return Control::Continue,
                },
                HlrVisitEvent::Enter(HlrNode::Expression(expr)) => match expr {
                    HlrExpression::Constant(c, _) => {
                        visited.push(*c);
                        return Control::Continue;
                    }
                    _ => return Control::Continue,
                },
                HlrVisitEvent::Finish(HlrNode::Statement(stmt)) => match stmt {
                    HlrStatement::VarDef(vars, _) => {
                        if !vars.is_empty() {
                            statement_exits.push(vars[0].name.clone());
                        }
                        return Control::Continue;
                    }
                    _ => return Control::Continue,
                },
                _ => {}
            }
            Control::Continue
        });

        // Should only visit the second constant due to pruning
        assert_eq!(visited, vec![2]);

        // Assert that exit events for both statements are called
        assert_eq!(
            statement_exits,
            vec!["first".to_string(), "second".to_string()]
        );
    }

    #[test]
    fn test_visitor_enter_finish() {
        let mut func = hlr_function(
            0,
            vec![hlr_vardef(
                hlr_var("x", Type::Int),
                hlr_const(42, Type::Int),
            )],
        );

        let mut events = Vec::<String>::new();

        visit_function(&mut func, |event| {
            match event {
                HlrVisitEvent::Enter(HlrNode::Block(_)) => events.push("enter block".to_string()),
                HlrVisitEvent::Finish(HlrNode::Block(_)) => events.push("finish block".to_string()),
                HlrVisitEvent::Enter(HlrNode::Statement(_)) => {
                    events.push("enter statement".to_string())
                }
                HlrVisitEvent::Finish(HlrNode::Statement(_)) => {
                    events.push("finish statement".to_string())
                }
                HlrVisitEvent::Enter(HlrNode::Expression(_)) => {
                    events.push("enter expression".to_string())
                }
                HlrVisitEvent::Finish(HlrNode::Expression(_)) => {
                    events.push("finish expression".to_string())
                }
            }
            Control::Continue
        });

        assert_eq!(events.len(), 6);
        assert_eq!(events[0], "enter block");
        assert_eq!(events[1], "enter statement");
        assert_eq!(events[2], "enter expression");
        assert_eq!(events[3], "finish expression");
        assert_eq!(events[4], "finish statement");
        assert_eq!(events[5], "finish block");
    }

    struct TestVisitor {
        events: Vec<String>,
    }

    impl HlrFunctionVisitor<Control, Vec<String>> for TestVisitor {
        fn enter_block(
            &mut self,
            location: BlockLocation,
            _block: &mut Vec<HlrStatement>,
        ) -> Control {
            self.events
                .push(format!("enter_block: {}", location.block_id));
            Control::Continue
        }

        fn finish_block(
            &mut self,
            location: BlockLocation,
            _block: &mut Vec<HlrStatement>,
        ) -> Control {
            self.events
                .push(format!("finish_block: {}", location.block_id));
            Control::Continue
        }

        fn enter_statement(
            &mut self,
            location: StatementLocation,
            stmt: &mut HlrStatement,
        ) -> Control {
            let stmt_type = match stmt {
                HlrStatement::VarDef(_, _) => "VarDef".to_string(),
                HlrStatement::If(_, _, _) => "If".to_string(),
                HlrStatement::While(_, _) => "While".to_string(),
                _ => format!("{:?}", stmt),
            };

            self.events.push(format!(
                "enter_statement: {} (block: {}, id: {})",
                stmt_type, location.block_location.block_id, location.statement_id
            ));
            Control::Continue
        }

        fn finish_statement(
            &mut self,
            location: StatementLocation,
            stmt: &mut HlrStatement,
        ) -> Control {
            let stmt_type = match stmt {
                HlrStatement::VarDef(_, _) => "VarDef".to_string(),
                HlrStatement::If(_, _, _) => "If".to_string(),
                HlrStatement::While(_, _) => "While".to_string(),
                _ => format!("{:?}", stmt),
            };

            self.events.push(format!(
                "finish_statement: {} (block: {}, id: {})",
                stmt_type, location.block_location.block_id, location.statement_id
            ));
            Control::Continue
        }

        fn enter_expression(
            &mut self,
            location: ExpressionLocation,
            expr: &mut HlrExpression,
        ) -> Control {
            let expr_type = match expr {
                HlrExpression::Constant(_val, _) => "Constant".to_string(),
                _ => format!("{}", expr),
            };

            self.events.push(format!(
                "enter_expression: {} (stmt: {}, id: {})",
                expr_type, location.containing_statement.statement_id, location.expression_id
            ));
            Control::Continue
        }

        fn finish_expression(
            &mut self,
            location: ExpressionLocation,
            expr: &mut HlrExpression,
        ) -> Control {
            let expr_type = match expr {
                HlrExpression::Constant(_val, _) => "Constant".to_string(),
                _ => format!("{}", expr),
            };

            self.events.push(format!(
                "finish_expression: {} (stmt: {}, id: {})",
                expr_type, location.containing_statement.statement_id, location.expression_id
            ));
            Control::Continue
        }

        fn finish(self) -> Vec<String> {
            self.events
        }
    }

    #[test]
    fn test_simple_function_with_var_def() {
        let mut func = hlr_function(
            0,
            vec![hlr_vardef(
                hlr_var("x", Type::Int),
                hlr_const(42, Type::Int),
            )],
        );

        let visitor = TestVisitor { events: Vec::new() };
        let events = visit(&mut func, visitor);

        assert_eq!(events.len(), 6);
        assert_eq!(events[0], "enter_block: 0");
        assert_eq!(events[1], "enter_statement: VarDef (block: 0, id: 0)");
        assert_eq!(events[2], "enter_expression: Constant (stmt: 0, id: 0)");
        assert_eq!(events[3], "finish_expression: Constant (stmt: 0, id: 0)");
        assert_eq!(events[4], "finish_statement: VarDef (block: 0, id: 0)");
        assert_eq!(events[5], "finish_block: 0");
    }

    #[test]
    fn test_nested_if_statement() {
        let mut func = hlr_function(
            0,
            vec![hlr_if(
                hlr_const(1, Type::Bool),
                vec![hlr_vardef(
                    hlr_var("then", Type::Int),
                    hlr_const(10, Type::Int),
                )],
                vec![hlr_vardef(
                    hlr_var("else", Type::Int),
                    hlr_const(20, Type::Int),
                )],
            )],
        );

        let visitor = TestVisitor { events: Vec::new() };
        let events = visit(&mut func, visitor);

        assert!(events.iter().any(|e| e == "enter_block: 0"));
        assert!(events.iter().any(|e| e == "enter_block: 1"));
        assert!(events.iter().any(|e| e == "enter_block: 2"));
        assert!(events
            .iter()
            .any(|e| e == "enter_statement: If (block: 0, id: 0)"));
        assert!(events
            .iter()
            .any(|e| e == "enter_statement: VarDef (block: 1, id: 1)"));
        assert!(events
            .iter()
            .any(|e| e == "enter_statement: VarDef (block: 2, id: 2)"));
    }

    #[test]
    fn test_loops_and_assignments() {
        let mut func = hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("x", Type::Int), hlr_const(0, Type::Int)),
                hlr_while(
                    hlr_const(1, Type::Bool),
                    vec![hlr_vardef(
                        hlr_var("y", Type::Int),
                        hlr_const(42, Type::Int),
                    )],
                ),
            ],
        );

        let visitor = TestVisitor { events: Vec::new() };
        let events = visit(&mut func, visitor);

        let block_ids: Vec<usize> = events
            .iter()
            .filter_map(|e| {
                e.strip_prefix("enter_block: ")
                    .map(|sz| sz.parse::<usize>().unwrap())
            })
            .collect();

        assert_eq!(block_ids, vec![0, 1]);
    }

    #[test]
    fn test_pruning_propagation() {
        struct PruningVisitor {
            loop_count: usize,
            defs: Vec<String>,
        }

        impl HlrFunctionVisitor<Control, (usize, Vec<String>)> for PruningVisitor {
            fn enter_statement(
                &mut self,
                _location: StatementLocation,
                stmt: &mut HlrStatement,
            ) -> Control {
                if let HlrStatement::Loop(..) = stmt {
                    self.loop_count += 1;
                    if self.loop_count == 2 {
                        return Control::Prune;
                    }
                }
                if let HlrStatement::VarDef(vs, ..) = stmt {
                    self.defs.push(vs[0].name.clone());
                }
                Control::Continue
            }

            fn finish(self) -> (usize, Vec<String>) {
                (self.loop_count, self.defs)
            }
        }

        let mut func = hlr_function(
            0,
            vec![
                hlr_loop(vec![
                    hlr_vardef(hlr_var("x", Type::Int), hlr_const(0, Type::Int)),
                    hlr_vardef(hlr_var("y", Type::Int), hlr_const(0, Type::Int)),
                ]),
                hlr_loop(vec![
                    hlr_vardef(hlr_var("z", Type::Int), hlr_const(0, Type::Int)),
                    hlr_vardef(hlr_var("w", Type::Int), hlr_const(0, Type::Int)),
                ]),
                hlr_loop(vec![
                    hlr_vardef(hlr_var("a", Type::Int), hlr_const(0, Type::Int)),
                    hlr_vardef(hlr_var("b", Type::Int), hlr_const(0, Type::Int)),
                ]),
            ],
        );

        let visitor = PruningVisitor {
            loop_count: 0,
            defs: Vec::new(),
        };
        let (loop_count, defs) = visit(&mut func, visitor);

        assert_eq!(loop_count, 3);
        assert_eq!(defs, vec!["x", "y", "a", "b"]);
    }
}
