use std::collections::{HashMap, HashSet};

use crate::disasm::{v2::model::FunctionId, v3::type_inference::Type};

use super::{
    ast::{HlrAssignmentTarget, HlrExpression, HlrFunction, HlrStatement, HlrVariable, Scope},
    visitor::{BlockLocation, Control, ExpressionLocation, HlrFunctionVisitor, StatementLocation},
};

/// Statistics about transformations applied to an HLR function
#[derive(Debug, Clone, Default)]
pub struct TransformationStats {
    /// Number of statements deleted
    pub deleted_statements: usize,
    /// Number of variable references replaced
    pub replaced_variables: usize,
}

/// A transformer for HLR functions that can delete statements and replace variables
pub struct HlrTransformer {
    statements_to_delete: HashSet<StatementLocation>,
    variable_replacements: HashMap<String, HlrExpression>,
    stats: TransformationStats,
}

impl Default for HlrTransformer {
    fn default() -> Self {
        Self::new()
    }
}

impl HlrTransformer {
    /// Create a new transformer with no transformations
    pub fn new() -> Self {
        Self {
            statements_to_delete: HashSet::new(),
            variable_replacements: HashMap::new(),
            stats: TransformationStats::default(),
        }
    }

    /// Mark a statement for deletion
    pub fn delete_statement(&mut self, location: StatementLocation) -> &mut Self {
        self.statements_to_delete.insert(location);
        self
    }

    /// Add a variable replacement
    pub fn replace_variable(&mut self, from: &HlrVariable, to: HlrExpression) -> &mut Self {
        self.variable_replacements.insert(from.name.clone(), to);
        self
    }

    /// Alias to visit
    pub fn transform(self, func: &mut HlrFunction) -> TransformationStats {
        self.visit(func)
    }
}

impl HlrFunctionVisitor<Control, TransformationStats> for HlrTransformer {
    fn enter_statement(&mut self, location: StatementLocation, stmt: &mut HlrStatement) -> Control {
        // Phase 1 of deletion: Replace statements to be deleted with Nop
        if self.statements_to_delete.contains(&location) {
            *stmt = HlrStatement::Nop;
            self.stats.deleted_statements += 1;
            return Control::Prune; // Skip processing the contents of deleted statements
        }

        Control::Continue
    }

    fn enter_expression(
        &mut self,
        _location: ExpressionLocation,
        expr: &mut HlrExpression,
    ) -> Control {
        // Replace variables in expressions
        if let HlrExpression::Variable(var) = expr {
            if let Some(replacement) = self.variable_replacements.get(&var.name) {
                *expr = replacement.clone();
                self.stats.replaced_variables += 1;
            }
        }
        Control::Continue
    }

    fn finish_block(&mut self, _location: BlockLocation, block: &mut Vec<HlrStatement>) -> Control {
        // Phase 2 of deletion: Filter out Nop statements
        block.retain(|stmt| !matches!(stmt, HlrStatement::Nop));
        Control::Continue
    }

    fn finish(self) -> TransformationStats {
        self.stats
    }
}

/// Replace a variable within the given expression with a new expression.
/// The substitituion is not applied recursively: if the exppression contains references to the variable,
/// they will remain unchanged.
pub fn replace_variable(
    expr: &HlrExpression,
    var: &HlrVariable,
    replacement: &HlrExpression,
) -> HlrExpression {
    let mut func = HlrFunction {
        original_id: FunctionId::new(0),
        name: "<replaced>".to_string(),
        args: vec![],
        return_type: vec![],
        body: vec![HlrStatement::Assignment(
            HlrAssignmentTarget::Variable(HlrVariable {
                name: "_".to_string(),
                type_info: Type::Any,
                scope: Scope::Local,
            }),
            expr.clone(),
        )],
    };
    let mut m = HlrTransformer::new();
    m.replace_variable(var, replacement.clone());
    m.transform(&mut func);
    let HlrStatement::Assignment(_, expr) = &func.body[0] else {
        panic!("Expected Assignment");
    };
    expr.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::hlr::ast::{test_utils::*, BinaryOperator};

    #[test]
    fn test_delete_statement() {
        let mut func = hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("x", Type::Int), hlr_const(1, Type::Int)),
                hlr_vardef(hlr_var("y", Type::Int), hlr_const(2, Type::Int)),
                hlr_vardef(hlr_var("z", Type::Int), hlr_const(3, Type::Int)),
            ],
        );

        // Create a transformer to delete the second statement
        let mut transformer = HlrTransformer::new();
        let statement_location = StatementLocation {
            block_location: BlockLocation { block_id: 0 },
            statement_id: 1, // The second statement
        };
        transformer.delete_statement(statement_location);

        // Apply the transformation
        let stats = transformer.transform(&mut func);

        // Verify the statement was deleted
        assert_eq!(stats.deleted_statements, 1);
        assert_eq!(func.body.len(), 2);

        if let HlrStatement::VarDef(vars, _) = &func.body[0] {
            assert_eq!(vars[0].name, "x");
        } else {
            panic!("Expected VarDef");
        }

        if let HlrStatement::VarDef(vars, _) = &func.body[1] {
            assert_eq!(vars[0].name, "z");
        } else {
            panic!("Expected VarDef");
        }
    }

    #[test]
    fn test_replace_variable() {
        let mut func = hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("x", Type::Int), hlr_const(1, Type::Int)),
                hlr_assign(hlr_var_target("y", Type::Int), hlr_var_expr("x", Type::Int)),
            ],
        );

        // Create a transformer to replace variable x with constant 42
        let mut transformer = HlrTransformer::new();
        let old_var = hlr_var("x", Type::Int);
        let new_expr = hlr_const(42, Type::Int);
        transformer.replace_variable(&old_var, new_expr);

        // Apply the transformation
        let stats = transformer.transform(&mut func);

        // Verify the variable was replaced
        assert_eq!(stats.replaced_variables, 1);

        // Check the variable reference in the assignment was replaced with constant
        if let HlrStatement::Assignment(_, expr) = &func.body[1] {
            if let HlrExpression::Constant(val, _) = expr {
                assert_eq!(*val, 42);
            } else {
                panic!("Expected Constant expression");
            }
        } else {
            panic!("Expected Assignment");
        }
    }

    #[test]
    fn test_replace_with_variable() {
        let mut func = hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("x", Type::Int), hlr_const(1, Type::Int)),
                hlr_assign(hlr_var_target("y", Type::Int), hlr_var_expr("x", Type::Int)),
            ],
        );

        // Create a transformer to replace variable x with z
        let mut transformer = HlrTransformer::new();
        let old_var = hlr_var("x", Type::Int);
        let new_expr = hlr_var_expr("z", Type::Int);
        transformer.replace_variable(&old_var, new_expr);

        // Apply the transformation
        let stats = transformer.transform(&mut func);

        // Verify the variable was replaced
        assert_eq!(stats.replaced_variables, 1);

        // Check the variable reference in the assignment was replaced
        if let HlrStatement::Assignment(_, expr) = &func.body[1] {
            if let HlrExpression::Variable(var) = expr {
                assert_eq!(var.name, "z");
            } else {
                panic!("Expected Variable expression");
            }
        } else {
            panic!("Expected Assignment");
        }
    }

    #[test]
    fn test_combined_transformations() {
        let mut func = hlr_function(
            0,
            vec![
                hlr_vardef(hlr_var("x", Type::Int), hlr_const(1, Type::Int)),
                hlr_vardef(hlr_var("y", Type::Int), hlr_const(2, Type::Int)),
                hlr_assign(hlr_var_target("x", Type::Int), hlr_var_expr("y", Type::Int)),
            ],
        );

        // Create a transformer to delete the second statement and replace y with z
        let mut transformer = HlrTransformer::new();

        // Delete the second statement
        let statement_location = StatementLocation {
            block_location: BlockLocation { block_id: 0 },
            statement_id: 1, // The second statement
        };
        transformer.delete_statement(statement_location);

        // Replace y with z
        let old_var = hlr_var("y", Type::Int);
        let new_expr = hlr_var_expr("z", Type::Int);
        transformer.replace_variable(&old_var, new_expr);

        // Apply the transformation
        let stats = transformer.transform(&mut func);

        // Verify the transformations
        assert_eq!(stats.deleted_statements, 1);
        assert_eq!(stats.replaced_variables, 1);
        assert_eq!(func.body.len(), 2);

        // Check the variable in the assignment expression was replaced
        if let HlrStatement::Assignment(_, expr) = &func.body[1] {
            if let HlrExpression::Variable(var) = expr {
                assert_eq!(var.name, "z");
            } else {
                panic!("Expected Variable expression");
            }
        } else {
            panic!("Expected Assignment");
        }
    }
    #[test]
    fn test_replace_variable_in_expression() {
        // Test replacing a variable within an expression
        let original = hlr_binop(
            BinaryOperator::Add,
            hlr_var_expr("x", Type::Int),
            hlr_const(5, Type::Int),
            Type::Int,
        );

        let var_to_replace = hlr_var("x", Type::Int);
        let replacement = hlr_const(10, Type::Int);

        let result = replace_variable(&original, &var_to_replace, &replacement);

        if let HlrExpression::BinaryOp {
            op,
            left,
            right,
            result_type,
        } = result
        {
            assert_eq!(op, BinaryOperator::Add);
            assert_eq!(*left, hlr_const(10, Type::Int));
            assert_eq!(*right, hlr_const(5, Type::Int));
            assert_eq!(result_type, Type::Int);
        } else {
            panic!("Expected BinaryOp expression");
        }
    }

    #[test]
    fn test_replace_variable_in_nested_expression() {
        // Test replacing a variable in a nested expression
        let inner_expr = hlr_binop(
            BinaryOperator::Mul,
            hlr_var_expr("x", Type::Int),
            hlr_const(3, Type::Int),
            Type::Int,
        );

        let outer_expr = hlr_binop(
            BinaryOperator::Add,
            inner_expr,
            hlr_var_expr("y", Type::Int),
            Type::Int,
        );

        let var_to_replace = hlr_var("x", Type::Int);
        let replacement = hlr_const(7, Type::Int);

        let result = replace_variable(&outer_expr, &var_to_replace, &replacement);

        if let HlrExpression::BinaryOp {
            op: outer_op,
            left: outer_left,
            right: outer_right,
            ..
        } = result
        {
            assert_eq!(outer_op, BinaryOperator::Add);

            if let HlrExpression::BinaryOp {
                op: inner_op,
                left: inner_left,
                right: inner_right,
                ..
            } = *outer_left
            {
                assert_eq!(inner_op, BinaryOperator::Mul);
                assert_eq!(*inner_left, hlr_const(7, Type::Int));
                assert_eq!(*inner_right, hlr_const(3, Type::Int));
            } else {
                panic!("Expected BinaryOp for inner expression");
            }

            assert!(matches!(*outer_right, HlrExpression::Variable(_)));
        } else {
            panic!("Expected BinaryOp for outer expression");
        }
    }

    #[test]
    fn test_replace_variable_no_match() {
        // Test replacing a variable that doesn't exist in the expression
        let original = hlr_binop(
            BinaryOperator::Add,
            hlr_var_expr("x", Type::Int),
            hlr_const(5, Type::Int),
            Type::Int,
        );

        let var_to_replace = hlr_var("z", Type::Int); // 'z' doesn't exist in the expression
        let replacement = hlr_const(10, Type::Int);

        let result = replace_variable(&original, &var_to_replace, &replacement);

        // Expression should remain unchanged
        if let HlrExpression::BinaryOp {
            op,
            left,
            right,
            result_type,
        } = result
        {
            assert_eq!(op, BinaryOperator::Add);

            if let HlrExpression::Variable(var) = *left {
                assert_eq!(var.name, "x");
            } else {
                panic!("Expected Variable expression");
            }

            assert_eq!(*right, hlr_const(5, Type::Int));
            assert_eq!(result_type, Type::Int);
        } else {
            panic!("Expected BinaryOp expression");
        }
    }
    #[test]
    fn test_replace_deeply_nested_variable() {
        // Create a deeply nested expression with multiple levels
        let nested_expr = hlr_binop(
            BinaryOperator::Add,
            hlr_binop(
                BinaryOperator::Mul,
                hlr_binop(
                    BinaryOperator::Sub,
                    hlr_var_expr("x", Type::Int),
                    hlr_const(1, Type::Int),
                    Type::Int,
                ),
                hlr_const(2, Type::Int),
                Type::Int,
            ),
            hlr_binop(
                BinaryOperator::Sub,
                hlr_const(10, Type::Int),
                hlr_var_expr("y", Type::Int),
                Type::Int,
            ),
            Type::Int,
        );

        let var_to_replace = hlr_var("x", Type::Int);
        let replacement = hlr_const(5, Type::Int);

        let result = replace_variable(&nested_expr, &var_to_replace, &replacement);

        // Verify that the variable was replaced at the deepest level
        if let HlrExpression::BinaryOp {
            left: outer_left, ..
        } = &result
        {
            if let HlrExpression::BinaryOp {
                left: middle_left, ..
            } = &**outer_left
            {
                if let HlrExpression::BinaryOp {
                    left: inner_left, ..
                } = &**middle_left
                {
                    assert_eq!(**inner_left, hlr_const(5, Type::Int));
                } else {
                    panic!("Expected BinaryOp for inner expression");
                }
            } else {
                panic!("Expected BinaryOp for middle expression");
            }
        } else {
            panic!("Expected BinaryOp for outer expression");
        }

        // The "y" variable should remain unchanged
        if let HlrExpression::BinaryOp {
            right: outer_right, ..
        } = &result
        {
            if let HlrExpression::BinaryOp {
                right: div_right, ..
            } = &**outer_right
            {
                if let HlrExpression::Variable(var) = &**div_right {
                    assert_eq!(var.name, "y");
                } else {
                    panic!("Expected Variable expression for y");
                }
            } else {
                panic!("Expected BinaryOp for division");
            }
        } else {
            panic!("Expected BinaryOp for outer expression");
        }
    }
}
