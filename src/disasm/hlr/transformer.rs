use std::collections::{HashMap, HashSet};

use super::{
    ast::{HlrExpression, HlrFunction, HlrStatement, HlrVariable},
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disasm::hlr::ast::test_utils::*;
    use crate::disasm::v2::type_inference::types::Type;

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
}
