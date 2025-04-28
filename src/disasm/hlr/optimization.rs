use std::collections::{HashMap, HashSet};

use crate::disasm::hlr::ast::{
    HlrAssignmentTarget, HlrExpression, HlrFunction, HlrProgram, HlrStatement, HlrVariable,
};

/// Structure to track variable replacements
pub struct VariableReplacements {
    replacements: HashMap<HlrVariable, HlrExpression>,
}

impl VariableReplacements {
    pub fn new() -> Self {
        Self {
            replacements: HashMap::new(),
        }
    }

    pub fn add_replacement(&mut self, var: HlrVariable, expr: HlrExpression) {
        self.replacements.insert(var, expr);
    }

    pub fn get_replacement(&self, var: &HlrVariable) -> Option<&HlrExpression> {
        self.replacements.get(var)
    }

    pub fn is_empty(&self) -> bool {
        self.replacements.is_empty()
    }
}

/*
pub struct VariableUsageCounter {
    usage_counts: HashMap<HlrVariable, usize>,
}

impl VariableUsageCounter {
    pub fn new() -> Self {
        Self {
            usage_counts: HashMap::new(),
        }
    }

    pub fn count_usages(&mut self, function: &HlrFunction) {
        // First, initialize all variables with 0 usages
        for stmt in &function.body {
            if let HlrStatement::VarDef(vars, _) = stmt {
                for var in vars {
                    self.usage_counts.insert(var.clone(), 0);
                }
            }
        }

        // Count variable usages in all expressions
        for stmt in &function.body {
            self.count_usages_in_statement(stmt);
        }
    }

    fn count_usages_in_statement(&mut self, stmt: &HlrStatement) {
        struct UsageCounterVisitor<'a> {
            counter: &'a mut VariableUsageCounter,
        }

        impl<'a> StatementVisitor for UsageCounterVisitor<'a> {
            fn visit_statement(&mut self, stmt: &HlrStatement) -> Option<HlrStatement> {
                // Special case for assignment targets that are variables
                if let HlrStatement::Assignment(target, _) = stmt {
                    if let HlrAssignmentTarget::Variable(var) = target {
                        *self.counter.usage_counts.entry(var.clone()).or_insert(0) += 1;
                    }
                }

                // We're just counting, not transforming
                Some(stmt.clone())
            }

            fn visit_expression(&mut self, expr: &HlrExpression) -> HlrExpression {
                self.counter.count_usages_in_expression(expr);
                expr.clone()
            }
        }

        let mut visitor = UsageCounterVisitor { counter: self };
        let _ = crate::disasm::hlr::visitor::traverse_statement(stmt, &mut visitor);
    }

    fn count_usages_in_expression(&mut self, expr: &HlrExpression) {
        for_each_expression(expr, &mut |e| {
            if let HlrExpression::Variable(var) = e {
                *self.usage_counts.entry(var.clone()).or_insert(0) += 1;
            }
        });
    }

    pub fn get_single_use_variables(&self) -> HashSet<HlrVariable> {
        self.usage_counts
            .iter()
            .filter_map(|(var, count)| if *count == 1 { Some(var.clone()) } else { None })
            .collect()
    }
}

/// Optimization pass that eliminates temporary variables
pub struct TemporaryVariableElimination;

impl OptimizationPass for TemporaryVariableElimination {
    fn name(&self) -> &str {
        "TemporaryVariableElimination"
    }

    fn run(&self, program: &mut HlrProgram) -> bool {
        let mut changed = false;

        // For each function in the program
        for function in &mut program.functions {
            // Analyze variable usage
            let (single_use_vars, replacements) = self.find_single_use_variables(function);

            if !replacements.is_empty() {
                changed = true;

                // Create transformer with the replacements
                let mut transformer = StatementTransformer::new(replacements);

                // Mark variables to be eliminated
                for var in single_use_vars {
                    transformer.mark_as_eliminated(&var);
                }

                // Transform the function body
                function.body = transformer.transform(&function.body);
            }
        }

        changed
    }
}

impl TemporaryVariableElimination {
    fn find_single_use_variables(
        &self,
        function: &HlrFunction,
    ) -> (HashSet<HlrVariable>, VariableReplacements) {
        let mut counter = VariableUsageCounter::new();
        counter.count_usages(function);

        let single_use_vars = counter.get_single_use_variables();
        let mut replacements = VariableReplacements::new();

        // Find definitions of single-use variables
        for stmt in &function.body {
            if let HlrStatement::VarDef(vars, expr) = stmt {
                if vars.len() == 1 && single_use_vars.contains(&vars[0]) {
                    replacements.add_replacement(vars[0].clone(), expr.clone());
                }
            }
        }

        (single_use_vars, replacements)
    }
}

/// Optimization pass that builds more complex expressions by inlining simple variables
pub struct ExpressionBuilding;

impl OptimizationPass for ExpressionBuilding {
    fn name(&self) -> &str {
        "ExpressionBuilding"
    }

    fn run(&self, program: &mut HlrProgram) -> bool {
        let mut changed = false;

        // For each function in the program
        for function in &mut program.functions {
            // Find chains of expressions that can be combined
            let replacements = self.find_expression_chains(function);

            if !replacements.is_empty() {
                changed = true;

                // Create transformer with the replacements
                let mut transformer = StatementTransformer::new(replacements);

                // Transform the function body
                function.body = transformer.transform(&function.body);
            }
        }

        changed
    }
}

impl ExpressionBuilding {
    fn find_expression_chains(&self, function: &HlrFunction) -> VariableReplacements {
        let mut replacements = VariableReplacements::new();
        let mut var_defs = HashMap::new();

        // First pass: collect all variable definitions
        for_each_statement(&function.body, &mut |stmt| {
            if let HlrStatement::VarDef(vars, expr) = stmt {
                if vars.len() == 1 {
                    var_defs.insert(vars[0].clone(), expr.clone());
                }
            }
        });

        // Second pass: find expression chains
        for (var, expr) in &var_defs {
            // Check if this expression uses variables that could be inlined
            let mut can_inline = true;
            let new_expr = map_expressions(expr, &mut |e| {
                if let HlrExpression::Variable(used_var) = e {
                    if let Some(def_expr) = var_defs.get(used_var) {
                        // Check if inlining this would be beneficial
                        if self.is_safe_to_inline(def_expr) {
                            return Some(def_expr.clone());
                        } else {
                            can_inline = false;
                        }
                    }
                }
                None
            });

            if can_inline && new_expr != *expr {
                // Avoid circular references
                let mut has_circular_ref = false;
                for_each_expression(&new_expr, &mut |e| {
                    if let HlrExpression::Variable(inner_var) = e {
                        if inner_var == var {
                            has_circular_ref = true;
                        }
                    }
                });

                if !has_circular_ref {
                    replacements.add_replacement(var.clone(), new_expr);
                }
            }
        }

        replacements
    }

    fn is_safe_to_inline(&self, expr: &HlrExpression) -> bool {
        // Determine if an expression is safe to inline
        // (e.g., simple expressions, no function calls that might have side effects)
        match expr {
            HlrExpression::Variable(_) | HlrExpression::Constant(_, _) => true,
            HlrExpression::BinaryOp { .. } => {
                // Check if operands are simple
                let mut is_simple = true;
                for_each_expression(expr, &mut |e| match e {
                    HlrExpression::Variable(_) | HlrExpression::Constant(_, _) => {}
                    HlrExpression::BinaryOp { .. } => {}
                    _ => is_simple = false,
                });
                is_simple
            }
            // Add more cases that are safe to inline
            HlrExpression::UnaryOperator { op: _, expr: inner } => self.is_safe_to_inline(inner),
            _ => false,
        }
    }
}

/// Pipeline for running multiple optimization passes
pub struct OptimizationPipeline {
    passes: Vec<Box<dyn OptimizationPass>>,
}

impl OptimizationPipeline {
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

}
*/
