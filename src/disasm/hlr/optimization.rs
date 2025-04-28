use std::collections::{HashMap, HashSet};

use crate::disasm::hlr::ast::{HlrExpression, HlrFunction, HlrProgram, HlrStatement, HlrVariable};
use crate::disasm::hlr::visitor::{for_each_expression, for_each_statement, map_expressions, traverse_expression, traverse_statements, ExpressionVisitor, StatementVisitor};

/// Interface for optimization passes
pub trait OptimizationPass {
    /// Apply the optimization pass to a program
    fn run(&self, program: &mut HlrProgram) -> bool;
    
    /// Name of the optimization for debugging/logging
    fn name(&self) -> &str;
}

/// Structure to track variable replacements
pub struct VariableReplacements {
    replacements: HashMap<HlrVariable, HlrExpression>,
}

impl VariableReplacements {
    pub fn new() -> Self {
        Self { replacements: HashMap::new() }
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

/// Visitor that transforms expressions by applying replacements
pub struct ExpressionTransformer {
    replacements: VariableReplacements,
}

impl ExpressionTransformer {
    pub fn new(replacements: VariableReplacements) -> Self {
        Self { replacements }
    }
}

impl ExpressionVisitor for ExpressionTransformer {
    fn visit_expression(&mut self, expr: &HlrExpression) -> HlrExpression {
        match expr {
            HlrExpression::Variable(var) => {
                if let Some(replacement) = self.replacements.get_replacement(var) {
                    // Clone the replacement expression
                    replacement.clone()
                } else {
                    // No replacement, keep the original
                    expr.clone()
                }
            },
            // For other expression types, just return the original
            // The traversal will handle recursively visiting nested expressions
            _ => expr.clone(),
        }
    }
}

/// Visitor that transforms statements
pub struct StatementTransformer {
    expr_transformer: ExpressionTransformer,
    eliminated_vars: HashSet<HlrVariable>,
}

impl StatementTransformer {
    pub fn new(replacements: VariableReplacements) -> Self {
        Self {
            expr_transformer: ExpressionTransformer::new(replacements),
            eliminated_vars: HashSet::new(),
        }
    }
    
    pub fn mark_as_eliminated(&mut self, var: &HlrVariable) {
        self.eliminated_vars.insert(var.clone());
    }
    
    pub fn transform(&mut self, statements: &[HlrStatement]) -> Vec<HlrStatement> {
        traverse_statements(statements, self)
    }
}

impl StatementVisitor for StatementTransformer {
    fn visit_statement(&mut self, stmt: &HlrStatement) -> Option<HlrStatement> {
        match stmt {
            HlrStatement::VarDef(vars, expr) => {
                // Check if this variable definition should be eliminated
                if vars.iter().any(|v| self.eliminated_vars.contains(v)) {
                    // Skip this statement
                    None
                } else {
                    // Transform the expression but keep the variable definition
                    let new_expr = self.visit_expression(expr);
                    if *expr == new_expr {
                        Some(stmt.clone())
                    } else {
                        Some(HlrStatement::VarDef(vars.clone(), new_expr))
                    }
                }
            },
            HlrStatement::Assignment(target, expr) => {
                let new_expr = self.visit_expression(expr);
                let new_target = match target {
                    HlrAssignmentTarget::Deref(deref_expr) => {
                        let new_deref = self.visit_expression(deref_expr);
                        if *deref_expr == new_deref {
                            target.clone()
                        } else {
                            HlrAssignmentTarget::Deref(new_deref)
                        }
                    },
                    _ => target.clone(),
                };
                
                if *expr == new_expr && *target == new_target {
                    Some(stmt.clone())
                } else {
                    Some(HlrStatement::Assignment(new_target, new_expr))
                }
            },
            HlrStatement::If(cond, then_branch, else_branch) => {
                let new_cond = self.visit_expression(cond);
                let new_then = self.transform(then_branch);
                let new_else = self.transform(else_branch);
                
                let changed = *cond != new_cond || 
                    then_branch != &new_then || 
                    else_branch != &new_else;
                
                if changed {
                    Some(HlrStatement::If(new_cond, new_then, new_else))
                } else {
                    Some(stmt.clone())
                }
            },
            HlrStatement::Loop(body) => {
                let new_body = self.transform(body);
                
                if body != &new_body {
                    Some(HlrStatement::Loop(new_body))
                } else {
                    Some(stmt.clone())
                }
            },
            HlrStatement::While(cond, body) => {
                let new_cond = self.visit_expression(cond);
                let new_body = self.transform(body);
                
                let changed = *cond != new_cond || body != &new_body;
                
                if changed {
                    Some(HlrStatement::While(new_cond, new_body))
                } else {
                    Some(stmt.clone())
                }
            },
            HlrStatement::DoWhile(body, cond) => {
                let new_body = self.transform(body);
                let new_cond = self.visit_expression(cond);
                
                let changed = *cond != new_cond || body != &new_body;
                
                if changed {
                    Some(HlrStatement::DoWhile(new_body, new_cond))
                } else {
                    Some(stmt.clone())
                }
            },
            HlrStatement::Return(exprs) => {
                let new_exprs = exprs.iter()
                    .map(|expr| self.visit_expression(expr))
                    .collect::<Vec<_>>();
                
                let changed = exprs.iter().zip(new_exprs.iter())
                    .any(|(a, b)| a != b);
                
                if changed {
                    Some(HlrStatement::Return(new_exprs))
                } else {
                    Some(stmt.clone())
                }
            },
            HlrStatement::Output(expr) => {
                let new_expr = self.visit_expression(expr);
                if *expr == new_expr {
                    Some(stmt.clone())
                } else {
                    Some(HlrStatement::Output(new_expr))
                }
            },
            _ => Some(stmt.clone()),
        }
    }
    
    fn visit_expression(&mut self, expr: &HlrExpression) -> HlrExpression {
        traverse_expression(expr, &mut self.expr_transformer)
    }
}

/// Counts variable usages in a function
pub struct VariableUsageCounter {
    usage_counts: HashMap<HlrVariable, usize>,
}

impl VariableUsageCounter {
    pub fn new() -> Self {
        Self { usage_counts: HashMap::new() }
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
        // Count variables used in expressions
        match stmt {
            HlrStatement::VarDef(_, expr) => {
                self.count_usages_in_expression(expr);
            },
            HlrStatement::Assignment(target, expr) => {
                // Count the target if it's a variable
                if let HlrAssignmentTarget::Variable(var) = target {
                    *self.usage_counts.entry(var.clone()).or_insert(0) += 1;
                } else if let HlrAssignmentTarget::Deref(deref_expr) = target {
                    // Count variables in the deref expression
                    self.count_usages_in_expression(deref_expr);
                }
                
                self.count_usages_in_expression(expr);
            },
            HlrStatement::If(cond, then_branch, else_branch) => {
                self.count_usages_in_expression(cond);
                
                for stmt in then_branch {
                    self.count_usages_in_statement(stmt);
                }
                
                for stmt in else_branch {
                    self.count_usages_in_statement(stmt);
                }
            },
            HlrStatement::Loop(body) => {
                for stmt in body {
                    self.count_usages_in_statement(stmt);
                }
            },
            HlrStatement::While(cond, body) => {
                self.count_usages_in_expression(cond);
                
                for stmt in body {
                    self.count_usages_in_statement(stmt);
                }
            },
            HlrStatement::DoWhile(body, cond) => {
                for stmt in body {
                    self.count_usages_in_statement(stmt);
                }
                
                self.count_usages_in_expression(cond);
            },
            HlrStatement::Return(exprs) => {
                for expr in exprs {
                    self.count_usages_in_expression(expr);
                }
            },
            HlrStatement::Output(expr) => {
                self.count_usages_in_expression(expr);
            },
            HlrStatement::Break | HlrStatement::Continue | HlrStatement::Halt => {},
        }
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
    fn find_single_use_variables(&self, function: &HlrFunction) -> (HashSet<HlrVariable>, VariableReplacements) {
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
                for_each_expression(expr, &mut |e| {
                    match e {
                        HlrExpression::Variable(_) | HlrExpression::Constant(_, _) => {},
                        HlrExpression::BinaryOp { .. } => {},
                        _ => is_simple = false,
                    }
                });
                is_simple
            },
            // Add more cases that are safe to inline
            HlrExpression::UnaryOperator { op: _, expr: inner } => {
                self.is_safe_to_inline(inner)
            },
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
    
    pub fn add_pass<T: OptimizationPass + 'static>(&mut self, pass: T) {
        self.passes.push(Box::new(pass));
    }
    
    pub fn run(&self, program: &mut HlrProgram) {
        let mut changed = true;
        let mut iteration = 0;
        
        // Run passes until no more changes
        while changed && iteration < 10 { // Limit iterations to prevent infinite loops
            changed = false;
            iteration += 1;
            
            for pass in &self.passes {
                let pass_changed = pass.run(program);
                changed |= pass_changed;
                
                if pass_changed {
                    println!("Pass {} made changes in iteration {}", pass.name(), iteration);
                }
            }
        }
    }
}
