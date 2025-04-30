use std::collections::{HashMap, HashSet};

use itertools::Itertools;
use log::{debug, trace};

use crate::disasm::hlr::ast::{
    BinaryOperator, HlrAssignmentTarget, HlrExpression, HlrFunction, HlrProgram, HlrStatement,
    HlrVariable, Scope, UnaryOperator,
};
use crate::disasm::hlr::transformer::{replace_variable, HlrTransformer};
use crate::disasm::hlr::visitor::{
    BlockLocation, ExpressionLocation, HlrFunctionVisitor, StatementLocation,
};
use crate::disasm::v2::model::ProgramModel;
use crate::disasm::v2::type_inference::types::Type;
use crate::disasm::Error;

pub trait OptimizationPass {
    /// Apply the optimization pass to a function
    fn run(&self, function: &mut HlrFunction) -> bool;

    /// Name of the optimization for debugging/logging
    fn name(&self) -> &str;
}

/// Optimizer for high-level representation (HLR) of the program.
///
/// This component performs various transformations on the HLR to make it more readable:
/// - Converting generic loops into more specific constructs (while, for)
/// - Propagating expressions where possible
/// - Creating higher-level expressions from lower-level operations
pub struct HlrOptimizer<'a> {
    _model: &'a ProgramModel,
    optimizations: Vec<Box<dyn OptimizationPass>>,
}

impl<'a> HlrOptimizer<'a> {
    pub fn new(model: &'a ProgramModel) -> Self {
        Self {
            _model: model,
            optimizations: vec![
                Box::new(PatternMatchingOptimizations),
                Box::new(IdentifyTemporaryVariables),
            ],
        }
    }

    /// Optimizes the given HLR program by applying various transformations
    pub fn optimize(&self, program: &HlrProgram) -> Result<HlrProgram, Error> {
        let mut optimized_functions = Vec::new();
        for function in &program.functions {
            trace!("Optimizing function {}", function.name);
            let mut f = function.clone();
            let mut changed = true;
            while changed {
                changed = false;
                for pass in &self.optimizations {
                    while pass.run(&mut f) {
                        changed = true;
                        trace!("Pass {} made changes in function {}", pass.name(), f.name);
                    }
                }
            }
            optimized_functions.push(f);
        }

        // Create and return the optimized HLR program
        let optimized_program = HlrProgram {
            functions: optimized_functions,
            globals: program.globals.clone(),
        };

        Ok(optimized_program)
    }
}

struct PatternMatchingOptimizations;

impl OptimizationPass for PatternMatchingOptimizations {
    fn name(&self) -> &str {
        "PatternMatchingOptimizations"
    }

    fn run(&self, function: &mut HlrFunction) -> bool {
        struct InitialOptimization {
            changed: bool,
        }
        impl HlrFunctionVisitor<(), bool> for InitialOptimization {
            fn finish_statement(&mut self, _: StatementLocation, stmt: &mut HlrStatement) -> () {
                if let HlrStatement::If(cond, if_body, else_body) = stmt {
                    if if_body.is_empty() {
                        *cond = cond.logical_not().unwrap();
                        std::mem::swap(if_body, else_body);
                        self.changed = true;
                    }
                }
            }

            fn finish_expression(&mut self, _: ExpressionLocation, expr: &mut HlrExpression) -> () {
                match expr {
                    HlrExpression::BinaryOp {
                        op, left, right, ..
                    } => match op {
                        BinaryOperator::Add => match right.as_constant_mut().filter(|s| **s < 0) {
                            Some(right_num) => {
                                *op = BinaryOperator::Sub;
                                *right_num = -*right_num;
                                self.changed = true;
                            }
                            None => match right.as_unary_minus() {
                                Some(right_negated) => {
                                    *op = BinaryOperator::Sub;
                                    *right = Box::new(right_negated.clone());
                                    self.changed = true;
                                }
                                None => {}
                            },
                        },
                        BinaryOperator::Equals
                            if right.as_constant() == Some(0)
                                && left
                                    .as_binary_op()
                                    .map_or(false, |(op, _, _)| op.is_logical_operator()) =>
                        {
                            left.negate_inplace();
                            *expr = *left.clone();
                            self.changed = true;
                        }
                        BinaryOperator::NotEquals
                            if right.as_constant() == Some(0)
                                && left
                                    .as_binary_op()
                                    .map_or(false, |(op, _, _)| op.is_logical_operator()) =>
                        {
                            *expr = *left.clone();
                            self.changed = true;
                        }
                        BinaryOperator::Mul => match (left.as_constant(), right.as_constant()) {
                            (_, Some(-1)) => {
                                *expr = HlrExpression::UnaryOperator {
                                    op: UnaryOperator::Minus,
                                    expr: left.clone(),
                                };
                                self.changed = true;
                            }
                            (Some(-1), _) => {
                                *expr = HlrExpression::UnaryOperator {
                                    op: UnaryOperator::Minus,
                                    expr: right.clone(),
                                };
                                self.changed = true;
                            }
                            _ => {}
                        },
                        _ => {}
                    },
                    _ => (),
                }
            }

            fn finish(self) -> bool {
                self.changed
            }
        }
        impl Default for InitialOptimization {
            fn default() -> Self {
                Self { changed: false }
            }
        }
        InitialOptimization::visit_with_default(function)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum VariableAccessKind {
    // Marks a variable that is passed in to the function
    PassedIn,
    Write {
        // Statement where a variable is written to.
        location: StatementLocation,
        // Expression that is written to the variable
        expr: HlrExpression,
        // All variables this expression depends on. A variable
        // will appear here as many times as it appears in the expression.
        deps: Vec<HlrVariable>,
    },
    // Variable is written to within a tuple, therefore
    // its value is unknown.
    WriteWithinTuple {
        location: StatementLocation,
    },
    // A function call occurs. This invalidates all variables
    // that depend on a global variable.
    FunctionCall {
        location: StatementLocation,
    },
    // Statement where a variable is read.
    Read {
        // Statement where a variable is read.
        location: ExpressionLocation,
    },
}

type VariableAccessEvent = (HlrVariable, VariableAccessKind);

struct VariableAccessLogger {
    variable_access_log: Vec<VariableAccessEvent>,
    in_write: Option<(HlrVariable, Vec<HlrVariable>, HlrExpression)>,
}

impl Default for VariableAccessLogger {
    fn default() -> Self {
        Self {
            variable_access_log: vec![],
            in_write: None,
        }
    }
}

impl HlrFunctionVisitor<(), Vec<VariableAccessEvent>> for VariableAccessLogger {
    fn start(&mut self, func: &mut HlrFunction) -> () {
        for var in &func.args {
            self.variable_access_log
                .push((var.clone(), VariableAccessKind::PassedIn));
        }
    }

    fn enter_statement(&mut self, location: StatementLocation, stmt: &mut HlrStatement) {
        match stmt {
            HlrStatement::VarDef(vs, expr) => {
                if vs.len() == 1 {
                    assert!(self.in_write.is_none());
                    self.in_write = Some((vs[0].clone(), vec![], expr.clone()));
                } else {
                    self.variable_access_log.push((
                        vs[0].clone(),
                        VariableAccessKind::WriteWithinTuple { location },
                    ));
                }
            }
            HlrStatement::Assignment(HlrAssignmentTarget::Variable(v), expr) => {
                assert!(self.in_write.is_none());
                self.in_write = Some((v.clone(), vec![], expr.clone()));
            }
            _ => (),
        }
    }

    fn enter_expression(&mut self, location: ExpressionLocation, expr: &mut HlrExpression) {
        match expr {
            HlrExpression::Variable(var_read) => {
                // If we write to a variable we record this read as a dependency.
                // If the variable we read is exactly the same one we are writing to,
                // it is "a read for update". We do not add this to the access log, but we
                // still record it as a dependency. This is because we want to
                // to make it easy to distingguish between reads for updates and other reads.
                let read_for_update = if let Some((var_written, deps, _)) = self.in_write.as_mut() {
                    // Record dpendency for the currently written variable.
                    deps.push(var_read.clone());
                    var_written.name == var_read.name
                } else {
                    false
                };

                if !read_for_update {
                    self.variable_access_log
                        .push((var_read.clone(), VariableAccessKind::Read { location }));
                }
            }
            HlrExpression::FunctionCall(..) => {
                self.variable_access_log.push((
                    HlrVariable {
                        name: "DUMMY".to_string(),
                        type_info: Type::Nothing,
                        scope: Scope::Global,
                    },
                    VariableAccessKind::FunctionCall {
                        location: location.get_containing_statement(),
                    },
                ));
            }
            _ => {}
        }
    }

    fn finish_statement(&mut self, location: StatementLocation, _: &mut HlrStatement) {
        if let Some((var, deps, expr)) = self.in_write.take() {
            self.variable_access_log.push((
                var,
                VariableAccessKind::Write {
                    location,
                    expr,
                    deps,
                },
            ));
        }
    }

    fn finish(self) -> Vec<VariableAccessEvent> {
        self.variable_access_log
    }
}

struct IdentifyTemporaryVariables;

impl OptimizationPass for IdentifyTemporaryVariables {
    fn name(&self) -> &str {
        "IdentifyTemporaryVariables"
    }

    fn run(&self, func: &mut HlrFunction) -> bool {
        #[derive(Clone, Debug)]
        struct OptInfo {
            // Number of updates following the initial definition.
            update_count: usize,
            // Statement that sets the variable v=f(deps) where x not in deps. May not exist
            // if X has reads before writes.
            defining_statement: Option<StatementLocation>,
            // Statements that update the variable v = f(deps) where x in deps exactly once.
            updating_statements: Vec<StatementLocation>,
            // Reads that happen to most recent value outside of updates.
            reading_statements: Vec<StatementLocation>,
            // Aggregated set of dependencies, without multiplicities.
            deps: HashSet<HlrVariable>,
            // Latest expression that is assigned to the variable.
            expr: HlrExpression,
            // sets to true means that the candidate is invalid and will not be processed.
            invalid: bool,
            // is the variable being read in this block before it is being written to?
            has_read_before_write: bool,
        }
        let var_access_log = VariableAccessLogger::visit_with_default(func);
        for v in &var_access_log {
            debug!("v={:?}", v);
        }
        let by_block = var_access_log
            .into_iter()
            .into_group_map_by(|(_, access_kind)| match access_kind {
                VariableAccessKind::Write { location, .. } => location.get_containing_block(),
                VariableAccessKind::WriteWithinTuple { location } => {
                    location.get_containing_block()
                }
                VariableAccessKind::Read { location } => location.get_containing_block(),
                VariableAccessKind::FunctionCall { location } => location.get_containing_block(),
                VariableAccessKind::PassedIn => BlockLocation { block_id: 0 },
            });
        fn finalize_var(var: HlrVariable, opt_info: OptInfo) {
            todo!()
        }
        let mut candidates_at_block: HashMap<BlockLocation, HashMap<HlrVariable, OptInfo>> =
            HashMap::new();
        for (block, access_events) in by_block {
            let mut candidates: HashMap<HlrVariable, OptInfo> = HashMap::new();
            for access_event in access_events {
                match access_event {
                    (
                        var,
                        VariableAccessKind::Write {
                            location,
                            expr,
                            deps,
                        },
                    ) => {
                        if var.scope != Scope::Local {
                            continue;
                        }
                        match deps.iter().filter(|v| v.name == var.name).count() {
                            0 => {
                                // variable gets reset to a new value.
                                if candidates.contains_key(&var)
                                    && candidates[&var].reading_statements.len() > 0
                                {
                                    // This happens due to a bug in the SSA converter. See fu2173
                                    // where a phi function unites multiple copies of local1. For now
                                    // we can't optimize since this would destroy the unrelated copy
                                    // and lead to incorrect code. We mark this candidate as invalid
                                    // to prevent it from being re-added by another assignment.
                                    candidates.get_mut(&var).unwrap().invalid = true;
                                } else {
                                    candidates.insert(
                                        var.clone(),
                                        OptInfo {
                                            update_count: 0,
                                            defining_statement: Some(location),
                                            updating_statements: vec![],
                                            reading_statements: vec![],
                                            expr: expr.clone(),
                                            deps: HashSet::new(),
                                            invalid: false,
                                            has_read_before_write: false,
                                        },
                                    );
                                }
                                trace!("Created candidate for {}: {}", var, expr);
                            }
                            1 => {
                                // variable gets updated once. If it is in candidates
                                // for expression propagation we update the expression
                                if let Some(opt_info) = candidates.get_mut(&var) {
                                    if !opt_info.reading_statements.is_empty() {
                                        // Can be implemented later.
                                        unimplemented!(
                                            "Variable {} is updated after read of an update...",
                                            var
                                        );
                                    }
                                    opt_info.update_count += 1;
                                    opt_info.deps.extend(deps);
                                    opt_info.updating_statements.push(location);
                                    opt_info.expr = replace_variable(&expr, &var, &opt_info.expr);
                                } else {
                                    // We have an update before a definition.
                                    candidates.insert(
                                        var.clone(),
                                        OptInfo {
                                            update_count: 0,
                                            defining_statement: None,
                                            updating_statements: vec![],
                                            reading_statements: vec![],
                                            expr: expr.clone(),
                                            deps: HashSet::new(),
                                            invalid: false,
                                            has_read_before_write: true,
                                        },
                                    );
                                }
                            }
                            _ => {
                                trace!("Variable {} is updated more than once: {:?}", var, deps);
                                // variable depends on itself more than once. We do not handle this
                                // for now since it could lead to unintended side effects such as
                                // calling a function twice.
                                candidates.remove(&var);
                            }
                        }
                    }
                    (_, VariableAccessKind::FunctionCall { .. }) => {
                        for (var, opt_info) in &candidates {
                            // On a function call, invalidate all variables that depend on a global
                            // (since function calls can update the global)
                            if opt_info.deps.iter().any(|d| d.scope == Scope::Global) {
                                // finalize_var(var, opt_info)
                            }
                        }
                    }
                    (var, VariableAccessKind::Read { location }) => {
                        if let Some(opt_info) = candidates.get_mut(&var) {
                            opt_info
                                .reading_statements
                                .push(location.get_containing_statement());
                        } else {
                            candidates.insert(
                                var.clone(),
                                OptInfo {
                                    update_count: 0,
                                    defining_statement: None,
                                    updating_statements: vec![],
                                    reading_statements: vec![], // we don't count this as reading statement.
                                    expr: HlrExpression::Variable(var.clone()),
                                    deps: HashSet::new(),
                                    invalid: false,
                                    has_read_before_write: true,
                                },
                            );
                        }
                    }
                    (var, VariableAccessKind::PassedIn) => {
                        candidates.insert(
                            var.clone(),
                            OptInfo {
                                update_count: 0,
                                defining_statement: None,
                                updating_statements: vec![],
                                reading_statements: vec![],
                                expr: HlrExpression::Variable(var.clone()),
                                deps: HashSet::new(),
                                invalid: false,
                                has_read_before_write: false,
                            },
                        );
                    }
                    (var, VariableAccessKind::WriteWithinTuple { location }) => {
                        candidates.insert(
                            var.clone(),
                            OptInfo {
                                update_count: 0,
                                defining_statement: None,
                                updating_statements: vec![],
                                reading_statements: vec![],
                                expr: HlrExpression::Variable(var.clone()),
                                deps: HashSet::new(),
                                invalid: true,
                                has_read_before_write: false,
                            },
                        );
                    }
                };
            }
            candidates_at_block.insert(block.clone(), candidates);
        }
        // let's rule out candidates that have read-before-write on another block.
        let mut to_invalidate = vec![];
        for (block_i, vars_i) in &candidates_at_block {
            for (block_j, vars_j) in &candidates_at_block {
                if block_i == block_j {
                    continue;
                }
                for (var, opt_info) in vars_i {
                    if opt_info.has_read_before_write {
                        // Block i reads the value before assigning to it.
                        // which means that if we optimize at any j, we may
                        // make block i incorrect.
                        if let Some(opt_info) = vars_j.get(var) {
                            to_invalidate.push((*block_j, var.clone()))
                        }
                    }
                }
            }
        }
        for (block, var) in to_invalidate {
            candidates_at_block.get_mut(&block).unwrap().remove(&var);
        }
        // For now just one var at a time...
        for (block, vars) in candidates_at_block {
            for (var, opt_info) in vars {
                if var.scope == Scope::Global {
                    continue;
                }
                if opt_info.invalid {
                    continue;
                }
                let transformer = HlrTransformer::new();
                if opt_info.reading_statements.is_empty() {
                    panic!("Updates with no reads for var={}: {:?}", var, opt_info);
                }
            }
        }

        /*
        // We are looking for variables that are defined and accessed in a single block.
        // They may be updated (written and read in the same statement) any number of times,
        // and only read once after all the updates in the block:
        // Expected pattern is def, (write, read), final read.
        'outer: for (var, access_events) in var_access {
            if var.scope != Scope::Local {
                continue;
            }
            let mut def_block = match &access_events[0] {
                VariableAccessLog::Define(loc, _) => Some(loc.get_containing_block()),
                VariableAccessLog::PassedIn => None,
                _ => continue,
            };
            if access_events.len() % 2 != 0 {
                continue;
            }
            for (write, read) in access_events.iter().skip(1).tuples() {
                let VariableAccessLog::Write(write_statement, write_expr) = write else {
                    continue 'outer;
                };
                let VariableAccessLog::Read(expr_read_location) = read else {
                    continue 'outer;
                };

                if write_statement.get_containing_block()
                    != expr_read_location.get_containing_block()
                {
                    continue 'outer;
                }
                if let Some(actual_def_block) = def_block {
                    if write_statement.get_containing_block() != actual_def_block {
                        continue 'outer;
                    } else {
                        def_block = Some(write_statement.get_containing_block());
                    }
                };

                if expr_read_location.get_containing_statement() != *write_statement {
                    // We are looking for an update, so read and write are on the same statement.
                    continue 'outer;
                }
            }
            if let VariableAccessLog::Read(last_read_location) = access_events.last().unwrap() {
                if def_block.is_some()
                    && Some(last_read_location.get_containing_block()) != def_block
                {
                    continue 'outer;
                }
            }

            if let Some(VariableAccessLog::Define(loc, expr)) = access_events.first() {
                let mut expr = expr.clone();
                let mut transformer = HlrTransformer::new();
                transformer.delete_statement(*loc);
                for (write_event, _read_event) in access_events.iter().skip(1).tuples() {
                    let VariableAccessLog::Write(write_location, write_expr) = write_event else {
                        println!("Unexpected event: {:?}", write_event);
                        unreachable!()
                    };
                    expr = replace_variable(write_expr, &var, &expr);
                    transformer.delete_statement(*write_location);
                }
                transformer.replace_variable(&var, expr.clone());
                transformer.transform(func);
                debug!("Transformed temporary variable var {} to {}", var, expr);
                return true;
            }
        }
        */
        false
    }
}
