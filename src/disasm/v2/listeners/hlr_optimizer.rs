use std::collections::HashMap;

use itertools::Itertools;
use log::{debug, trace};

use crate::disasm::hlr::ast::{
    BinaryOperator, HlrAssignmentTarget, HlrExpression, HlrFunction, HlrProgram, HlrStatement,
    HlrVariable, UnaryOperator,
};
use crate::disasm::hlr::visitor::{ExpressionLocation, HlrFunctionVisitor, StatementLocation};
use crate::disasm::v2::model::ProgramModel;
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
                Box::new(InitialOptimization),
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
            for pass in &self.optimizations {
                if pass.run(&mut f) {
                    trace!("Pass {} made changes in function {}", pass.name(), f.name);
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

struct InitialOptimization;

impl OptimizationPass for InitialOptimization {
    fn name(&self) -> &str {
        "InitialOptimization"
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
                    } => {
                        if *op == BinaryOperator::Add {
                            if let Some(right_num) = right.as_constant_mut().filter(|s| **s < 0) {
                                *op = BinaryOperator::Sub;
                                *right_num = -*right_num;
                                self.changed = true;
                            }
                        }
                        if *op == BinaryOperator::Mul {
                            if right.as_constant() == Some(-1) {
                                *expr = HlrExpression::UnaryOperator {
                                    op: UnaryOperator::Minus,
                                    expr: left.clone(),
                                };
                                self.changed = true;
                            } else if left.as_constant() == Some(-1) {
                                *expr = HlrExpression::UnaryOperator {
                                    op: UnaryOperator::Minus,
                                    expr: right.clone(),
                                };
                                self.changed = true;
                            }
                        }
                    }
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

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
enum VariableAccessEvent {
    // Marks a variable that is passed in to the function
    PassedIn,
    // Point where a variable is defined.
    Define(StatementLocation, HlrExpression),
    // Statement where a variable is written to.
    Write(StatementLocation, HlrExpression),
    // Statement where a variable is read.
    Read(ExpressionLocation),
}

struct VariableAccessAnalyzer {
    variable_access_events: HashMap<HlrVariable, Vec<VariableAccessEvent>>,
}

impl VariableAccessAnalyzer {
    fn new() -> Self {
        Self {
            variable_access_events: HashMap::new(),
        }
    }
}

impl HlrFunctionVisitor<(), HashMap<HlrVariable, Vec<VariableAccessEvent>>>
    for VariableAccessAnalyzer
{
    fn start(&mut self, func: &mut HlrFunction) -> () {
        for var in &func.args {
            self.variable_access_events
                .entry(var.clone())
                .or_default()
                .push(VariableAccessEvent::PassedIn);
        }
    }

    fn enter_statement(&mut self, location: StatementLocation, stmt: &mut HlrStatement) {
        match stmt {
            HlrStatement::VarDef(vs, e) => {
                if vs.len() == 1 {
                    self.variable_access_events
                        .entry(vs[0].clone())
                        .or_default()
                        .push(VariableAccessEvent::Define(location, e.clone()));
                }
            }
            HlrStatement::Assignment(HlrAssignmentTarget::Variable(v), e) => {
                self.variable_access_events
                    .entry(v.clone())
                    .or_default()
                    .push(VariableAccessEvent::Write(location, e.clone()));
            }
            _ => (),
        }
    }

    fn enter_expression(&mut self, location: ExpressionLocation, expr: &mut HlrExpression) {
        match expr {
            HlrExpression::Variable(v) => {
                self.variable_access_events
                    .entry(v.clone())
                    .or_default()
                    .push(VariableAccessEvent::Read(location));
            }
            _ => {}
        }
    }

    fn finish(self) -> HashMap<HlrVariable, Vec<VariableAccessEvent>> {
        self.variable_access_events
    }
}

impl Default for VariableAccessAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

struct IdentifyTemporaryVariables;

impl OptimizationPass for IdentifyTemporaryVariables {
    fn name(&self) -> &str {
        "IdentifyTemporaryVariables"
    }

    fn run(&self, func: &mut HlrFunction) -> bool {
        let var_access = VariableAccessAnalyzer::visit_with_default(func);
        // We are looking for variables that are defined and accessed in a single block.
        // They may be updated (written and read in the same statement) any number of times,
        // and only read once after all the updates in the block:
        // Expected pattern is def, (write, read), final read.
        'outer: for (var, access_events) in var_access {
            let mut def_block = match &access_events[0] {
                VariableAccessEvent::Define(loc, expr) => Some(loc.get_containing_block()),
                VariableAccessEvent::PassedIn => None,
                _ => continue,
            };
            if access_events.len() % 2 != 0 {
                continue;
            }
            for (write, read) in access_events.iter().skip(1).tuples() {
                let VariableAccessEvent::Write(write_statement, write_expr) = write else {
                    continue 'outer;
                };
                let VariableAccessEvent::Read(expr_read_location) = read else {
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
            if let VariableAccessEvent::Read(last_read_location) = access_events.last().unwrap() {
                if def_block.is_some()
                    && Some(last_read_location.get_containing_block()) != def_block
                {
                    continue 'outer;
                }
            }
            debug!("Found a temporary variable var {}:", var);
            for e in access_events {
                match e {
                    VariableAccessEvent::PassedIn => {
                        debug!("  - passed in");
                    }
                    VariableAccessEvent::Define(loc, expr) => {
                        debug!("  - define {:?} at {:?}", expr, loc);
                    }
                    VariableAccessEvent::Write(loc, expr) => {
                        debug!("  - write {} at {:?}", expr, loc);
                    }
                    VariableAccessEvent::Read(loc) => {
                        debug!("  - read at {:?}", loc);
                    }
                }
            }
        }
        true
    }
}
