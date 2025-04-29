use std::collections::HashMap;

use crate::disasm::hlr::ast::{
    BinaryOperator, HlrAssignmentTarget, HlrExpression, HlrFunction, HlrProgram, HlrStatement,
    HlrVariable, UnaryOperator,
};
use crate::disasm::hlr::visitor::{visit_function, HlrNode, HlrVisitControlFlow, HlrVisitEvent};
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
            let mut f = function.clone();
            for pass in &self.optimizations {
                if pass.run(&mut f) {
                    println!("Pass {} made changes in function {}", pass.name(), f.name);
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
        let mut changed = false;
        visit_function(function, |e| match e {
            HlrVisitEvent::Finish(HlrNode::Statement(stmt)) => {
                if let HlrStatement::If(cond, if_body, else_body) = stmt {
                    if if_body.is_empty() {
                        *cond = cond.logical_not().unwrap();
                        std::mem::swap(if_body, else_body);
                        changed = true;
                    }
                }
                HlrVisitControlFlow::Continue
            }
            HlrVisitEvent::Finish(HlrNode::Expression(expr)) => match expr {
                HlrExpression::BinaryOp {
                    op, left, right, ..
                } => {
                    if *op == BinaryOperator::Add {
                        if let Some(right_num) = right.as_constant_mut().filter(|s| **s < 0) {
                            *op = BinaryOperator::Sub;
                            *right_num = -*right_num;
                            changed = true;
                        }
                    }
                    if *op == BinaryOperator::Mul {
                        if right.as_constant() == Some(-1) {
                            *expr = HlrExpression::UnaryOperator {
                                op: UnaryOperator::Minus,
                                expr: left.clone(),
                            };
                            changed = true;
                        } else if left.as_constant() == Some(-1) {
                            *expr = HlrExpression::UnaryOperator {
                                op: UnaryOperator::Minus,
                                expr: right.clone(),
                            };
                            changed = true;
                        }
                    }

                    // TODO: Handle other cases
                    HlrVisitControlFlow::Continue
                }
                _ => HlrVisitControlFlow::Continue,
            },
            _ => HlrVisitControlFlow::Continue,
        });
        changed
    }
}

struct IdentifyTemporaryVariables;

impl OptimizationPass for IdentifyTemporaryVariables {
    fn name(&self) -> &str {
        "IdentifyTemporaryVariables"
    }

    fn run(&self, function: &mut HlrFunction) -> bool {
        struct VarInfo {
            read_count: usize,
            update_count: usize,
            expr: HlrExpression,
        }

        impl VarInfo {
            fn new(initial: HlrExpression) -> Self {
                Self {
                    read_count: 0,
                    update_count: 0,
                    expr: initial,
                }
            }
        }

        let mut changed = false;
        let mut usage_stack: Vec<HashMap<HlrVariable, VarInfo>> = vec![];
        let mut current_usage = HashMap::new();
        let mut assignee_read_count = 0;
        let mut in_assignment_of = None;
        println!("Analayzing function {}", function.name);
        visit_function(function, |e| match e {
            HlrVisitEvent::Enter(HlrNode::Block(_)) => {
                let mut new_stack = HashMap::new();
                std::mem::swap(&mut new_stack, &mut current_usage);
                usage_stack.push(new_stack);
                HlrVisitControlFlow::Continue
            }
            HlrVisitEvent::Finish(HlrNode::Block(_)) => {
                // handle finish of current usage.
                current_usage = usage_stack.pop().unwrap();
                HlrVisitControlFlow::Continue
            }
            HlrVisitEvent::Enter(HlrNode::Statement(stmt)) => match stmt {
                HlrStatement::VarDef(vs, e) if vs.len() == 1 => {
                    /*
                    assert!(current_usage
                        .insert(vs[0].clone(), VarInfo::new(e.clone()))
                        .is_none());
                        */
                    HlrVisitControlFlow::Continue
                }
                HlrStatement::Assignment(HlrAssignmentTarget::Variable(v), _) => {
                    if !current_usage.contains_key(v) {
                        return HlrVisitControlFlow::Continue;
                    }
                    in_assignment_of = Some(v.clone());
                    assignee_read_count = 0;
                    HlrVisitControlFlow::Continue
                }
                _ => HlrVisitControlFlow::Continue, // TODO: Handle other cases
            },
            /*
            HlrVisitEvent::Enter(HlrNode::Expression(expr)) => {
                match expr {
                    HlrExpression::Variable(v) => {
                        if in_assignment_of.as_ref() == Some(v) {
                            assignee_read_count += 1;
                        }
                        usages.entry(v.clone()).or_default().read_count += 1;
                    }
                    _ => (),
                };
                HlrVisitControlFlow::Continue
            }
            HlrVisitEvent::Finish(HlrNode::Statement(stmt)) => match stmt {
                HlrStatement::Assignment(HlrAssignmentTarget::Variable(ref v), _) => {
                    assert!(in_assignment_of.as_ref() == Some(v));
                    if assignee_read_count == 1 {
                        usages.entry(v.clone()).or_default().update_count += 1;
                        let mut p = CodePrinter::new();
                        pretty_print_statement(&mut p, stmt);
                        println!("Found update of {} at {}", v.name, p.result());
                    }
                    in_assignment_of = None;
                    return HlrVisitControlFlow::Continue;
                }
                _ => HlrVisitControlFlow::Continue,
            },
            */
            _ => HlrVisitControlFlow::Continue,
        });
        changed
    }
}
