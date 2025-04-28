use crate::disasm::hlr::ast::{
    BinaryOperator, HlrExpression, HlrFunction, HlrProgram, HlrStatement, UnaryOperator,
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
            optimizations: vec![Box::new(InitialOptimization)],
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
            HlrVisitEvent::Exit(HlrNode::Statement(stmt)) => {
                match stmt {
                    HlrStatement::If(cond, if_body, else_body) => {
                        if if_body.is_empty() {
                            *cond = cond.logical_not().unwrap();
                            std::mem::swap(if_body, else_body);
                            changed = true;
                        }
                    }
                    _ => {}
                }
                HlrVisitControlFlow::Continue
            }
            HlrVisitEvent::Exit(HlrNode::Expression(expr)) => match expr {
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
