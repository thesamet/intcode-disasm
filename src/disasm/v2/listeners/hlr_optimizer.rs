use crate::disasm::hlr::ast::{
    BinaryOperator, HlrExpression, HlrFunction, HlrProgram, HlrStatement, UnaryOperator,
};
use crate::disasm::v2::model::ProgramModel;
use crate::disasm::v2::type_inference::types::Type;
use crate::disasm::Error;

/// Optimizer for high-level representation (HLR) of the program.
///
/// This component performs various transformations on the HLR to make it more readable:
/// - Converting generic loops into more specific constructs (while, for)
/// - Propagating expressions where possible
/// - Creating higher-level expressions from lower-level operations
pub struct HlrOptimizer<'a> {
    model: &'a ProgramModel,
}

impl<'a> HlrOptimizer<'a> {
    pub fn new(model: &'a ProgramModel) -> Self {
        Self { model }
    }

    /// Optimizes the given HLR program by applying various transformations
    pub fn optimize(&self, program: &HlrProgram) -> Result<HlrProgram, Error> {
        let mut optimized_functions = Vec::new();

        // Process each function in the program
        for function in &program.functions {
            let optimized_function = self.optimize_function(function)?;
            optimized_functions.push(optimized_function);
        }

        // Create and return the optimized HLR program
        let optimized_program = HlrProgram {
            functions: optimized_functions,
            globals: program.globals.clone(),
        };

        Ok(optimized_program)
    }

    /// Optimizes a single function by applying transformations to its body
    fn optimize_function(&self, function: &HlrFunction) -> Result<HlrFunction, Error> {
        // Create a new function with the same metadata but optimized body
        let optimized_function = HlrFunction {
            original_id: function.original_id,
            name: function.name.clone(),
            args: function.args.clone(),
            return_type: function.return_type.clone(),
            body: self.optimize_statements(&function.body)?,
        };

        Ok(optimized_function)
    }

    /// Optimizes a list of statements by applying transformations
    fn optimize_statements(&self, statements: &[HlrStatement]) -> Result<Vec<HlrStatement>, Error> {
        let mut out = Vec::new();
        for statement in statements.into_iter() {
            let res = match statement {
                HlrStatement::If(cond, if_body, else_body) => {
                    if if_body.is_empty() {
                        let new_cond = self.optimize_expression(&cond.logical_not().ok_or(
                            Error::AnalysisError("Could not negate if cond".to_string()),
                        )?)?;
                        HlrStatement::If(new_cond, self.optimize_statements(else_body)?, vec![])
                    } else {
                        HlrStatement::If(
                            self.optimize_expression(&cond.clone())?,
                            self.optimize_statements(if_body)?,
                            self.optimize_statements(else_body)?,
                        )
                    }
                }
                HlrStatement::Assignment(target, expr) => {
                    HlrStatement::Assignment(target.clone(), self.optimize_expression(expr)?)
                }
                HlrStatement::While(cond, body) => HlrStatement::While(
                    self.optimize_expression(cond)?,
                    self.optimize_statements(body)?,
                ),
                HlrStatement::DoWhile(body, cond) => HlrStatement::DoWhile(
                    self.optimize_statements(body)?,
                    self.optimize_expression(cond)?,
                ),
                HlrStatement::Loop(body) => HlrStatement::Loop(self.optimize_statements(body)?),
                _ => statement.clone(),
            };
            out.push(res);
        }
        // For now, just return a clone of the original statements
        // This will be expanded with actual optimizations in the future
        Ok(out)
    }

    fn optimize_expression(&self, expr: &HlrExpression) -> Result<HlrExpression, Error> {
        match expr {
            HlrExpression::BinaryOp {
                op,
                left,
                right,
                result_type,
            } => self.optimize_binary_op(*op, left, right, result_type),
            HlrExpression::FunctionCall(func_expr, func_args) => Ok(HlrExpression::FunctionCall(
                func_expr.clone(),
                func_args.clone(),
            )),
            HlrExpression::Tuple(exprs) => Ok(HlrExpression::Tuple(
                exprs
                    .iter()
                    .map(|expr| self.optimize_expression(expr))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            HlrExpression::Input() => Ok(HlrExpression::Input()),
            HlrExpression::Variable(var) => Ok(HlrExpression::Variable(var.clone())),
            HlrExpression::Deref(var) => Ok(HlrExpression::Deref(var.clone())),
            HlrExpression::Constant(val, ty) => Ok(HlrExpression::Constant(*val, ty.clone())),
            HlrExpression::UnaryOperator { op, expr } => Ok(HlrExpression::UnaryOperator {
                op: op.clone(),
                expr: Box::new(self.optimize_expression(expr)?),
            }),
        }
    }

    fn optimize_binary_op(
        &self,
        op: BinaryOperator,
        left: &HlrExpression,
        right: &HlrExpression,
        result_type: &Type,
    ) -> Result<HlrExpression, Error> {
        match op {
            BinaryOperator::Add => {
                match &right {
                    HlrExpression::Constant(v, t) if *v < 0 => {
                        return self.optimize_binary_op(
                            BinaryOperator::Sub,
                            left,
                            &HlrExpression::Constant(-v, t.clone()),
                            result_type,
                        )
                    }
                    _ => {}
                };
                Ok(HlrExpression::BinaryOp {
                    op: op.clone(),
                    left: Box::new(self.optimize_expression(left)?),
                    right: Box::new(self.optimize_expression(right)?),
                    result_type: result_type.clone(),
                })
            }
            BinaryOperator::Mul => {
                match &left {
                    HlrExpression::Constant(v, _) if *v == -1 => {
                        return self.optimize_expression(&HlrExpression::UnaryOperator {
                            op: UnaryOperator::Minus,
                            expr: Box::new(self.optimize_expression(right)?),
                        })
                    }
                    _ => {}
                };
                match &right {
                    HlrExpression::Constant(v, _) if *v == -1 => {
                        return self.optimize_expression(&HlrExpression::UnaryOperator {
                            op: UnaryOperator::Minus,
                            expr: Box::new(self.optimize_expression(left)?),
                        })
                    }
                    _ => {}
                };
                Ok(HlrExpression::BinaryOp {
                    op: op.clone(),
                    left: Box::new(self.optimize_expression(left)?),
                    right: Box::new(self.optimize_expression(right)?),
                    result_type: result_type.clone(),
                })
            }
            BinaryOperator::Sub => Ok(HlrExpression::BinaryOp {
                op: op.clone(),
                left: Box::new(self.optimize_expression(left)?),
                right: Box::new(self.optimize_expression(right)?),
                result_type: result_type.clone(),
            }),
            _ => Ok(HlrExpression::BinaryOp {
                op,
                left: Box::new(self.optimize_expression(left)?),
                right: Box::new(self.optimize_expression(right)?),
                result_type: result_type.clone(),
            }),
        }
    }
}
