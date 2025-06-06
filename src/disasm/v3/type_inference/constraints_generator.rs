// disasm/src/disasm/v3/type_inference/analyzer.rs

use itertools::Itertools;
use log::{trace, warn};

use crate::disasm::v3::cfg::BlockView;
use crate::disasm::v3::lir::{
    BinaryOperator, Expression, ExpressionPath, ExpressionPathElement, Instruction,
    MemoryReferenceInfo, TypeVarPath,
};
use crate::disasm::v3::model::{FoldedSsaComplete, Model};
use crate::disasm::v3::ssa::converter::PhiFunction;
use crate::disasm::v3::ssa::SsaMemoryReference;
use crate::disasm::{self, SymbolRenaming};
// SsaBlock was unused
use crate::disasm::v3::lir::InstructionNode;
// Assuming this is generic over SsaMemoryReference
use crate::disasm::v3::{FunctionId, InstructionId};

use super::constraints::{Constraint, ConstraintReason, ConstraintStore};
use super::type_bounds_map::InferenceAlgorithmState;
use super::types::{Type, TypeVarId};
// TypeVarNode is defined in types.rs and re-exported by the parent module.
use super::types::TypeVarNode;

use std::collections::HashMap;

pub struct TypeConstraintGeneratorResult {
    pub state: InferenceAlgorithmState,
    pub store: ConstraintStore,
    pub markers: HashMap<char, TypeVarId>, // Type of markers might need adjustment based on actual usage
    pub function_types: HashMap<FunctionId, (Type, Type)>,
    pub global_vars: HashMap<usize, TypeVarId>,
}

pub struct TypeConstraintGenerator<'a> {
    // References to external data structures
    model: &'a Model<FoldedSsaComplete>,
    symbol_renaming: &'a SymbolRenaming,
    result: TypeConstraintGeneratorResult,
}

impl<'a> TypeConstraintGenerator<'a> {
    fn new(model: &'a Model<FoldedSsaComplete>, symbol_renaming: &'a SymbolRenaming) -> Self {
        TypeConstraintGenerator {
            model,
            symbol_renaming,
            result: TypeConstraintGeneratorResult {
                state: InferenceAlgorithmState::new(),
                store: ConstraintStore::new(),
                markers: HashMap::new(),
                function_types: HashMap::new(),
                global_vars: HashMap::new(),
            },
        }
    }

    // Iterates through the SSA model (conceptual)
    fn generate_all_constraints(&mut self) {
        trace!("Generating constraints for model");
        for (function_id, f) in self.model.functions().sorted_by_key(|f| f.0) {
            let args = self.result.state.add_type_var(TypeVarNode {
                path: TypeVarPath::FunctionDefArgTuple { function_id },
                vmr: None,
            });
            let returns = self.result.state.add_type_var(TypeVarNode {
                path: TypeVarPath::FunctionDefRetTuple { function_id },
                vmr: None,
            });
            self.result
                .function_types
                .insert(function_id, (args.to_type(), returns.to_type()));
            let mut args_tuple = vec![];
            let mut rets_tuple = vec![];
            for (idx, v) in f.callee_info().parameter_entry_vars.iter().sorted() {
                args_tuple.push(
                    self.result
                        .state
                        .get_or_create_type_var_for_vmr(
                            v,
                            TypeVarPath::FunctionDefArg {
                                function_id,
                                index: *idx as usize,
                            },
                        )
                        .to_type(),
                );
            }
            for (idx, v) in f.callee_info().return_writes.iter().sorted() {
                rets_tuple.push(
                    self.result
                        .state
                        .get_or_create_type_var_for_vmr(
                            v,
                            TypeVarPath::FunctionDefRet {
                                function_id,
                                index: *idx as usize,
                            },
                        )
                        .to_type(),
                );
            }
            self.result.store.add_equality_constraint(
                Constraint::new(
                    args.to_type(),
                    Type::tuple(&args_tuple),
                    function_id,
                    InstructionId::new(0), // Dummy ID for function args
                    ConstraintReason::CalleeFunctionArguments,
                ),
                None,
                &self.result.state,
            );
            self.result.store.add_equality_constraint(
                Constraint::new(
                    returns.to_type(),
                    Type::tuple(&rets_tuple),
                    function_id,
                    InstructionId::new(0), // Dummy ID for function args
                    ConstraintReason::CalleeFunctionReturns,
                ),
                None,
                &self.result.state,
            );
        }

        for (function_id, f) in self.model.functions().sorted_by_key(|f| f.0) {
            for (_block_id, ssa_block_content) in f.blocks().sorted_by_key(|b| b.0) {
                // blocks is BTreeMap<BlockId, SsaBlock>
                // Process Phi functions first for the block
                let phi_origin_instruction_id = ssa_block_content
                    .low_instructions()
                    .first()
                    .map_or_else(|| InstructionId::new(0), |instr| instr.id); // Use first instruction's ID or a dummy

                for phi_function in &ssa_block_content.ssa().phi_functions {
                    self.process_phi_function(phi_function, function_id, phi_origin_instruction_id);
                }

                // Process instructions
                for instruction_node in &ssa_block_content.folded_ssa().instructions {
                    self.generate_constraints_for_instruction(
                        &ssa_block_content,
                        instruction_node,
                        function_id,
                    );
                }
            }
        }

        for (addr, tv_id, var) in self
            .result
            .state
            .iter_all_vmr_to_type_var_id()
            .filter_map(|(var, tv_id)| var.as_global().map(|addr| (addr, tv_id, var)))
            .sorted()
        {
            if let Some(canonical_id) = self.result.global_vars.get(&addr) {
                self.result.store.add_equality_constraint(
                    Constraint::new(
                        Type::TypeVar(*canonical_id),
                        Type::TypeVar(*tv_id),
                        var.function_id,
                        InstructionId::new(0), // Dummy ID for function args
                        ConstraintReason::GlobalVariable(addr),
                    ),
                    None,
                    &self.result.state,
                );
            } else {
                self.result.global_vars.insert(addr, *tv_id);
            }
        }

        for (vmr, (_, ty)) in self.symbol_renaming.get_variables() {
            let Some(ty) = ty else {
                continue;
            };
            let Some(tv_id) = self.result.state.get_type_id_for_vmr(vmr) else {
                warn!("Could not find type var for {}", vmr);
                continue;
            };
            self.result.store.add_equality_constraint(
                Constraint::new(
                    Type::TypeVar(tv_id),
                    ty.clone(),
                    vmr.function_id,
                    InstructionId::new(0), // Dummy ID for function args
                    ConstraintReason::SymbolRenaming,
                ),
                None,
                &self.result.state,
            );
        }
    }

    fn process_phi_function(
        &mut self,
        phi: &PhiFunction, // Assuming PhiFunction structure
        function_id: FunctionId,
        phi_origin_instruction_id: InstructionId, // ID representing the phi node location
    ) {
        let dest_tv_id = self.result.state.get_or_create_type_var_for_vmr(
            &phi.result, // PhiFunction uses 'result'
            TypeVarPath::PhiAssignment {
                function_id,
                instruction_id: phi_origin_instruction_id,
            },
        );

        for (index, incoming_vmr) in phi.inputs.values().enumerate() {
            // PhiFunction uses 'inputs'
            // inputs: Vec<(BlockId, VersionedMemoryReference)>
            let incoming_tv_id = self.result.state.get_or_create_type_var_for_vmr(
                incoming_vmr,
                TypeVarPath::PhiAssignmentArg {
                    function_id,
                    instruction_id: phi_origin_instruction_id,
                    index,
                },
            );

            self.result.store.add_equality_constraint(
                Constraint::new(
                    incoming_tv_id.to_type(),
                    dest_tv_id.to_type(),
                    function_id,
                    phi_origin_instruction_id,
                    ConstraintReason::PhiNodeOperand,
                ),
                None,
                &self.result.state,
            );
        }
    }

    fn generate_constraints_for_instruction(
        &mut self,
        block: &BlockView<'a, FoldedSsaComplete>,
        instruction_node: &InstructionNode<SsaMemoryReference>,
        function_id: FunctionId,
    ) {
        let instruction_id = instruction_node.id;
        trace!(
            "Generating constraints for instruction {}: {}",
            instruction_id,
            instruction_node
        );

        match &instruction_node.kind {
            Instruction::Assign {
                target,
                src,
                target_debug_marker,
            } => {
                let src_type = self.process_expression(
                    src,
                    function_id,
                    instruction_id,
                    TypeVarPath::AssignmentSrc {
                        function_id,
                        instruction_id,
                        expression_path: ExpressionPath::root(),
                    },
                );

                match target {
                    SsaMemoryReference::Versioned(vmr_target) => {
                        let target_tv_id = self.result.state.get_or_create_type_var_for_vmr(
                            vmr_target,
                            TypeVarPath::AssignmentTargetVersioned {
                                function_id,
                                instruction_id,
                                vmr: *vmr_target,
                            },
                        );
                        let target_type = Type::TypeVar(target_tv_id);

                        self.result.store.add_equality_constraint(
                            Constraint::new(
                                Type::TypeVar(src_type),
                                target_type.clone(),
                                function_id,
                                instruction_id,
                                ConstraintReason::Assignment,
                            ),
                            None,
                            &self.result.state,
                        );
                        if let Some(debug_marker) = target_debug_marker {
                            self.result.markers.insert(*debug_marker, target_tv_id);
                        }
                    }
                    SsaMemoryReference::Deref(ptr_expr_target) => {
                        let ptr_addr_type = self.process_expression(
                            ptr_expr_target.as_ref(), // ptr_expr_target is Box<Expression>
                            function_id,
                            instruction_id,
                            TypeVarPath::AssignmentTargetDeref {
                                function_id,
                                instruction_id,
                                expression_path: ExpressionPath::root(),
                            },
                        );
                        self.result.store.add_equality_constraint(
                            Constraint::new(
                                Type::TypeVar(ptr_addr_type),
                                Type::Pointer(Box::new(Type::TypeVar(src_type))),
                                function_id,
                                instruction_id,
                                ConstraintReason::AssignmentToDereferenceTarget,
                            ),
                            None,
                            &self.result.state,
                        );
                    }
                }
            }
            Instruction::If { cond, .. } => {
                let cond_type = self.process_expression(
                    cond,
                    function_id,
                    instruction_id,
                    TypeVarPath::IfCond {
                        function_id,
                        instruction_id,
                        expression_path: ExpressionPath::root(),
                    },
                );
                self.result.store.add_constraint(
                    Constraint::new(
                        cond_type.to_type(),
                        Type::Truthy,
                        function_id,
                        instruction_id,
                        ConstraintReason::IfConditionOperand,
                    ),
                    None,
                    &self.result.state,
                );
            }
            Instruction::Output(expr) => {
                let expr_type = self.process_expression(
                    expr,
                    function_id,
                    instruction_id,
                    TypeVarPath::Output {
                        function_id,
                        instruction_id,
                        expression_path: ExpressionPath::root(),
                    },
                );
                self.result.store.add_equality_constraint(
                    Constraint::new(
                        expr_type.to_type(),
                        Type::Char,
                        function_id,
                        instruction_id,
                        ConstraintReason::OutputValueType,
                    ),
                    None,
                    &self.result.state,
                );
            }
            Instruction::Call { addr, args, .. } => {
                let addr_var_id = self.process_expression(
                    addr,
                    function_id,
                    instruction_id,
                    TypeVarPath::CallAddress {
                        function_id,
                        instruction_id,
                        expression_path: ExpressionPath::root(),
                    },
                );

                let mut arg_type_tuple = vec![];
                for (index, arg) in args.iter().enumerate() {
                    arg_type_tuple.push(
                        self.process_expression(
                            arg,
                            function_id,
                            instruction_id,
                            TypeVarPath::CallArg {
                                function_id,
                                instruction_id,
                                index,
                                expression_path: ExpressionPath::root(),
                            },
                        )
                        .to_type(),
                    );
                }
                let arg_type_tuple = Type::tuple(&arg_type_tuple);

                let mut ret_type_tuple = vec![];
                for (idx, ret) in block.call_site_info().return_reads.iter() {
                    ret_type_tuple.push(
                        self.result
                            .state
                            .get_or_create_type_var_for_vmr(
                                ret,
                                TypeVarPath::CallRet {
                                    function_id,
                                    instruction_id,
                                    index: *idx as usize,
                                    vmr: *ret,
                                },
                            )
                            .to_type(),
                    );
                }
                let ret_type_tuple = Type::tuple(&ret_type_tuple);
                let args_id = self.result.state.add_type_var(TypeVarNode {
                    path: TypeVarPath::CallArgTuple {
                        function_id,
                        instruction_id,
                    },
                    vmr: None,
                });

                let rets_id = self.result.state.add_type_var(TypeVarNode {
                    path: TypeVarPath::CallRetTuple {
                        function_id,
                        instruction_id,
                    },
                    vmr: None,
                });

                let fp = Type::function(args_id.to_type(), rets_id.to_type());
                self.result.store.add_constraint(
                    Constraint::new(
                        addr_var_id.to_type(),
                        fp,
                        function_id,
                        instruction_id,
                        ConstraintReason::FunctionCallImpliesFunctionType,
                    ),
                    None,
                    &self.result.state,
                );
                self.result.store.add_equality_constraint(
                    Constraint::new(
                        args_id.to_type(),
                        arg_type_tuple,
                        function_id,
                        instruction_id,
                        ConstraintReason::FunctionCallArguments,
                    ),
                    None,
                    &self.result.state,
                );
                self.result.store.add_equality_constraint(
                    Constraint::new(
                        ret_type_tuple,
                        rets_id.to_type(),
                        function_id,
                        instruction_id,
                        ConstraintReason::FunctionCallReturns,
                    ),
                    None,
                    &self.result.state,
                );
                if let Expression::Constant(direct_addr) = addr {
                    if let Some((callee_arg_type, callee_ret_type)) = self
                        .result
                        .function_types
                        .get(&FunctionId::new(*direct_addr as usize))
                    {
                        self.result.store.add_constraint(
                            Constraint::new(
                                args_id.to_type(),
                                callee_arg_type.clone(),
                                function_id,
                                instruction_id,
                                ConstraintReason::FunctionCallArgumentsBinding,
                            ),
                            None,
                            &self.result.state,
                        );
                        self.result.store.add_constraint(
                            Constraint::new(
                                callee_ret_type.clone(),
                                rets_id.to_type(),
                                function_id,
                                instruction_id,
                                ConstraintReason::FunctionCallReturnsBinding,
                            ),
                            None,
                            &self.result.state,
                        );
                    }
                }
            }

            // TODO: Handle If, Call, Output, Return for SsaMemoryReference
            // Example for If:
            // crate::disasm::v3::lir::Instruction::If { cond, .. } => {
            //     let cond_type = self.process_expression(cond, function_id, instruction_id, state, store);
            //     // Need a new ConstraintReason::IfConditionOperand
            //     store.add_constraint(Constraint::new(cond_type, Type::Truthy, function_id, instruction_id, ConstraintReason::ComparisonOperand /* Placeholder */));
            // }
            _ => {}
        }
    }

    fn process_expression(
        &mut self,
        expr: &Expression<SsaMemoryReference>,
        function_id: FunctionId,
        instruction_id: InstructionId,
        path: TypeVarPath,
    ) -> TypeVarId {
        match expr {
            Expression::Constant(_) => {
                let tv_id = self.result.state.make_const_type_var(path);
                let const_type = Type::TypeVar(tv_id);

                // Need a new ConstraintReason::LiteralInteger
                self.result.store.add_constraint(
                    Constraint::new(
                        const_type.clone(),
                        Type::NumericLiteral,
                        function_id,
                        instruction_id,
                        ConstraintReason::NumericLiteral,
                    ),
                    None,
                    &self.result.state,
                );
                // If val is 0 or 1, could add specific constraints for Bool/Truthy
                // E.g., ConstraintReason::LiteralBoolean, ConstraintReason::LiteralTruthy
                tv_id
            }
            Expression::Addressable(ssa_ref) => match ssa_ref {
                SsaMemoryReference::Versioned(vmr) => {
                    self.result.state.get_or_create_type_var_for_vmr(vmr, path)
                }
                SsaMemoryReference::Deref(inner_ptr_expr) => {
                    let ptr_addr_type_var_id = self.process_expression(
                        inner_ptr_expr,
                        function_id,
                        instruction_id,
                        path.extending_path_element(ExpressionPathElement::Deref),
                    );

                    let pointee_tv_id = self.result.state.make_expression_type_var(path);
                    let pointee_type = Type::TypeVar(pointee_tv_id);

                    self.result.store.add_equality_constraint(
                        Constraint::new(
                            Type::TypeVar(ptr_addr_type_var_id),
                            Type::Pointer(Box::new(pointee_type.clone())),
                            function_id,
                            instruction_id,
                            ConstraintReason::DereferenceRequiresPointer,
                        ),
                        None,
                        &self.result.state,
                    );
                    pointee_tv_id
                }
            },
            Expression::Binary { op, lhs, rhs } => {
                let lhs_type = Type::TypeVar(self.process_expression(
                    lhs,
                    function_id,
                    instruction_id,
                    path.extending_path_element(ExpressionPathElement::BinaryLeft),
                ));
                let rhs_type = Type::TypeVar(self.process_expression(
                    rhs,
                    function_id,
                    instruction_id,
                    path.extending_path_element(ExpressionPathElement::BinaryRight),
                ));
                let result_tv_id = self.result.state.make_expression_type_var(path);
                let result_type = Type::TypeVar(result_tv_id);

                match op {
                    disasm::v3::lir::expression::BinaryOperator::Add
                    | disasm::v3::lir::expression::BinaryOperator::Sub => {
                        self.result.store.add_unclassified_add_expression(
                            expr.clone(),
                            lhs_type.clone(),
                            rhs_type.clone(),
                            result_type.clone(),
                        );
                    }
                    disasm::v3::lir::expression::BinaryOperator::Mul => {
                        // Need ConstraintReason::ArithmeticLHS, ArithmeticRHS, ArithmeticResult
                        self.result.store.add_equality_constraint(
                            Constraint::new(
                                lhs_type.clone(),
                                Type::Int,
                                function_id,
                                instruction_id,
                                ConstraintReason::ArithmeticLHS,
                            ),
                            None,
                            &self.result.state,
                        );
                        self.result.store.add_equality_constraint(
                            Constraint::new(
                                rhs_type.clone(),
                                Type::Int,
                                function_id,
                                instruction_id,
                                ConstraintReason::ArithmeticRHS,
                            ),
                            None,
                            &self.result.state,
                        );
                        self.result.store.add_equality_constraint(
                            Constraint::new(
                                result_type.clone(),
                                Type::Int,
                                function_id,
                                instruction_id,
                                ConstraintReason::ArithmeticResult,
                            ),
                            None,
                            &self.result.state,
                        );
                    }
                    BinaryOperator::GreaterThan
                    | BinaryOperator::LessThan
                    | BinaryOperator::Equals
                    | BinaryOperator::NotEquals
                    | BinaryOperator::LessThanOrEqual
                    | BinaryOperator::GreaterThanOrEqual => {
                        self.result.store.add_equality_constraint(
                            Constraint::new(
                                result_type.clone(),
                                Type::Bool,
                                function_id,
                                instruction_id,
                                ConstraintReason::ComparisonResult,
                            ),
                            None,
                            &self.result.state,
                        );
                    }
                }
                match op {
                    BinaryOperator::LessThan
                    | BinaryOperator::GreaterThan
                    | BinaryOperator::LessThanOrEqual
                    | BinaryOperator::GreaterThanOrEqual => {
                        // Need ConstraintReason::ComparisonLHS, ComparisonRHS, ComparisonResult
                        self.result.store.add_equality_constraint(
                            Constraint::new(
                                lhs_type,
                                Type::Int,
                                function_id,
                                instruction_id,
                                ConstraintReason::ComparisonLHS,
                            ),
                            None,
                            &self.result.state,
                        );
                        self.result.store.add_equality_constraint(
                            Constraint::new(
                                rhs_type,
                                Type::Int,
                                function_id,
                                instruction_id,
                                ConstraintReason::ComparisonRHS,
                            ),
                            None,
                            &self.result.state,
                        );
                    }
                    BinaryOperator::Equals | BinaryOperator::NotEquals => {
                        self.result.store.add_equality_constraint(
                            Constraint::new(
                                lhs_type,
                                rhs_type,
                                function_id,
                                instruction_id,
                                ConstraintReason::EqualityComparisonSameType,
                            ),
                            None,
                            &self.result.state,
                        );
                    }
                    _ => {}
                }
                result_tv_id
            }
            Expression::Unary { op, arg } => {
                let arg_type = self.process_expression(
                    arg,
                    function_id,
                    instruction_id,
                    path.extending_path_element(ExpressionPathElement::Unary),
                );
                let result_tv_id = self.result.state.make_expression_type_var(path);
                let result_type = Type::TypeVar(result_tv_id);

                match op {
                    disasm::v3::lir::expression::UnaryOperator::Not => {
                        // Need ConstraintReason::NotOperand, NotResult
                        self.result.store.add_constraint(
                            Constraint::new(
                                Type::TypeVar(arg_type),
                                Type::NumericLiteral, // Operand of NOT must be Truthy
                                function_id,
                                instruction_id,
                                ConstraintReason::NotOperand,
                            ),
                            None,
                            &self.result.state,
                        );
                        self.result.store.add_constraint(
                            Constraint::new(
                                result_type.clone(),
                                Type::Bool, // Result of NOT is Bool
                                function_id,
                                instruction_id,
                                ConstraintReason::NotResult,
                            ),
                            None,
                            &self.result.state,
                        );
                    }
                    disasm::v3::lir::expression::UnaryOperator::Minus => {
                        self.result.store.add_constraint(
                            Constraint::new(
                                Type::TypeVar(arg_type),
                                Type::Int,
                                function_id,
                                instruction_id,
                                ConstraintReason::UnaryMinusOperand,
                            ),
                            None,
                            &self.result.state,
                        );
                        self.result.store.add_constraint(
                            Constraint::new(
                                result_type.clone(),
                                Type::Int,
                                function_id,
                                instruction_id,
                                ConstraintReason::UnaryMinusResult,
                            ),
                            None,
                            &self.result.state,
                        );
                    }
                }
                result_tv_id
            }
            Expression::Input() => {
                let tv_id = self.result.state.make_expression_type_var(path);
                let input_type = Type::TypeVar(tv_id);
                // Need ConstraintReason::InputSourceType
                self.result.store.add_constraint(
                    Constraint::new(
                        input_type,
                        Type::Char, // Assuming input is Char by default
                        function_id,
                        instruction_id,
                        ConstraintReason::InputSourceType,
                    ),
                    None,
                    &self.result.state,
                );
                tv_id
            }
            Expression::DebugMarker(marker, inner_expr) => {
                let expr_type =
                    self.process_expression(inner_expr, function_id, instruction_id, path);
                self.result.markers.insert(*marker, expr_type);
                expr_type
            }
        }
    }
}

pub fn generate_constraints(
    model: &Model<FoldedSsaComplete>,
    symbol_renaming: &SymbolRenaming,
) -> TypeConstraintGeneratorResult {
    let mut constraint_generator = TypeConstraintGenerator::new(model, symbol_renaming);
    constraint_generator.generate_all_constraints();
    constraint_generator.result
}
