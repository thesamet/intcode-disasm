// disasm/src/disasm/v3/type_inference/analyzer.rs

use crate::disasm::v3::lir::Expression;
use crate::disasm::v3::model::{FoldedSsaComplete, Model};
use crate::disasm::v3::ssa::converter::PhiFunction;
use crate::disasm::v3::ssa::{SsaMemoryReference, VersionedMemoryReference};
// SsaBlock was unused
use crate::disasm::v3::lir::InstructionNode; // Assuming this is generic over SsaMemoryReference
use crate::disasm::v3::{FunctionId, InstructionId};

use super::constraints::{Constraint, ConstraintReason, ConstraintStore};
use super::type_bounds_map::{InferenceAlgorithmState, TypeVarId};
use super::types::{Type, TypeVarKind};
// TypeVarNode is defined in types.rs and re-exported by the parent module.
use super::types::TypeVarNode;

use std::collections::HashMap;

pub struct TypeInferenceAnalyzer {
    next_type_var_id_counter: usize,
    // Maps a (FunctionId, VersionedMemoryReference) to a TypeVarId.
    // This ensures that each unique versioned memory reference gets one TypeVar.
    vmr_to_type_var: HashMap<VersionedMemoryReference, TypeVarId>,

    markers: HashMap<char, Type>,
}

impl TypeInferenceAnalyzer {
    pub fn new() -> Self {
        TypeInferenceAnalyzer {
            next_type_var_id_counter: 0,
            vmr_to_type_var: HashMap::new(),
            markers: HashMap::new(),
        }
    }

    fn fresh_type_var_id(&mut self) -> TypeVarId {
        let id = self.next_type_var_id_counter;
        self.next_type_var_id_counter += 1;
        id // Assuming TypeVarId = usize
    }

    /// Gets or creates a TypeVar for a VersionedMemoryReference within a specific function.
    fn get_or_create_type_var_for_vmr(
        &mut self,
        vmr: &VersionedMemoryReference,
        function_id: FunctionId, // Function where this VMR is defined/used
        instruction_id: InstructionId, // Instruction that "introduces" this VMR to typing
        state: &mut InferenceAlgorithmState,
    ) -> TypeVarId {
        if let Some(tv_id) = self.vmr_to_type_var.get(vmr) {
            return *tv_id;
        }

        // When creating a TypeVar for a VMR, its kind is MemoryReference.
        // We wrap the VMR in SsaMemoryReference::Versioned for the TypeVarKind.
        let ssa_ref_for_kind = SsaMemoryReference::Versioned(*vmr);
        let new_tv_id = self.create_memory_reference_type_var(
            function_id,
            instruction_id,
            &ssa_ref_for_kind,
            state,
        );
        self.vmr_to_type_var.insert(vmr.clone(), new_tv_id);
        new_tv_id
    }

    /// Creates a new TypeVar for an expression result or intermediate value.
    fn make_expression_type_var(
        &mut self,
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression: &Expression<SsaMemoryReference>,
        state: &mut InferenceAlgorithmState,
    ) -> TypeVarId {
        let tv_id = self.fresh_type_var_id();
        let node_info = TypeVarNode {
            kind: TypeVarKind::Expression(expression.clone()),
            instruction_id,
            function_id,
        };
        state.add_type_var(tv_id, node_info);
        tv_id
    }

    fn make_const_type_var(
        &mut self,
        function_id: FunctionId,
        instruction_id: InstructionId,
        const_val: i128,
        state: &mut InferenceAlgorithmState,
    ) -> TypeVarId {
        let tv_id = self.fresh_type_var_id();
        let node_info = TypeVarNode {
            kind: TypeVarKind::Const(const_val),
            instruction_id,
            function_id,
        };
        state.add_type_var(tv_id, node_info);
        tv_id
    }

    fn create_memory_reference_type_var(
        &mut self,
        function_id: FunctionId,
        instruction_id: InstructionId,
        ssa_memref: &SsaMemoryReference,
        state: &mut InferenceAlgorithmState,
    ) -> TypeVarId {
        let tv_id = self.fresh_type_var_id();
        let node_info = TypeVarNode {
            kind: TypeVarKind::MemoryReference(ssa_memref.clone()),
            instruction_id,
            function_id,
        };
        state.add_type_var(tv_id, node_info);
        tv_id
    }

    // Iterates through the SSA model (conceptual)
    pub fn generate_constraints(
        &mut self,
        model: &Model<FoldedSsaComplete>,
        state: &mut InferenceAlgorithmState,
        store: &mut ConstraintStore,
    ) {
        for (function_id, f) in model.functions() {
            for (_block_id, ssa_block_content) in f.blocks() {
                // blocks is BTreeMap<BlockId, SsaBlock>
                // Process Phi functions first for the block
                let phi_origin_instruction_id = ssa_block_content
                    .low_instructions()
                    .first()
                    .map_or_else(|| InstructionId::new(0), |instr| instr.id); // Use first instruction's ID or a dummy

                for phi_function in &ssa_block_content.ssa().phi_functions {
                    self.process_phi_function(
                        phi_function,
                        function_id,
                        phi_origin_instruction_id,
                        state,
                        store,
                    );
                }

                // Process instructions
                for instruction_node in &ssa_block_content.folded_ssa().instructions {
                    self.generate_constraints_for_instruction(
                        instruction_node,
                        function_id,
                        state,
                        store,
                    );
                }
            }
        }
    }

    fn process_phi_function(
        &mut self,
        phi: &PhiFunction, // Assuming PhiFunction structure
        function_id: FunctionId,
        phi_origin_instruction_id: InstructionId, // ID representing the phi node location
        state: &mut InferenceAlgorithmState,
        store: &mut ConstraintStore,
    ) {
        let dest_tv_id = self.get_or_create_type_var_for_vmr(
            &phi.result, // PhiFunction uses 'result'
            function_id,
            phi_origin_instruction_id,
            state,
        );
        let dest_type = Type::TypeVar(dest_tv_id);

        for (_block_id, incoming_vmr) in &phi.inputs {
            // PhiFunction uses 'inputs'
            // inputs: Vec<(BlockId, VersionedMemoryReference)>
            let incoming_tv_id = self.get_or_create_type_var_for_vmr(
                incoming_vmr,
                function_id,
                phi_origin_instruction_id, // Source VMRs contribute to the phi at this point
                state,
            );
            let incoming_type = Type::TypeVar(incoming_tv_id);

            store.add_constraint(Constraint::new(
                incoming_type,
                dest_type.clone(),
                function_id,
                phi_origin_instruction_id,
                ConstraintReason::PhiNodeOperand,
            ));
        }
    }

    fn generate_constraints_for_instruction(
        &mut self,
        instruction_node: &InstructionNode<SsaMemoryReference>,
        function_id: FunctionId,
        state: &mut InferenceAlgorithmState,
        store: &mut ConstraintStore,
    ) {
        let instruction_id = instruction_node.id;

        match &instruction_node.kind {
            crate::disasm::v3::lir::Instruction::Assign { target, src, .. } => {
                let src_type =
                    self.process_expression(&src, function_id, instruction_id, state, store);

                match target {
                    SsaMemoryReference::Versioned(vmr_target) => {
                        let target_tv_id = self.get_or_create_type_var_for_vmr(
                            &vmr_target,
                            function_id,
                            instruction_id,
                            state,
                        );
                        let target_type = Type::TypeVar(target_tv_id);

                        store.add_constraint(Constraint::new(
                            src_type,
                            target_type,
                            function_id,
                            instruction_id,
                            ConstraintReason::Assignment,
                        ));
                    }
                    SsaMemoryReference::Deref(ptr_expr_target) => {
                        let ptr_addr_type = self.process_expression(
                            ptr_expr_target.as_ref(), // ptr_expr_target is Box<Expression>
                            function_id,
                            instruction_id,
                            state,
                            store,
                        );
                        store.add_constraint(Constraint::new(
                            ptr_addr_type,
                            Type::Pointer(Box::new(src_type.clone())),
                            function_id,
                            instruction_id,
                            ConstraintReason::AssignmentToDereferenceTarget,
                        ));
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
        state: &mut InferenceAlgorithmState,
        store: &mut ConstraintStore,
    ) -> Type {
        match expr {
            Expression::Constant(val) => {
                let tv_id = self.make_const_type_var(function_id, instruction_id, *val, state);
                let const_type = Type::TypeVar(tv_id);

                // Need a new ConstraintReason::LiteralInteger
                store.add_constraint(Constraint::new(
                    const_type.clone(),
                    Type::Int,
                    function_id,
                    instruction_id,
                    ConstraintReason::LiteralInteger,
                ));
                // If val is 0 or 1, could add specific constraints for Bool/Truthy
                // E.g., ConstraintReason::LiteralBoolean, ConstraintReason::LiteralTruthy
                const_type
            }
            Expression::Addressable(ssa_ref) => match ssa_ref {
                SsaMemoryReference::Versioned(vmr) => {
                    let tv_id = self.get_or_create_type_var_for_vmr(
                        vmr,
                        function_id,
                        instruction_id,
                        state,
                    );
                    Type::TypeVar(tv_id)
                }
                SsaMemoryReference::Deref(inner_ptr_expr) => {
                    let ptr_addr_type = self.process_expression(
                        inner_ptr_expr,
                        function_id,
                        instruction_id,
                        state,
                        store,
                    );

                    let pointee_tv_id = self.make_expression_type_var(
                        function_id,
                        instruction_id,
                        inner_ptr_expr.as_ref(),
                        state,
                    );
                    let pointee_type = Type::TypeVar(pointee_tv_id);

                    store.add_constraint(Constraint::new(
                        ptr_addr_type,
                        Type::Pointer(Box::new(pointee_type.clone())),
                        function_id,
                        instruction_id,
                        ConstraintReason::DereferenceRequiresPointer,
                    ));
                    pointee_type
                }
            },
            Expression::Binary { op, lhs, rhs } => {
                let lhs_type =
                    self.process_expression(lhs, function_id, instruction_id, state, store);
                let rhs_type =
                    self.process_expression(rhs, function_id, instruction_id, state, store);
                let result_tv_id =
                    self.make_expression_type_var(function_id, instruction_id, expr, state);
                let result_type = Type::TypeVar(result_tv_id);

                match op {
                    crate::disasm::v3::lir::expression::BinaryOperator::Add
                    | crate::disasm::v3::lir::expression::BinaryOperator::Mul
                    | crate::disasm::v3::lir::expression::BinaryOperator::Sub => {
                        // Need ConstraintReason::ArithmeticLHS, ArithmeticRHS, ArithmeticResult
                        store.add_constraint(Constraint::new(
                            lhs_type,
                            Type::Int,
                            function_id,
                            instruction_id,
                            ConstraintReason::ArithmeticLHS,
                        ));
                        store.add_constraint(Constraint::new(
                            rhs_type,
                            Type::Int,
                            function_id,
                            instruction_id,
                            ConstraintReason::ArithmeticRHS,
                        ));
                        store.add_constraint(Constraint::new(
                            result_type.clone(),
                            Type::Int,
                            function_id,
                            instruction_id,
                            ConstraintReason::ArithmeticResult,
                        ));
                    }
                    crate::disasm::v3::lir::expression::BinaryOperator::LessThan // Add other comparison ops
                    | crate::disasm::v3::lir::expression::BinaryOperator::Equals => {
                        // Need ConstraintReason::ComparisonLHS, ComparisonRHS, ComparisonResult
                        store.add_constraint(Constraint::new(
                            lhs_type,
                            Type::Int, // Assuming comparison is between Ints for now
                            function_id,
                            instruction_id,
                            ConstraintReason::ComparisonLHS,
                        ));
                        store.add_constraint(Constraint::new(
                            rhs_type,
                            Type::Int, // Assuming comparison is between Ints for now
                            function_id,
                            instruction_id,
                            ConstraintReason::ComparisonRHS,
                        ));
                        store.add_constraint(Constraint::new(
                            result_type.clone(),
                            Type::Bool,
                            function_id,
                            instruction_id,
                            ConstraintReason::ComparisonResult,
                        ));
                    }
                    _ => { /* Handle other binary ops or add a general case */ }
                }
                result_type
            }
            Expression::Unary { op, arg } => {
                let arg_type =
                    self.process_expression(arg, function_id, instruction_id, state, store);
                let result_tv_id =
                    self.make_expression_type_var(function_id, instruction_id, expr, state);
                let result_type = Type::TypeVar(result_tv_id);

                match op {
                    crate::disasm::v3::lir::expression::UnaryOperator::Not => {
                        // Need ConstraintReason::NotOperand, NotResult
                        store.add_constraint(Constraint::new(
                            arg_type,
                            Type::Truthy, // Operand of NOT must be Truthy
                            function_id,
                            instruction_id,
                            ConstraintReason::NotOperand,
                        ));
                        store.add_constraint(Constraint::new(
                            result_type.clone(),
                            Type::Bool, // Result of NOT is Bool
                            function_id,
                            instruction_id,
                            ConstraintReason::NotResult,
                        ));
                    }
                    crate::disasm::v3::lir::expression::UnaryOperator::Minus => {
                        store.add_constraint(Constraint::new(
                            arg_type,
                            Type::Int,
                            function_id,
                            instruction_id,
                            ConstraintReason::UnaryMinusOperand,
                        ));
                        store.add_constraint(Constraint::new(
                            result_type.clone(),
                            Type::Int,
                            function_id,
                            instruction_id,
                            ConstraintReason::UnaryMinusResult,
                        ));
                    }
                }
                result_type
            }
            Expression::Input() => {
                let tv_id = self.make_expression_type_var(function_id, instruction_id, expr, state);
                let input_type = Type::TypeVar(tv_id);
                // Need ConstraintReason::InputSourceType
                store.add_constraint(Constraint::new(
                    input_type.clone(),
                    Type::Char, // Assuming input is Char by default
                    function_id,
                    instruction_id,
                    ConstraintReason::InputSourceType,
                ));
                input_type
            }
            Expression::DebugMarker(marker, inner_expr) => {
                let expr_type =
                    self.process_expression(inner_expr, function_id, instruction_id, state, store);
                self.markers.insert(*marker, expr_type.clone());
                expr_type
            }
        }
    }
}
