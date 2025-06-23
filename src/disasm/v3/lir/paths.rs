use crate::disasm::{
    symbol_renaming::StructId,
    v3::{
        lir::{Expression, Instruction, InstructionNode},
        model::{HasFoldedSsaResult, Model, ModelState},
        ssa::{SsaMemoryReference, VersionedMemoryReference},
        type_inference::TypeVarId,
        FunctionId, InstructionId,
    },
};
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ExpressionPathElement {
    BinaryLeft,
    BinaryRight,
    Unary,
    Deref,
    TupleElementBase,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExpressionPath(Vec<ExpressionPathElement>);

impl ExpressionPath {
    pub fn root() -> Self {
        ExpressionPath(vec![])
    }

    pub fn extending(&self, element: ExpressionPathElement) -> Self {
        let mut new_path = self.clone();
        new_path.0.push(element);
        new_path
    }

    pub fn concat(&self, other: &ExpressionPath) -> Self {
        let mut new_path = self.clone();
        new_path.0.extend(other.0.clone());
        new_path
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get_subexpression<'a>(
        &self,
        expression: &'a Expression<SsaMemoryReference>,
    ) -> &'a Expression<SsaMemoryReference> {
        let mut current_expression = expression;
        while let Expression::DebugMarker(_, expr) = current_expression {
            current_expression = expr;
        }
        for element in &self.0 {
            match element {
                ExpressionPathElement::BinaryLeft => {
                    if let Expression::Binary { lhs, .. } = current_expression {
                        current_expression = lhs;
                    } else {
                        panic!("Invalid path: expected Binary with left hand side");
                    }
                }
                ExpressionPathElement::BinaryRight => {
                    if let Expression::Binary { rhs, .. } = current_expression {
                        current_expression = rhs;
                    } else {
                        panic!("Invalid path: expected Binary with right hand side");
                    }
                }
                ExpressionPathElement::Unary => {
                    if let Expression::Unary { arg, .. } = current_expression {
                        current_expression = arg;
                    } else {
                        panic!("Invalid path: expected Unary expression");
                    }
                }
                ExpressionPathElement::Deref => {
                    if let Expression::Addressable(SsaMemoryReference::Deref(expr)) =
                        current_expression
                    {
                        current_expression = expr;
                    } else {
                        panic!("Invalid path: expected Addressable::Deref expression");
                    }
                }
                ExpressionPathElement::TupleElementBase => {
                    if let Expression::StructField { base, .. } = current_expression {
                        current_expression = base;
                    } else {
                        panic!("Invalid path: expected TupleElement expression");
                    }
                }
            }
            while let Expression::DebugMarker(_, expr) = current_expression {
                current_expression = expr;
            }
        }
        current_expression
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeVarPath {
    FunctionDefArg {
        function_id: FunctionId,
        index: usize,
    },
    FunctionDefArgTuple {
        function_id: FunctionId,
    },
    FunctionDefRet {
        function_id: FunctionId,
        index: usize,
    },
    FunctionDefRetTuple {
        function_id: FunctionId,
    },
    AssignmentTargetVersioned {
        function_id: FunctionId,
        instruction_id: InstructionId,
        vmr: VersionedMemoryReference,
    },
    AssignmentTargetDeref {
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression_path: ExpressionPath,
    },
    AssignmentSrc {
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression_path: ExpressionPath,
    },
    IfCond {
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression_path: ExpressionPath,
    },
    Output {
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression_path: ExpressionPath,
    },
    CallAddress {
        function_id: FunctionId,
        instruction_id: InstructionId,
        expression_path: ExpressionPath,
    },
    CallArgTuple {
        function_id: FunctionId,
        instruction_id: InstructionId,
    },
    CallArg {
        function_id: FunctionId,
        instruction_id: InstructionId,
        index: usize,
        expression_path: ExpressionPath,
    },
    CallRetTuple {
        function_id: FunctionId,
        instruction_id: InstructionId,
    },
    CallRet {
        function_id: FunctionId,
        instruction_id: InstructionId,
        index: usize,
        vmr: VersionedMemoryReference,
    },
    PhiAssignment {
        function_id: FunctionId,
        instruction_id: InstructionId,
    },
    PhiAssignmentArg {
        function_id: FunctionId,
        instruction_id: InstructionId,
        index: usize,
    },
    SymbolRenaming {
        function_id: FunctionId,
    },

    // When we discover that a type var has a function type as an upper bound, we converge it to a function type.
    // with args and returns tuples. The path of these new type vars is FunctionsArgsRefinement and FunctionsRetsRefinement.
    FunctionArgsRefinement {
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
    },
    FunctionRetsRefinement {
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
    },
    /// When we are inferring a type has a tuple as an upper bound, it means it is also a tuple with arity as least as the upper bound.
    TupleRefinement {
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
        index: usize,
    },
    PointerRefinement {
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
    },
    StructField {
        struct_id: StructId,
        index: usize,
    },
}

impl TypeVarPath {
    #[must_use]
    pub fn function_def_arg(function_id: FunctionId, index: usize) -> Self {
        Self::FunctionDefArg { function_id, index }
    }

    #[must_use]
    pub fn function_def_arg_tuple(function_id: FunctionId) -> Self {
        Self::FunctionDefArgTuple { function_id }
    }

    #[must_use]
    pub fn function_def_ret(function_id: FunctionId, index: usize) -> Self {
        Self::FunctionDefRet { function_id, index }
    }

    #[must_use]
    pub fn function_def_ret_tuple(function_id: FunctionId) -> Self {
        Self::FunctionDefRetTuple { function_id }
    }

    #[must_use]
    pub fn assignment_target_versioned(
        function_id: FunctionId,
        instruction_id: InstructionId,
        vmr: VersionedMemoryReference,
    ) -> Self {
        Self::AssignmentTargetVersioned {
            function_id,
            instruction_id,
            vmr,
        }
    }

    #[must_use]
    pub fn assignment_target_deref(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::AssignmentTargetDeref {
            function_id,
            instruction_id,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn assignment_src(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::AssignmentSrc {
            function_id,
            instruction_id,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn if_cond(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::IfCond {
            function_id,
            instruction_id,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn output(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::Output {
            function_id,
            instruction_id,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn call_address(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::CallAddress {
            function_id,
            instruction_id,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn call_arg_tuple(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::CallArgTuple {
            function_id,
            instruction_id,
        }
    }

    #[must_use]
    pub fn call_arg(function_id: FunctionId, instruction_id: InstructionId, index: usize) -> Self {
        Self::CallArg {
            function_id,
            instruction_id,
            index,
            expression_path: ExpressionPath::root(),
        }
    }

    #[must_use]
    pub fn call_ret_tuple(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::CallRetTuple {
            function_id,
            instruction_id,
        }
    }

    #[must_use]
    pub fn call_ret(
        function_id: FunctionId,
        instruction_id: InstructionId,
        index: usize,
        vmr: VersionedMemoryReference,
    ) -> Self {
        Self::CallRet {
            function_id,
            instruction_id,
            index,
            vmr,
        }
    }

    #[must_use]
    pub fn phi_assignment(function_id: FunctionId, instruction_id: InstructionId) -> Self {
        Self::PhiAssignment {
            function_id,
            instruction_id,
        }
    }

    #[must_use]
    pub fn phi_assignment_arg(
        function_id: FunctionId,
        instruction_id: InstructionId,
        index: usize,
    ) -> Self {
        Self::PhiAssignmentArg {
            function_id,
            instruction_id,
            index,
        }
    }

    #[must_use]
    pub fn function_args_refinement(
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
    ) -> Self {
        Self::FunctionArgsRefinement {
            function_id,
            original_type_var_id,
        }
    }

    #[must_use]
    pub fn function_rets_refinement(
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
    ) -> Self {
        Self::FunctionRetsRefinement {
            function_id,
            original_type_var_id,
        }
    }

    #[must_use]
    pub fn tuple_refinement(
        function_id: FunctionId,
        original_type_var_id: TypeVarId,
        index: usize,
    ) -> Self {
        Self::TupleRefinement {
            function_id,
            original_type_var_id,
            index,
        }
    }

    #[must_use]
    pub fn pointer_refinement(function_id: FunctionId, original_type_var_id: TypeVarId) -> Self {
        Self::PointerRefinement {
            function_id,
            original_type_var_id,
        }
    }
}

impl TypeVarPath {
    pub fn function_id(&self) -> FunctionId {
        match self {
            TypeVarPath::FunctionDefArg { function_id, .. }
            | TypeVarPath::FunctionDefArgTuple { function_id, .. }
            | TypeVarPath::FunctionDefRet { function_id, .. }
            | TypeVarPath::FunctionDefRetTuple { function_id, .. }
            | TypeVarPath::AssignmentTargetVersioned { function_id, .. }
            | TypeVarPath::AssignmentTargetDeref { function_id, .. }
            | TypeVarPath::AssignmentSrc { function_id, .. }
            | TypeVarPath::IfCond { function_id, .. }
            | TypeVarPath::Output { function_id, .. }
            | TypeVarPath::CallAddress { function_id, .. }
            | TypeVarPath::CallArg { function_id, .. }
            | TypeVarPath::CallArgTuple { function_id, .. }
            | TypeVarPath::CallRet { function_id, .. }
            | TypeVarPath::CallRetTuple { function_id, .. }
            | TypeVarPath::PhiAssignment { function_id, .. }
            | TypeVarPath::PhiAssignmentArg { function_id, .. }
            | TypeVarPath::FunctionArgsRefinement { function_id, .. }
            | TypeVarPath::FunctionRetsRefinement { function_id, .. }
            | TypeVarPath::TupleRefinement { function_id, .. }
            | TypeVarPath::PointerRefinement { function_id, .. }
            | TypeVarPath::SymbolRenaming { function_id, .. } => *function_id,
            TypeVarPath::StructField { .. } => FunctionId::new(0),
        }
    }

    pub fn instruction_id(&self) -> Option<InstructionId> {
        match self {
            TypeVarPath::AssignmentTargetVersioned { instruction_id, .. }
            | TypeVarPath::AssignmentTargetDeref { instruction_id, .. }
            | TypeVarPath::AssignmentSrc { instruction_id, .. }
            | TypeVarPath::IfCond { instruction_id, .. }
            | TypeVarPath::Output { instruction_id, .. }
            | TypeVarPath::CallAddress { instruction_id, .. }
            | TypeVarPath::CallArg { instruction_id, .. }
            | TypeVarPath::CallRet { instruction_id, .. }
            | TypeVarPath::PhiAssignment { instruction_id, .. }
            | TypeVarPath::PhiAssignmentArg { instruction_id, .. }
            | TypeVarPath::CallArgTuple { instruction_id, .. }
            | TypeVarPath::CallRetTuple { instruction_id, .. } => Some(*instruction_id),
            TypeVarPath::FunctionDefArg { .. }
            | TypeVarPath::FunctionDefArgTuple { .. }
            | TypeVarPath::FunctionDefRet { .. }
            | TypeVarPath::FunctionDefRetTuple { .. }
            | TypeVarPath::FunctionArgsRefinement { .. }
            | TypeVarPath::FunctionRetsRefinement { .. }
            | TypeVarPath::TupleRefinement { .. }
            | TypeVarPath::SymbolRenaming { .. }
            | TypeVarPath::StructField { .. }
            | TypeVarPath::PointerRefinement { .. } => None,
        }
    }

    pub fn expression_path(&self) -> Option<&ExpressionPath> {
        match self {
            TypeVarPath::FunctionDefArg { .. }
            | TypeVarPath::FunctionDefArgTuple { .. }
            | TypeVarPath::FunctionDefRet { .. }
            | TypeVarPath::FunctionDefRetTuple { .. }
            | TypeVarPath::AssignmentTargetVersioned { .. }
            | TypeVarPath::CallArgTuple { .. }
            | TypeVarPath::CallRet { .. }
            | TypeVarPath::PhiAssignment { .. }
            | TypeVarPath::PhiAssignmentArg { .. }
            | TypeVarPath::CallRetTuple { .. }
            | TypeVarPath::FunctionArgsRefinement { .. }
            | TypeVarPath::FunctionRetsRefinement { .. }
            | TypeVarPath::TupleRefinement { .. }
            | TypeVarPath::SymbolRenaming { .. }
            | TypeVarPath::StructField { .. }
            | TypeVarPath::PointerRefinement { .. } => None,
            TypeVarPath::AssignmentSrc {
                expression_path, ..
            }
            | TypeVarPath::AssignmentTargetDeref {
                expression_path, ..
            }
            | TypeVarPath::IfCond {
                expression_path, ..
            }
            | TypeVarPath::Output {
                expression_path, ..
            }
            | TypeVarPath::CallAddress {
                expression_path, ..
            }
            | TypeVarPath::CallArg {
                expression_path, ..
            } => Some(expression_path),
        }
    }

    pub fn with_expression_path(&self, expression_path: ExpressionPath) -> TypeVarPath {
        match self {
            TypeVarPath::AssignmentTargetDeref {
                function_id,
                instruction_id,
                ..
            } => TypeVarPath::AssignmentTargetDeref {
                function_id: *function_id,
                instruction_id: *instruction_id,
                expression_path,
            },
            TypeVarPath::AssignmentSrc {
                function_id,
                instruction_id,
                ..
            } => TypeVarPath::AssignmentSrc {
                function_id: *function_id,
                instruction_id: *instruction_id,
                expression_path,
            },
            TypeVarPath::IfCond {
                function_id,
                instruction_id,
                ..
            } => TypeVarPath::IfCond {
                function_id: *function_id,
                instruction_id: *instruction_id,
                expression_path,
            },
            TypeVarPath::Output {
                function_id,
                instruction_id,
                ..
            } => TypeVarPath::Output {
                function_id: *function_id,
                instruction_id: *instruction_id,
                expression_path,
            },
            TypeVarPath::CallAddress {
                function_id,
                instruction_id,
                ..
            } => TypeVarPath::CallAddress {
                function_id: *function_id,
                instruction_id: *instruction_id,
                expression_path,
            },
            TypeVarPath::CallArg {
                function_id,
                instruction_id,
                index,
                ..
            } => TypeVarPath::CallArg {
                function_id: *function_id,
                instruction_id: *instruction_id,
                index: *index,
                expression_path,
            },
            _ => panic!("Cannot add expression path to {self:?}"),
        }
    }

    pub fn extending_path_element(&self, element: ExpressionPathElement) -> TypeVarPath {
        self.with_expression_path(
            self.expression_path()
                .unwrap_or_else(|| panic!("Cannot extend path for {self:?} / element {element:?}"))
                .extending(element),
        )
    }

    pub fn extending_path(&self, path: &ExpressionPath) -> TypeVarPath {
        self.with_expression_path(
            self.expression_path()
                .unwrap_or_else(|| panic!("Cannot extend path for {self:?} / path {path:?}"))
                .concat(path),
        )
    }

    pub fn instruction_from_model<'a, S>(
        &self,
        model: &'a Model<S>,
    ) -> Option<&'a InstructionNode<SsaMemoryReference>>
    where
        S: ModelState + HasFoldedSsaResult,
    {
        let instruction_id = self.instruction_id()?;
        let f = model.function(&self.function_id());
        f.blocks()
            .flat_map(|(_, block)| &block.folded_ssa().instructions)
            .find(|instruction| instruction.id == instruction_id)
    }

    pub fn expression_from_model<'a, S>(
        &self,
        model: &'a Model<S>,
    ) -> Option<&'a Expression<SsaMemoryReference>>
    where
        S: ModelState + HasFoldedSsaResult,
    {
        let inst = self.instruction_from_model(model)?;
        let path = self.expression_path()?;
        let expr = match (self, &inst.kind) {
            (
                TypeVarPath::AssignmentTargetDeref { .. },
                Instruction::Assign {
                    target: SsaMemoryReference::Deref(expr),
                    ..
                },
            ) => expr,
            (TypeVarPath::AssignmentSrc { .. }, Instruction::Assign { src, .. }) => src,
            (TypeVarPath::IfCond { .. }, Instruction::If { cond, .. }) => cond,
            (TypeVarPath::Output { .. }, Instruction::Output(output)) => output,
            (TypeVarPath::CallAddress { .. }, Instruction::Call { addr, .. }) => addr,
            (TypeVarPath::CallArg { index, .. }, Instruction::Call { args, .. }) => &args[*index],
            _ => panic!("Unexpected combination of TypeVarPath and Instruction: {self:?}"),
        };
        Some(path.get_subexpression(expr))
    }
}
