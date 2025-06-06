use super::{
    expression::{BinaryOperator, Expression, UnaryOperator},
    instruction::{Instruction, InstructionNode},
    memory_reference::MemoryReference,
    MemoryReferenceInfo,
};
use crate::disasm::v3::{
    id_types::{BlockId, InstructionId, PointerId},
    native::{
        instruction::{GenericNativeInstruction, NativeInstruction, NativeInstructionKind},
        operand::{Operand, OperandKind},
    },
    FunctionId,
};

impl From<Operand> for Expression<MemoryReference> {
    fn from(op: Operand) -> Expression<MemoryReference> {
        let expr = match op.kind {
            OperandKind::Immediate(value) => Expression::Constant(value),
            OperandKind::Memory(_)
            | OperandKind::RelativeMemory(_)
            | OperandKind::Deref(_)
            | OperandKind::Pointer(_) => Expression::Addressable(op.kind.try_into().unwrap()),
        };
        match op.debug_marker {
            Some(marker) => Expression::DebugMarker(marker, Box::new(expr)),
            None => expr,
        }
    }
}

impl TryFrom<OperandKind> for MemoryReference {
    type Error = &'static str;

    fn try_from(value: OperandKind) -> Result<Self, Self::Error> {
        match value {
            OperandKind::Memory(offset) => Ok(MemoryReference::Global(offset)),
            OperandKind::RelativeMemory(offset) => Ok(MemoryReference::StackRelative(offset)),
            OperandKind::Deref(offset) => Ok(MemoryReference::Deref(Box::new(
                Expression::Addressable(MemoryReference::Pointer(PointerId::from(offset))),
            ))),
            OperandKind::Pointer(offset) => Ok(MemoryReference::Pointer(PointerId::from(offset))),
            OperandKind::Immediate(_) => Err("Cannot convert immediate operand to addressable"),
        }
    }
}

impl InstructionNode<MemoryReference> {
    /// Converts a block of native instructions into a block of low-level instructions.
    pub fn convert_block<I>(
        function_id: FunctionId,
        native: I,
    ) -> Vec<InstructionNode<MemoryReference>>
    where
        I: IntoIterator<Item = NativeInstruction>,
    {
        let mut iter = native.into_iter().peekable();
        let mut result = vec![];
        while let Some(native) = iter.next() {
            let (skip, low) = InstructionNode::from_native_instruction_pair(
                function_id,
                native,
                iter.peek(),
                &result,
            );
            result.extend(low);
            assert!(skip == 2 || skip == 1);
            if skip == 2 {
                iter.next();
            }
        }
        result
    }

    /// Converts a native instruction into a low-level instruction.
    /// Returns the number of instructions consumed and the resulting low-level instruction(s).
    fn from_native_instruction_pair(
        function_id: FunctionId,
        native: NativeInstruction,
        next_instruction: Option<&NativeInstruction>,
        previous_instructions: &[InstructionNode<MemoryReference>],
    ) -> (usize, Option<InstructionNode<MemoryReference>>) {
        // Handle special cases that need to look at the next instruction
        if let Some(result) = Self::handle_special_instruction_pairs(
            function_id,
            &native,
            next_instruction,
            previous_instructions,
        ) {
            return result;
        }

        // Handle regular single instructions
        let kind = match native.kind {
            NativeInstructionKind::Add(lhs, rhs, target) => {
                Self::create_binary_expression_assignment(BinaryOperator::Add, lhs, rhs, target)
            }
            NativeInstructionKind::Mul(lhs, rhs, target) => {
                Self::create_binary_expression_assignment(BinaryOperator::Mul, lhs, rhs, target)
            }
            NativeInstructionKind::LessThan(lhs, rhs, target) => {
                Self::create_binary_expression_assignment(
                    BinaryOperator::LessThan,
                    lhs,
                    rhs,
                    target,
                )
            }
            NativeInstructionKind::Equals(lhs, rhs, target) => {
                Self::create_binary_expression_assignment(BinaryOperator::Equals, lhs, rhs, target)
            }
            NativeInstructionKind::Input(target) => Instruction::Assign {
                target: target.kind.try_into().unwrap(),
                src: Expression::Input(),
                target_debug_marker: target.debug_marker,
            },
            NativeInstructionKind::Output(operand) => Instruction::Output(operand.into()),
            NativeInstructionKind::JumpIfTrue(cond, addr) => {
                Self::create_conditional_jump(cond, addr, native.span.end, false)
            }
            NativeInstructionKind::JumpIfFalse(cond, addr) => {
                Self::create_conditional_jump(cond, addr, native.span.end, true)
            }
            NativeInstructionKind::Goto(addr) => Self::create_goto(addr),
            NativeInstructionKind::Halt => Instruction::Halt,
            NativeInstructionKind::Assign(target, src) => Instruction::Assign {
                target: target.kind.try_into().unwrap(),
                src: src.into(),
                target_debug_marker: target.debug_marker,
            },
            // These cases are handled in handle_special_instruction_pairs
            NativeInstructionKind::AdjustRelativeBase(_) => return (1, None),
            NativeInstructionKind::Data(_) => unreachable!("Data instruction should be removed"),
        };
        (
            1,
            Some(InstructionNode {
                containing_function_id: function_id,
                kind,
                id: InstructionId::fresh(),
            }),
        )
    }

    /// Creates a binary expression assignment instruction
    ///
    /// Takes a binary operator and operands and creates an assignment instruction
    /// that assigns the result of the binary operation to the target.
    fn create_binary_expression_assignment(
        op: BinaryOperator,
        lhs: Operand,
        rhs: Operand,
        target: Operand,
    ) -> Instruction<MemoryReference> {
        Instruction::Assign {
            target: target
                .kind
                .try_into()
                .unwrap_or_else(|e| panic!("Failed to convert target to MemoryReference: {e}")),
            src: Expression::Binary {
                op,
                lhs: Box::new(lhs.into()),
                rhs: Box::new(rhs.into()),
            },
            target_debug_marker: target.debug_marker,
        }
    }

    /// Creates a conditional jump instruction
    fn create_conditional_jump(
        cond: Operand,
        addr: Operand,
        fallthrough_addr: usize,
        negate: bool,
    ) -> Instruction<MemoryReference> {
        let cond_expr = if negate {
            Expression::Unary {
                op: UnaryOperator::Not,
                arg: Box::new(cond.into()),
            }
        } else {
            cond.into()
        };

        let target_addr = match <Operand as Into<Expression<MemoryReference>>>::into(addr) {
            Expression::Constant(a) => BlockId::from(a as usize),
            _ => panic!("Expected constant address for jump"),
        };

        Instruction::If {
            cond: cond_expr,
            then_addr: target_addr,
            else_addr: BlockId::from(fallthrough_addr),
        }
    }

    /// Creates a goto instruction
    fn create_goto(addr: Operand) -> Instruction<MemoryReference> {
        let target_addr = addr
            .kind
            .get_immediate()
            .unwrap_or_else(|| panic!("Expected immediate value for GOTO address"));

        Instruction::Goto(BlockId::from(target_addr as usize))
    }

    /// Handles special cases where we need to look at pairs of instructions together
    fn handle_special_instruction_pairs(
        function_id: FunctionId,
        native: &NativeInstruction,
        next_instruction: Option<&NativeInstruction>,
        previous_instructions: &[InstructionNode<MemoryReference>],
    ) -> Option<(usize, Option<InstructionNode<MemoryReference>>)> {
        match &native.kind {
            // Handle function return sequence: R -= N followed by goto [R]
            NativeInstructionKind::AdjustRelativeBase(r) => {
                let Some(adjust) = r.kind.get_immediate() else {
                    panic!("Expected immediate value for R adjustment");
                };
                if adjust < 0 {
                    // Must be followed by GOTO [R], representing a return
                    if let Some(GenericNativeInstruction {
                        kind:
                            NativeInstructionKind::Goto(Operand {
                                kind: OperandKind::RelativeMemory(0),
                                ..
                            }),
                        ..
                    }) = next_instruction
                    {
                        Some((
                            2,
                            Some(InstructionNode {
                                containing_function_id: function_id,
                                id: InstructionId::fresh(),
                                kind: Instruction::Return,
                            }),
                        ))
                    } else {
                        panic!("Expected GOTO [R] after R adjustment for function return")
                    }
                } else if adjust > 0 {
                    // Entry point to function, discard
                    return Some((1, None));
                } else {
                    panic!("R adjustment must be non-zero");
                }
            }

            // Handle function call sequence: [R] = return_addr followed by goto func_addr
            NativeInstructionKind::Assign(target, src) => {
                if Some(0) == target.kind.get_relative_memory() {
                    if let Some(return_to) = src.kind.get_immediate().map(|i| i as usize) {
                        // Check if the return address matches the expected pattern (end of assign + size of goto)
                        // Assign is 4 bytes (opcode + 3 args), Goto is 3 bytes (opcode + 2 args)
                        // But Goto is simplified from JumpIfTrue, which is 3 bytes.
                        // Assign is simplified from Add, which is 4 bytes.
                        // So, native.span.end should be offset + 4.
                        // The next instruction (Goto) starts at offset + 4.
                        // The instruction *after* the Goto starts at offset + 4 + 3 = offset + 7.
                        // Let's re-evaluate the check:
                        // native.span.end is the address *after* the assign instruction.
                        // next_instruction.span.end is the address *after* the goto instruction.
                        // So, the return address should be next_instruction.span.end.
                        let expected_return_addr = next_instruction.map(|ni| ni.span.end);

                        if Some(return_to) == expected_return_addr {
                            if let Some(GenericNativeInstruction {
                                kind: NativeInstructionKind::Goto(func_addr),
                                ..
                            }) = next_instruction
                            {
                                let collected_args = extract_arguments(previous_instructions);

                                return Some((
                                    2,
                                    Some(InstructionNode {
                                        containing_function_id: function_id,
                                        kind: Instruction::Call {
                                            addr: (*func_addr).into(),
                                            args: collected_args
                                                .into_iter()
                                                .map(Expression::Addressable)
                                                .collect(),
                                            return_to: BlockId::from(return_to),
                                        },
                                        id: InstructionId::fresh(),
                                    }),
                                ));
                            }
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }
}

fn extract_arguments(
    previous_instructions: &[InstructionNode<MemoryReference>],
) -> Vec<MemoryReference> {
    // Extract arguments for a call
    // Arguments are expected to be assignments to [R+1], [R+2], ..., [R+N]
    // appearing consecutively in previous_instructions just before this call sequence.
    // Iterating previous_instructions in reverse means we see [R+N], then [R+N-1], ..., [R+1].
    let mut collected_args: Vec<MemoryReference> = Vec::new();
    // Stores the offset expected for the *next* argument in the reversed sequence.
    // e.g., if we just saw R+k, this will be R+(k-1).
    let mut next_expected_lower_offset: Option<i128> = None;

    for prev_node in previous_instructions.iter().rev() {
        // Guard 1: Must be an Assign instruction
        let Instruction::Assign { target, .. } = &prev_node.kind else {
            // Not an Assign instruction. Argument sequence ends here.
            break;
        };

        // Guard 2: Target must be stack-relative
        // MemoryReferenceInfo::as_stack_relative is used here.
        let Some(offset_val) = target.as_stack_relative() else {
            // Not a stack-relative assignment. Argument sequence ends here.
            break;
        };

        // Guard 3: Stack offset must be positive
        if offset_val <= 0 {
            // Not a positive stack offset (e.g., R+0 or R-ve).
            // Argument sequence ends here.
            break;
        }

        // At this point, we have a positive stack-relative assignment, a potential argument.
        match next_expected_lower_offset {
            None => {
                // This is the first potential argument found (should be R+N).
                collected_args.push(target.clone());
                next_expected_lower_offset = Some(offset_val - 1);
            }
            Some(expected_offset) => {
                // Assert it's consecutive [R-3] then [R-1]...
                assert_eq!(offset_val, expected_offset);
                collected_args.push(target.clone());
                next_expected_lower_offset = Some(offset_val - 1);
            }
        }
        if offset_val == 1 {
            // Found R+1 as the very first argument (single argument case)
            break;
        }
    }

    // Validate the collected arguments:
    // If arguments were found, the sequence must be complete,
    // meaning it ended with R+1 (so next_expected_lower_offset became Some(0)).
    // If no arguments were found, next_expected_lower_offset is None, and collected_args is empty.
    assert!(next_expected_lower_offset.is_none_or(|x| x == 0));

    // The collected_args are currently in [R+N, ..., R+1] order. Reverse it.
    collected_args.reverse();
    // Now in [R+1, ..., R+N] order.
    collected_args
}
