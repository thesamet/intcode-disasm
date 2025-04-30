use std::{cmp::Ordering, sync::atomic::AtomicUsize};

use pretty_assertions::assert_matches;

use super::{
    id_types::define_id_type,
    model::BlockId,
    native::{
        GenericNativeInstruction, NativeInstruction, NativeInstructionKind, Operand, OperandKind,
    },
};

/// Represents operands that have an address in memory.
/// These can be both sources and targets.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Addressable {
    /// Represents a memory location outside the stack and code segments.
    Memory(usize),
    /// Represents a memory location relative to some base address.
    RelativeMemory(i128),
    /// Represents a dereference of the given address.
    Deref(usize),
    /// Represents a pointer to a point in memory.
    Pointer(usize),
}

define_id_type!(InstructionId);

static INSTRUCTION_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl InstructionId {
    pub fn fresh() -> Self {
        let next = INSTRUCTION_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        InstructionId::new(next)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction<A> {
    pub id: InstructionId,
    pub kind: InstructionKind<A>,
}

/// Represents different kinds of low-level instructions.
/// Type parameter `A` represents the type of the addresable type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum InstructionKind<A> {
    /// Assigns the result of an expression to a target address.
    Assign {
        /// Target location where the result will be stored.
        target: A,
        /// Source expression to evaluate.
        src: LowExpr<A>,
    },
    /// Conditional branch instruction.
    If {
        /// Condition to evaluate.
        cond: LowExpr<A>,
        /// Address to jump to if condition is true.
        then_addr: BlockId,
        /// Address to jump to if condition is false.
        else_addr: BlockId,
    },
    Goto(BlockId),
    /// Calls a function. Does not contain information on arguments and return values.
    Call {
        addr: LowExpr<A>,
        return_to: BlockId,
    },
    /// Outputs the result of an expression.
    Output(LowExpr<A>),
    /// Returns from the current function. Does not contain information on return values.
    Return,
    /// Halts execution.
    Halt,
}

/// Represents a low-level expression that can be evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LowExpr<A> {
    /// A literal constant value.
    Constant(i128),
    /// A reference to an addressable location.
    Addressable(A),
    /// A binary operation with two operands.
    BinaryOp {
        /// The binary operator.
        op: BinaryOp,
        /// The left-hand side operand.
        lhs: Box<LowExpr<A>>,
        /// The right-hand side operand.
        rhs: Box<LowExpr<A>>,
    },
    /// A unary operation with one operand.
    UnaryOp {
        /// The unary operator.
        op: UnaryOp,
        /// The operand argument.
        arg: Box<LowExpr<A>>,
    },
    Input(), // Expression that reads the next input.
    DebugMarker(char, Box<LowExpr<A>>),
}

/// Represents binary operations that can be performed on two operands.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    /// Addition operation (+).
    Add,
    /// Multiplication operation (*).
    Mul,
    /// Subtraction operation (-).
    Sub,
    /// Less than comparison (<).
    LessThan,
    /// Less than or equal comparison (<=).
    LessThanOrEqual,
    /// Greater than comparison (>).
    GreaterThan,
    /// Greater than or equal comparison (>=).
    GreaterThanOrEqual,
    /// Equality comparison (==).
    Equals,
    /// Inequality comparison (!=).
    NotEquals,
}

/// Represents unary operations that can be performed on a single operand.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum UnaryOp {
    /// Logical negation operation (!).
    Not,
    /// Arithmetic negation operation (-).
    Minus,
}

#[expect(dead_code)]
impl<A> LowExpr<A> {
    /// Checks if the expression is a constant.
    fn is_constant(&self) -> bool {
        matches!(self, LowExpr::Constant(_))
    }

    /// Checks if the expression is an addressable reference.
    fn is_addressable(&self) -> bool {
        matches!(self, LowExpr::Addressable(_))
    }

    /// Checks if the expression is a unary operation.
    fn is_unary(&self) -> bool {
        matches!(self, LowExpr::UnaryOp { .. })
    }

    /// Checks if the expression is a binary operation.
    fn is_binary(&self) -> bool {
        matches!(self, LowExpr::BinaryOp { .. })
    }

    /// Checks if the expression is a unary operation.
    /// This is an alias for `is_unary`.
    fn is_unary_op(&self) -> bool {
        matches!(self, LowExpr::UnaryOp { .. })
    }

    /// Checks if the expression is a binary operation.
    /// This is an alias for `is_binary`.
    fn is_binary_op(&self) -> bool {
        matches!(self, LowExpr::BinaryOp { .. })
    }

    /// Extracts the binary operation components if this expression is a binary operation.
    ///
    /// Returns a tuple containing the operator, left-hand side, and right-hand side
    /// if this is a binary operation, or None otherwise.
    fn as_binary_op(&self) -> Option<(BinaryOp, &LowExpr<A>, &LowExpr<A>)> {
        match self {
            LowExpr::BinaryOp { op, lhs, rhs } => Some((*op, lhs, rhs)),
            _ => None,
        }
    }
}

impl From<Operand> for LowExpr<Addressable> {
    fn from(op: Operand) -> LowExpr<Addressable> {
        let expr = match op.kind {
            OperandKind::Immediate(value) => LowExpr::Constant(value),
            OperandKind::Memory(_)
            | OperandKind::RelativeMemory(_)
            | OperandKind::Deref(_)
            | OperandKind::Pointer(_) => LowExpr::Addressable(op.into()),
        };
        match op.debug_marker {
            Some(marker) => LowExpr::DebugMarker(marker, Box::new(expr)),
            None => expr,
        }
    }
}

impl Addressable {
    /// Checks if this addressable is a direct memory reference.
    pub fn is_memory(&self) -> bool {
        matches!(self, Addressable::Memory(_))
    }

    /// Checks if this addressable is a relative memory reference.
    pub fn is_relative_memory(&self) -> bool {
        matches!(self, Addressable::RelativeMemory(_))
    }

    /// Checks if this addressable is a dereferenced pointer.
    pub fn is_deref(&self) -> bool {
        matches!(self, Addressable::Deref(_))
    }

    /// Checks if this addressable is a direct pointer.
    pub fn is_pointer(&self) -> bool {
        matches!(self, Addressable::Pointer(_))
    }

    /// Checks if this addressable is a positive relative memory offset.
    pub fn is_positive_relative_memory(&self) -> bool {
        matches!(self, Addressable::RelativeMemory(n) if *n > 0)
    }

    /// Checks if this addressable is a negative relative memory offset.
    pub fn is_negative_relative_memory(&self) -> bool {
        matches!(self, Addressable::RelativeMemory(n) if *n < 0)
    }

    /// Extracts the relative memory offset if this is a relative memory reference.
    ///
    /// Returns the offset value if this is a relative memory reference, or None otherwise.
    pub fn as_relative_memory(&self) -> Option<i128> {
        match self {
            Addressable::RelativeMemory(value) => Some(*value),
            _ => None,
        }
    }
}

impl From<Operand> for Addressable {
    fn from(op: Operand) -> Addressable {
        match op.kind {
            OperandKind::Memory(offset) => Addressable::Memory(offset),
            OperandKind::RelativeMemory(offset) => Addressable::RelativeMemory(offset),
            OperandKind::Deref(offset) => Addressable::Deref(offset),
            OperandKind::Pointer(offset) => Addressable::Pointer(offset),
            OperandKind::Immediate(_) => panic!("Cannot convert immediate operand to addressable"),
        }
    }
}

impl Instruction<Addressable> {
    /// Converts a block of native instructions into a block of low-level instructions.
    pub fn convert_block<I>(native: I) -> Vec<Instruction<Addressable>>
    where
        I: IntoIterator<Item = NativeInstruction>,
    {
        let mut iter = native.into_iter().peekable();
        let mut result = vec![];
        while let Some(native) = iter.next() {
            let (skip, low) = Instruction::from_native_instruction_pair(native, iter.peek());
            result.extend(low);
            assert!(skip == 2 || skip == 1);
            if skip == 2 {
                iter.next();
            }
        }
        result
    }

    /// Converts a native instruction into a low-level instruction.
    /// Returns the number of instructions consumed by this instruction, which would
    /// be either 1 or 2 if `next_instruction` was consumed. The second return value
    /// is an optional instruction that is produced by this instruction, as some native
    /// instructions do not prodice a low-level instruction.
    fn from_native_instruction_pair(
        native: NativeInstruction,
        next_instruction: Option<&NativeInstruction>,
    ) -> (usize, Option<Instruction<Addressable>>) {
        // matches returns the default case of (1, Some(i)), if it's anything else,
        // there's an early return.
        let kind = match native.kind {
            NativeInstructionKind::Add(a, b, c) => InstructionKind::Assign {
                target: c.into(),
                src: LowExpr::BinaryOp {
                    op: BinaryOp::Add,
                    lhs: Box::new(a.into()),
                    rhs: Box::new(b.into()),
                },
            },
            NativeInstructionKind::Mul(a, b, c) => InstructionKind::Assign {
                target: c.into(),
                src: LowExpr::BinaryOp {
                    op: BinaryOp::Mul,
                    lhs: Box::new(a.into()),
                    rhs: Box::new(b.into()),
                },
            },
            NativeInstructionKind::Input(a) => InstructionKind::Assign {
                target: a.into(),
                src: LowExpr::Input(),
            },
            NativeInstructionKind::Output(a) => InstructionKind::Output(a.into()),
            NativeInstructionKind::JumpIfTrue(cond, addr) => InstructionKind::If {
                cond: cond.into(),
                then_addr: match addr.into() {
                    LowExpr::Constant(a) => BlockId::from(a as usize),
                    _ => panic!("Expected constant address for jump"),
                },
                else_addr: BlockId::from(native.span.end),
            },
            NativeInstructionKind::JumpIfFalse(cond, addr) => InstructionKind::If {
                cond: LowExpr::UnaryOp {
                    op: UnaryOp::Not,
                    arg: Box::new(cond.into()),
                },
                then_addr: match addr.into() {
                    LowExpr::Constant(a) => BlockId::from(a as usize),
                    _ => panic!("Expected constant address for jump"),
                },
                else_addr: BlockId::from(native.span.end),
            },
            NativeInstructionKind::LessThan(a, b, c) => InstructionKind::Assign {
                target: c.into(),
                src: LowExpr::BinaryOp {
                    op: BinaryOp::LessThan,
                    lhs: Box::new(a.into()),
                    rhs: Box::new(b.into()),
                },
            },
            NativeInstructionKind::Equals(a, b, c) => InstructionKind::Assign {
                target: c.into(),
                src: LowExpr::BinaryOp {
                    op: BinaryOp::Equals,
                    lhs: Box::new(a.into()),
                    rhs: Box::new(b.into()),
                },
            },
            NativeInstructionKind::AdjustRelativeBase(r) => {
                let Some(adjust) = r.kind.get_immediate() else {
                    panic!("Expected immediate value for R adjustment");
                };
                match adjust.cmp(&0) {
                    Ordering::Less => {
                        // must be followed by GOTO [R], representing a return.
                        assert_matches!(
                            next_instruction,
                            Some(GenericNativeInstruction {
                                kind: NativeInstructionKind::Goto(Operand {
                                    kind: OperandKind::RelativeMemory(0),
                                    ..
                                }),
                                ..
                            })
                        );
                        return (
                            2,
                            Some(Instruction {
                                id: InstructionId::fresh(),
                                kind: InstructionKind::Return,
                            }),
                        );
                    }
                    Ordering::Equal => {
                        panic!("R adjustment must be non-zero");
                    }
                    Ordering::Greater => {
                        // entry point to function, discard
                        return (1, None);
                    }
                }
            }
            NativeInstructionKind::Halt => InstructionKind::Halt,
            NativeInstructionKind::Data(_) => {
                unreachable!("Data instruction should be removed")
            }
            NativeInstructionKind::Goto(addr) => InstructionKind::Goto(BlockId::from(
                addr.kind
                    .get_immediate()
                    .unwrap_or_else(|| panic!("Expected immediate value for GOTO address"))
                    as usize,
            )),
            NativeInstructionKind::Assign(target, src) => {
                if Some(0) == target.kind.get_relative_memory() {
                    let return_to = src.kind.get_immediate().map(|i| i as usize).unwrap();
                    assert_eq!(return_to, native.span.end + 3);
                    let Some(GenericNativeInstruction {
                        kind: NativeInstructionKind::Goto(func_addr),
                        ..
                    }) = next_instruction
                    else {
                        panic!("Expected next instruction to be GOTO (func_addr)]");
                    };
                    return (
                        2,
                        Some(Instruction {
                            kind: InstructionKind::Call {
                                addr: func_addr.clone().into(),
                                return_to: BlockId::from(return_to),
                            },
                            id: InstructionId::fresh(),
                        }),
                    );
                } else {
                    InstructionKind::Assign {
                        target: target.into(),
                        src: src.into(),
                    }
                }
            }
        };
        (
            1,
            Some(Instruction {
                kind,
                id: InstructionId::fresh(),
            }),
        )
    }
}
