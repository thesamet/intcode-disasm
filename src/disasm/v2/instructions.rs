use std::{cmp::Ordering, fmt::Display, iter, sync::atomic::AtomicUsize};

use pretty_assertions::assert_matches;

use super::{
    id_types::define_id_type,
    model::BlockId,
    native::{
        GenericNativeInstruction, NativeInstruction, NativeInstructionKind, Operand, OperandKind,
    },
    ssa_form::{MemoryReferenceType, SsaMemoryReference, VersionedMemoryReference},
};

define_id_type!(PointerId);

/// Represents a reference to a memory location that can be read from or written to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemoryReference {
    /// Represents a fixed memory location outside the stack and code segments.
    /// These will get versioned.
    Global(usize),
    /// Stack-relative memory location with specific semantics:
    /// - Positive values (R+n): Outgoing parameters to called functions or return values
    /// - Zero (R+0): Return address for function calls
    /// - Negative values (R-n): Local variables, incoming parameters, or return values
    StackRelative(i128),
    /// Represents a pointer to a point in memory.
    Pointer(PointerId),
    /// Dereference of a pointer expression.
    Deref(Box<Expression<MemoryReference>>),
}

impl<'a> From<&'a MemoryReference> for MemoryReference {
    fn from(value: &'a MemoryReference) -> Self {
        value.clone()
    }
}

impl<'a> From<&'a SsaMemoryReference> for MemoryReference {
    fn from(value: &'a SsaMemoryReference) -> Self {
        match value {
            SsaMemoryReference::Versioned(var) => (var).into(),
            SsaMemoryReference::Deref(expr) => {
                MemoryReference::Deref(Box::new(expr.map(&mut |t| Self::from(t))))
            }
        }
    }
}

impl<'a> From<&'a VersionedMemoryReference> for MemoryReference {
    fn from(value: &'a VersionedMemoryReference) -> MemoryReference {
        (&value.kind).into()
    }
}

impl<'a> From<&'a MemoryReferenceType> for MemoryReference {
    fn from(value: &'a MemoryReferenceType) -> MemoryReference {
        match value {
            MemoryReferenceType::Memory(addr) => MemoryReference::Global(*addr),
            MemoryReferenceType::RelativeMemory(offset) => MemoryReference::StackRelative(*offset),
            MemoryReferenceType::Pointer(pointer_id) => MemoryReference::Pointer(*pointer_id),
        }
    }
}

/// A trait for types that can be converted to a MemoryReference.
///
/// This trait provides utility methods for querying properties of memory references,
/// with implementations for any type that can be converted to a MemoryReference.
pub trait MemoryReferenceInfo<'a> {
    /// Converts this value to a MemoryReference.
    ///
    /// This is the core method that must be implemented by all types
    /// implementing this trait.
    fn to_memory_reference(&'a self) -> MemoryReference;

    /// Extracts the global address if this is a global memory reference.
    ///
    /// # Returns
    /// - `Some(usize)` containing the global address if this is a global reference
    /// - `None` if this is not a global reference
    fn as_global(&'a self) -> Option<usize> {
        match self.to_memory_reference() {
            MemoryReference::Global(g) => Some(g),
            _ => None,
        }
    }

    /// Checks if this reference is a global memory reference.
    ///
    /// # Returns
    /// `true` if this is a global memory reference, `false` otherwise
    fn is_global(&'a self) -> bool {
        self.as_global().is_some()
    }

    /// Extracts the offset if this is a stack-relative memory reference.
    ///
    /// # Returns
    /// - `Some(i128)` containing the stack offset if this is a stack-relative reference
    /// - `None` if this is not a stack-relative reference
    fn as_stack_relative(&'a self) -> Option<i128> {
        match self.to_memory_reference() {
            MemoryReference::StackRelative(n) => Some(n),
            _ => None,
        }
    }

    /// Checks if this reference is a stack-relative memory reference.
    ///
    /// # Returns
    /// `true` if this is a stack-relative memory reference, `false` otherwise
    fn is_stack_relative(&'a self) -> bool {
        self.as_stack_relative().is_some()
    }

    /// Extracts the expression if this is a dereferenced pointer.
    ///
    /// # Returns
    /// - `Some(Expression<MemoryReference>)` containing the dereferenced expression
    /// - `None` if this is not a dereferenced pointer
    fn as_deref(&'a self) -> Option<Expression<MemoryReference>> {
        match self.to_memory_reference() {
            MemoryReference::Deref(e) => Some(*e),
            _ => None,
        }
    }

    /// Checks if this reference is a dereferenced pointer.
    ///
    /// # Returns
    /// `true` if this is a dereferenced pointer, `false` otherwise
    fn is_deref(&'a self) -> bool {
        self.as_deref().is_some()
    }

    /// Extracts the pointer ID if this is a direct pointer reference.
    ///
    /// # Returns
    /// - `Some(PointerId)` containing the pointer identifier
    /// - `None` if this is not a direct pointer reference
    fn as_pointer(&'a self) -> Option<PointerId> {
        match self.to_memory_reference() {
            MemoryReference::Pointer(p) => Some(p),
            _ => None,
        }
    }

    /// Checks if this reference is a direct pointer.
    ///
    /// # Returns
    /// `true` if this is a direct pointer reference, `false` otherwise
    fn is_pointer(&'a self) -> bool {
        self.as_pointer().is_some()
    }

    /// Checks if this reference is an outgoing parameter (positive stack offset).
    ///
    /// Outgoing parameters are represented by positive stack-relative offsets.
    ///
    /// # Returns
    /// `true` if this is a stack-relative reference with positive offset, `false` otherwise
    fn is_outgoing_parameter(&'a self) -> bool {
        self.as_stack_relative().map(|n| n > 0).unwrap_or(false)
    }

    /// Checks if this reference is a local variable or incoming parameter (negative stack offset).
    ///
    /// Local variables and incoming parameters are represented by negative stack-relative offsets.
    ///
    /// # Returns
    /// `true` if this is a stack-relative reference with negative offset, `false` otherwise
    fn is_local_or_parameter(&'a self) -> bool {
        self.as_stack_relative().map(|n| n < 0).unwrap_or(false)
    }
}

/// This implementation allows the MemoryReferenceInfo trait to be used with
/// any type that can be converted into a MemoryReference, including both
/// owned and borrowed values. This provides flexibility when working with
/// different representations of memory references.
impl<'a, T: 'a> MemoryReferenceInfo<'a> for T
where
    &'a T: Into<MemoryReference>,
{
    fn to_memory_reference(&'a self) -> MemoryReference {
        self.into()
    }
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
pub struct InstructionNode<A> {
    pub id: InstructionId,
    pub kind: Instruction<A>,
}

/// Represents different kinds of low-level instructions.
///
/// Each instruction represents an operation in the intermediate representation.
/// The type parameter `A` represents the type of memory reference (typically `MemoryReference`),
/// which can be addressed (read from or written to) during instruction execution.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Instruction<A> {
    /// Assigns the result of an expression to a target address.
    Assign {
        /// Target location where the result will be stored.
        target: A,
        /// Source expression to evaluate.
        src: Expression<A>,
        /// Debug marker applies to the lhs side.
        target_debug_marker: Option<char>,
    },
    /// Conditional branch instruction.
    If {
        /// Condition to evaluate.
        cond: Expression<A>,
        /// Address to jump to if condition is true.
        then_addr: BlockId,
        /// Address to jump to if condition is false.
        else_addr: BlockId,
    },
    Goto(BlockId),
    /// Calls a function. Does not contain information on arguments and return values.
    Call {
        addr: Expression<A>,
        return_to: BlockId,
    },
    /// Outputs the result of an expression.
    Output(Expression<A>),
    /// Returns from the current function. Does not contain information on return values.
    Return,
    /// Halts execution.
    Halt,
}

impl<A> Instruction<A> {
    /// Collects the source expressions that this instruction evaluates.
    ///
    /// Different instruction types operate on different kinds of expressions:
    /// - Assign: The source expression to be assigned. Note that evaluating
    ///           the target expression will result in the source expression
    ///           being evaluated. See ReadAddressExtractor for more details.
    /// - If: The condition expression
    /// - Call: The target address expression
    /// - Output: The expression to be output
    /// - Other instructions (Goto, Return, Halt): No expressions
    pub fn collect_source_expressions(&self) -> Vec<&Expression<A>> {
        match self {
            Instruction::Assign { src, .. } => vec![src],
            Instruction::If { cond, .. } => vec![cond],
            Instruction::Goto(_) => vec![],
            Instruction::Call { addr, .. } => vec![addr],
            Instruction::Output(expr) => vec![expr],
            Instruction::Return | Instruction::Halt => vec![],
        }
    }
    /// Returns the target memory reference that this instruction writes to, if any.
    ///
    /// Only Assign instructions write to memory. For example, in an assignment
    /// like `mem[5] = value`, this would return a reference to memory location 5.
    pub fn get_write_address(&self) -> Option<&A> {
        match self {
            Instruction::Assign { target, .. } => Some(target),
            _ => None,
        }
    }
}

/// Represents a low-level expression that can be evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Expression<A> {
    /// A literal constant value.
    Constant(i128),
    /// A reference to an addressable location.
    Addressable(A),
    /// A binary operation with two operands.
    Binary {
        /// The binary operator.
        op: BinaryOperator,
        /// The left-hand side operand.
        lhs: Box<Expression<A>>,
        /// The right-hand side operand.
        rhs: Box<Expression<A>>,
    },
    /// A unary operation with one operand.
    Unary {
        /// The unary operator.
        op: UnaryOperator,
        /// The operand argument.
        arg: Box<Expression<A>>,
    },
    Input(), // Expression that reads the next input.
    DebugMarker(char, Box<Expression<A>>),
}

impl<A> Expression<A> {
    /// Collects all memory references that this expression reads from.
    ///
    /// This method recursively traverses the expression tree to find all memory
    /// references that are read during evaluation. It's a key component of data flow
    /// analysis, as it identifies all dependencies of an expression.
    ///
    /// # Returns
    /// A vector of references to all addressable locations accessed during
    /// evaluation of this expression.
    ///
    /// # Examples
    ///
    /// ```
    /// // For an expression like: mem[5] + mem[3]
    /// // This would return references to memory locations 5 and 3
    /// ```
    pub fn collect_read_addresses<'a>(&'a self) -> Vec<&'a A> {
        let mut out = vec![];
        let mut queue = vec![self];
        while let Some(expr) = queue.pop() {
            match expr {
                Expression::Constant(_) => {}
                Expression::Addressable(a) => out.push(a),
                Expression::Binary { lhs, rhs, .. } => {
                    queue.push(lhs);
                    queue.push(rhs);
                }
                Expression::Unary { arg, .. } => queue.push(arg),
                Expression::Input() => {}
                Expression::DebugMarker(_, expr) => queue.push(expr),
            }
        }
        out
    }

    /// Maps all addressable references in this expression using the provided function.
    ///
    /// This traverses the expression tree and applies a mapping function to each
    /// addressable reference, producing a new expression with transformed references.
    /// This is useful for address translation, renaming, or other transformations.
    ///
    /// # Parameters
    ///
    /// * `map`: A mutable function that transforms references of type `A` to type `B`
    ///
    /// # Returns
    ///
    /// A new expression with all addressable references transformed from type `A` to type `B`
    pub fn map<F, B>(&self, map: &mut F) -> Expression<B>
    where
        F: FnMut(&A) -> B,
    {
        match self {
            Expression::Constant(val) => Expression::Constant(*val),
            Expression::Addressable(a) => Expression::Addressable(map(a)),
            Expression::Binary { op, lhs, rhs } => Expression::Binary {
                op: *op,
                lhs: Box::new(lhs.map(map)),
                rhs: Box::new(rhs.map(map)),
            },
            Expression::Unary { op, arg } => Expression::Unary {
                op: *op,
                arg: Box::new(arg.map(map)),
            },
            Expression::Input() => Expression::Input(),
            Expression::DebugMarker(marker, expr) => {
                Expression::DebugMarker(*marker, Box::new(expr.map(map)))
            }
        }
    }

    /// Locates a subexpression marked with a specific debug marker.
    ///
    /// Searches the expression tree for a debug marker with the specified character
    /// and returns a reference to the expression contained within that marker.
    /// This is useful for finding specific points of interest in complex expressions
    /// that have been annotated during construction or analysis.
    ///
    /// # Parameters
    ///
    /// * `marker`: The character identifier of the debug marker to find
    ///
    /// # Returns
    ///
    /// A reference to the expression contained within the debug marker if found,
    /// or None if no matching marker exists in the expression tree
    pub fn find_debug_marker(self: &Expression<A>, marker: char) -> Option<&Expression<A>> {
        match self {
            Expression::DebugMarker(c, e) if *c == marker => Some(e),
            Expression::DebugMarker(_, e) => e.find_debug_marker(marker),
            Expression::Binary { lhs, rhs, .. } => lhs
                .find_debug_marker(marker)
                .or_else(|| rhs.find_debug_marker(marker)),
            Expression::Unary { arg, .. } => arg.find_debug_marker(marker),
            _ => None,
        }
    }
}

/// Represents binary operations that can be performed on two operands.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum BinaryOperator {
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

/// A trait for types that can extract read addresses from themselves.
///
/// This trait is crucial for data flow analysis, as it allows us to identify all memory
/// locations that are read when a value is used, including indirect reads through pointers.
///
/// For example, when writing to a dereferenced pointer (`*ptr = value`), we need to recognize
/// that `ptr` itself is being read to determine the target address. This trait provides a
/// standardized way to extract such read operations across different memory reference types.
pub trait ReadAddressExtractor {
    /// Extracts all memory references that are read when this value is used.
    ///
    /// This method is particularly important for:
    /// 1. Dereferenced pointers, where the pointer expression must be read
    /// 2. Complex memory addressing expressions that involve multiple reads
    ///
    /// # Returns
    /// A vector of references to all memory locations that are read when this value is used.
    fn extract_read_addresses(&self) -> Vec<&Self>;
}

impl ReadAddressExtractor for MemoryReference {
    fn extract_read_addresses(&self) -> Vec<&Self> {
        match self {
            // When dereferencing a pointer, we need to read the pointer expression
            MemoryReference::Deref(expr) => expr.collect_read_addresses(),
            // Other memory reference types don't involve indirect reads
            MemoryReference::Global(_) => Vec::new(),
            MemoryReference::StackRelative(_) => Vec::new(),
            MemoryReference::Pointer(_) => Vec::new(),
        }
    }
}

impl ReadAddressExtractor for SsaMemoryReference {
    fn extract_read_addresses(&self) -> Vec<&Self> {
        match self {
            // Similar to MemoryReference, we need to extract reads from dereferenced expressions
            SsaMemoryReference::Deref(expr) => expr.collect_read_addresses(),
            // Versioned references don't involve indirect reads
            SsaMemoryReference::Versioned(_) => vec![],
        }
    }
}

impl<A: ReadAddressExtractor> Instruction<A> {
    /// Collects all memory references that this instruction reads from.
    ///
    /// This method is essential for data flow analysis as it identifies all memory
    /// locations that an instruction depends on. It handles both:
    /// 1. Explicit reads in source expressions (e.g., `[100]` in `[101] = [100] + 5`)
    /// 2. Implicit reads in write targets (e.g., `ptr` in `*ptr = value`)
    ///
    /// The latter case is particularly important for correct liveness analysis and
    /// SSA conversion, as it ensures that pointers used in dereferenced writes are
    /// properly tracked as being read.
    ///
    /// # Returns
    /// A vector of references to all memory locations read by this instruction.
    pub fn collect_read_addresses(&self) -> Vec<&A> {
        // Start with reads from the write target (if any)
        // This is crucial for cases like *ptr = value where ptr is read
        let mut reads = self
            .get_write_address()
            .map_or(vec![], |a| a.extract_read_addresses());
        reads.extend(
            self.collect_source_expressions()
                .iter()
                .flat_map(|e| e.collect_read_addresses()),
        );
        reads
    }
}

impl Display for BinaryOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BinaryOperator::Add => write!(f, "+"),
            BinaryOperator::Mul => write!(f, "*"),
            BinaryOperator::Sub => write!(f, "-"),
            BinaryOperator::LessThan => write!(f, "<"),
            BinaryOperator::LessThanOrEqual => write!(f, "<="),
            BinaryOperator::GreaterThan => write!(f, ">"),
            BinaryOperator::GreaterThanOrEqual => write!(f, ">="),
            BinaryOperator::Equals => write!(f, "=="),
            BinaryOperator::NotEquals => write!(f, "!="),
        }
    }
}

/// Represents unary operations that can be performed on a single operand.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnaryOperator {
    /// Logical negation operation (!).
    Not,
    /// Arithmetic negation operation (-).
    Minus,
}

impl Display for UnaryOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnaryOperator::Not => write!(f, "!"),
            UnaryOperator::Minus => write!(f, "-"),
        }
    }
}

#[expect(dead_code)]
impl<A> Expression<A> {
    /// Checks if the expression is a constant.
    fn is_constant(&self) -> bool {
        matches!(self, Expression::Constant(_))
    }

    /// Checks if the expression is an addressable reference.
    fn is_addressable(&self) -> bool {
        matches!(self, Expression::Addressable(_))
    }

    /// Checks if the expression is a unary operation.
    fn is_unary(&self) -> bool {
        matches!(self, Expression::Unary { .. })
    }

    /// Checks if the expression is a binary operation.
    fn is_binary(&self) -> bool {
        matches!(self, Expression::Binary { .. })
    }

    /// Checks if the expression is a unary operation.
    /// This is an alias for `is_unary`.
    fn is_unary_op(&self) -> bool {
        matches!(self, Expression::Unary { .. })
    }

    /// Checks if the expression is a binary operation.
    /// This is an alias for `is_binary`.
    fn is_binary_op(&self) -> bool {
        matches!(self, Expression::Binary { .. })
    }

    /// Extracts the binary operation components if this expression is a binary operation.
    ///
    /// Returns a tuple containing the operator, left-hand side, and right-hand side
    /// if this is a binary operation, or None otherwise.
    fn as_binary_op(&self) -> Option<(BinaryOperator, &Expression<A>, &Expression<A>)> {
        match self {
            Expression::Binary { op, lhs, rhs } => Some((*op, lhs, rhs)),
            _ => None,
        }
    }
}

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
    pub fn convert_block<I>(native: I) -> Vec<InstructionNode<MemoryReference>>
    where
        I: IntoIterator<Item = NativeInstruction>,
    {
        let mut iter = native.into_iter().peekable();
        let mut result = vec![];
        while let Some(native) = iter.next() {
            let (skip, low) = InstructionNode::from_native_instruction_pair(native, iter.peek());
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
    /// instructions do not produce a low-level instruction.
    fn from_native_instruction_pair(
        native: NativeInstruction,
        next_instruction: Option<&NativeInstruction>,
    ) -> (usize, Option<InstructionNode<MemoryReference>>) {
        // matches returns the default case of (1, Some(i)), if it's anything else,
        // there's an early return.
        let kind = match native.kind {
            NativeInstructionKind::Add(a, b, c) => Instruction::Assign {
                target: c.kind.try_into().unwrap(),
                src: Expression::Binary {
                    op: BinaryOperator::Add,
                    lhs: Box::new(a.into()),
                    rhs: Box::new(b.into()),
                },
                target_debug_marker: c.debug_marker,
            },
            NativeInstructionKind::Mul(a, b, c) => Instruction::Assign {
                target: c.kind.try_into().unwrap(),
                src: Expression::Binary {
                    op: BinaryOperator::Mul,
                    lhs: Box::new(a.into()),
                    rhs: Box::new(b.into()),
                },
                target_debug_marker: c.debug_marker,
            },
            NativeInstructionKind::Input(a) => Instruction::Assign {
                target: a.kind.try_into().unwrap(),
                src: Expression::Input(),
                target_debug_marker: a.debug_marker,
            },
            NativeInstructionKind::Output(a) => Instruction::Output(a.into()),
            NativeInstructionKind::JumpIfTrue(cond, addr) => Instruction::If {
                cond: cond.into(),
                then_addr: match addr.into() {
                    Expression::Constant(a) => BlockId::from(a as usize),
                    _ => panic!("Expected constant address for jump"),
                },
                else_addr: BlockId::from(native.span.end),
            },
            NativeInstructionKind::JumpIfFalse(cond, addr) => Instruction::If {
                cond: Expression::Unary {
                    op: UnaryOperator::Not,
                    arg: Box::new(cond.into()),
                },
                then_addr: match addr.into() {
                    Expression::Constant(a) => BlockId::from(a as usize),
                    _ => panic!("Expected constant address for jump"),
                },
                else_addr: BlockId::from(native.span.end),
            },
            NativeInstructionKind::LessThan(a, b, c) => Instruction::Assign {
                target: c.kind.try_into().unwrap(),
                src: Expression::Binary {
                    op: BinaryOperator::LessThan,
                    lhs: Box::new(a.into()),
                    rhs: Box::new(b.into()),
                },
                target_debug_marker: a.debug_marker,
            },
            NativeInstructionKind::Equals(a, b, c) => Instruction::Assign {
                target: c.kind.try_into().unwrap(),
                src: Expression::Binary {
                    op: BinaryOperator::Equals,
                    lhs: Box::new(a.into()),
                    rhs: Box::new(b.into()),
                },
                target_debug_marker: c.debug_marker,
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
                            Some(InstructionNode {
                                id: InstructionId::fresh(),
                                kind: Instruction::Return,
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
            NativeInstructionKind::Halt => Instruction::Halt,
            NativeInstructionKind::Data(_) => {
                unreachable!("Data instruction should be removed")
            }
            NativeInstructionKind::Goto(addr) => Instruction::Goto(BlockId::from(
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
                        Some(InstructionNode {
                            kind: Instruction::Call {
                                addr: func_addr.clone().into(),
                                return_to: BlockId::from(return_to),
                            },
                            id: InstructionId::fresh(),
                        }),
                    );
                } else {
                    Instruction::Assign {
                        target: target.kind.try_into().unwrap(),
                        src: src.into(),
                        target_debug_marker: target.debug_marker,
                    }
                }
            }
        };
        (
            1,
            Some(InstructionNode {
                kind,
                id: InstructionId::fresh(),
            }),
        )
    }
}

impl<A> InstructionNode<A> {
    pub fn map_rw<C, R, W, T>(
        &self,
        context: &mut C,
        mut map_read: R,
        mut map_write: W,
    ) -> InstructionNode<T>
    where
        R: FnMut(&mut C, &A) -> T,
        W: FnMut(&mut C, &A) -> T,
        C: std::fmt::Debug,
    {
        match &self.kind {
            Instruction::Assign {
                target,
                src,
                target_debug_marker,
            } => {
                if self.id == InstructionId::from(6) {
                    print!("hello!: {:?}", context);
                }
                InstructionNode {
                    id: self.id,
                    kind: Instruction::Assign {
                        target: map_write(context, &target),
                        src: src.map(&mut |v| map_read(context, v)),
                        target_debug_marker: *target_debug_marker,
                    },
                }
            }
            Instruction::If {
                cond,
                then_addr,
                else_addr,
            } => InstructionNode {
                id: self.id,
                kind: Instruction::If {
                    cond: cond.map(&mut |v| map_read(context, v)),
                    then_addr: *then_addr,
                    else_addr: *else_addr,
                },
            },
            Instruction::Goto(addr) => InstructionNode {
                id: self.id,
                kind: Instruction::Goto(*addr),
            },
            Instruction::Call { addr, return_to } => InstructionNode {
                id: self.id,
                kind: Instruction::Call {
                    addr: addr.map(&mut |v| map_read(context, v)),
                    return_to: *return_to,
                },
            },
            Instruction::Output(expr) => InstructionNode {
                id: self.id,
                kind: Instruction::Output(expr.map(&mut |v| map_read(context, v))),
            },
            Instruction::Return => InstructionNode {
                id: self.id,
                kind: Instruction::Return,
            },
            Instruction::Halt => InstructionNode {
                id: self.id,
                kind: Instruction::Halt,
            },
        }
    }
}
