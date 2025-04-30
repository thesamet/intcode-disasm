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

/// Represents different kinds of low-level instructions.
pub enum InstructionKind<A> {
    /// Assigns the result of an expression to a target address.
    Assign {
        /// Target location where the result will be stored.
        target: Addressable,
        /// Source expression to evaluate.
        src: LowExpr<A>,
    },
    /// Conditional branch instruction.
    If {
        /// Condition to evaluate.
        cond: LowExpr<A>,
        /// Address to jump to if condition is true.
        then_addr: usize,
        /// Address to jump to if condition is false.
        else_addr: usize,
    },
    /// Calls a function. Does not contain information on arguments and return values.
    Call { addr: LowExpr<A> },
    /// Outputs the result of an expression.
    Output(LowExpr<A>),
    /// Returns from the current function. Does not contain information on return values.
    Return,
    /// Halts execution.
    Halt,
}

/// Represents a low-level expression that can be evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
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
