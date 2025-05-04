use std::fmt::Display;
use super::MemoryReference;

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
