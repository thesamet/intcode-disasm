// Use LIR MemoryReference
use std::fmt::Display;

use crate::{lir_expr, match_expr};

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
    pub fn collect_read_addresses(&self) -> Vec<&A> {
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
    pub fn map<F, B>(&self, mut map: F) -> Expression<B>
    where
        F: FnMut(&A) -> B,
    {
        self.flat_map(&mut |x| Expression::Addressable(map(x)))
    }

    pub fn flat_map<T, F>(&self, f: &mut F) -> Expression<T>
    where
        F: FnMut(&A) -> Expression<T>,
    {
        match &self {
            Expression::Constant(val) => Expression::Constant(*val),
            Expression::Addressable(a) => f(a),
            Expression::Binary { op, lhs, rhs } => Expression::Binary {
                op: *op,
                lhs: Box::new(lhs.flat_map(f)),
                rhs: Box::new(rhs.flat_map(f)),
            },
            Expression::Unary { op, arg } => Expression::Unary {
                op: *op,
                arg: Box::new(arg.flat_map(f)),
            },
            Expression::Input() => Expression::Input(),
            Expression::DebugMarker(marker, expr) => {
                Expression::DebugMarker(*marker, Box::new(expr.flat_map(f)))
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

    pub fn simplify(&self) -> Option<Expression<A>>
    where
        A: Clone,
    {
        match_expr!(self,
        binary BinaryOperator::Add { lhs, rhs } => {
            match_expr!(**lhs, const 0 => {
                return Some((**lhs).clone())
            });
            match_expr!(**rhs, const 0 => {
                return Some((**rhs).clone())
            });
            match_expr!(**rhs, const x if x < 0 => {
                return Some(lir_expr!(sub {lhs.as_ref().clone()} {lir_expr!(const -x)}));
            });
            match_expr!(lhs.as_ref(), unary UnaryOperator::Minus {arg} => {
                return Some(lir_expr!(sub {rhs.as_ref().clone()} {arg.as_ref().clone()}));
            });
            match_expr!(rhs.as_ref(), unary UnaryOperator::Minus {arg} => {
                return Some(lir_expr!(sub {lhs.as_ref().clone()} {arg.as_ref().clone()}));
            });
            let lhs_simplified = lhs.simplify();
            let rhs_simplified = rhs.simplify();
            if lhs_simplified.is_some() || rhs_simplified.is_some() {
                return Some(lir_expr!(add {lhs_simplified.unwrap_or_else(|| lhs.as_ref().clone())} {rhs_simplified.unwrap_or_else(|| rhs.as_ref().clone())}));
            }
            return None
        });
        match_expr!(self,
        binary BinaryOperator::Sub { lhs, rhs } => {
            match_expr!(**lhs, const 0 => {
                return Some((**lhs).clone())
            });
            match_expr!(**rhs, const 0 => {
                return Some((**rhs).clone())
            });
            match_expr!(**rhs, const x if x < 0 => {
                return Some(lir_expr!(add {lhs.as_ref().clone()} {lir_expr!(const -x)}));
            });
            match_expr!(rhs.as_ref(), unary UnaryOperator::Minus { arg }=> {
                return Some(lir_expr!(add {lhs.as_ref().clone()} {arg.as_ref().clone()}));
            });
            let lhs_simplified = lhs.simplify();
            let rhs_simplified = rhs.simplify();
            if lhs_simplified.is_some() || rhs_simplified.is_some() {
                return Some(lir_expr!(sub {lhs_simplified.unwrap_or_else(|| lhs.as_ref().clone())} {rhs_simplified.unwrap_or_else(|| rhs.as_ref().clone())}));
            }
            return None
        });
        match_expr!(self,
            binary BinaryOperator::Mul { lhs, rhs } => {
                match_expr!(**lhs, const 0 => {
                    return Some((**lhs).clone())
                });
                match_expr!(**rhs, const 0 => {
                    return Some((**rhs).clone())
                });
                match_expr!(**rhs, const -1 => {
                    return Some(lir_expr!(minus {lhs.as_ref().clone()}));
                });
                match_expr!(**lhs, const -1 => {
                    return Some(lir_expr!(minus {rhs.as_ref().clone()}));
                });
                let lhs_simplified = lhs.simplify();
                let rhs_simplified = rhs.simplify();
                if lhs_simplified.is_some() || rhs_simplified.is_some() {
                    return Some(lir_expr!(mul {lhs_simplified.unwrap_or_else(|| lhs.as_ref().clone())} {rhs_simplified.unwrap_or_else(|| rhs.as_ref().clone())}));
                }
                return None;
            }
        );
        match_expr!(self,
            unary UnaryOperator::Not { arg } => {
                if let Expression::Binary { op, lhs, rhs } = arg.as_ref() {
                    if let Some(new_op) = op.logical_negate() {
                        return Some(lir_expr!(binary new_op {lhs.as_ref().clone()} {rhs.as_ref().clone()}));
                    }
                }
                return arg.simplify().map(|arg| lir_expr!(not {arg}));
            }
        );
        None
    }
}

impl<A> From<A> for Expression<A> {
    fn from(value: A) -> Self {
        Expression::Addressable(value)
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

impl BinaryOperator {
    pub fn logical_negate(&self) -> Option<BinaryOperator> {
        match self {
            BinaryOperator::Add => None,
            BinaryOperator::Mul => None,
            BinaryOperator::Sub => None,
            BinaryOperator::LessThan => Some(BinaryOperator::GreaterThanOrEqual),
            BinaryOperator::LessThanOrEqual => Some(BinaryOperator::GreaterThan),
            BinaryOperator::GreaterThan => Some(BinaryOperator::LessThanOrEqual),
            BinaryOperator::GreaterThanOrEqual => Some(BinaryOperator::LessThan),
            BinaryOperator::Equals => Some(BinaryOperator::NotEquals),
            BinaryOperator::NotEquals => Some(BinaryOperator::Equals),
        }
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
