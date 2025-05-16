// Use LIR MemoryReference
use std::fmt::Display;

use dsl_macros_impl::match_dsl;

use crate::disasm::v3::ssa::SsaMemoryReference;
use crate::macros::build_expr;

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
}

impl Expression<SsaMemoryReference> {
    pub fn simplify(&self) -> Option<Self> {
        let mut current = self.clone();
        let mut count = 0;

        while let Some(next) = current.simplify_once() {
            current = next;
            count += 1;
        }

        if count == 0 {
            None
        } else {
            Some(current)
        }
    }

    fn simplify_once(&self) -> Option<Expression<SsaMemoryReference>> {
        match_dsl!(self,
            $lhs:expr + 0 => {
                Some(lhs.clone()) // x + 0 == x
            },
            0 + $rhs:expr => {
                Some(rhs.clone()) // 0 + x == x
            },
            $lhs:expr + $rhs:const if rhs < &0 => {
                let lhs_expr = lhs.clone();
                let neg_x_expr = Expression::Constant(-*rhs); // -x is positive here
                Some(build_expr!(#lhs_expr - #neg_x_expr)) // a + (-b) == a - b
            },
            -$arg:expr + $rhs:expr => {
                // (-a) + b == b - a
                let rhs_expr = rhs.clone();
                let arg_expr = arg.clone();
                Some(build_expr!(#rhs_expr - #arg_expr))
            },
            $lhs:expr + -$arg:expr => {
                // a + (-b) == a - b
                let lhs_expr = lhs.clone();
                let arg_expr = arg.clone();
                Some(build_expr!(#lhs_expr - #arg_expr))
            },
            $lhs:expr + $rhs:expr => {
                let lhs_simplified = lhs.simplify();
                let rhs_simplified = rhs.simplify();
                if lhs_simplified.is_some() || rhs_simplified.is_some() {
                    let final_lhs = lhs_simplified.unwrap_or_else(|| lhs.clone());
                    let final_rhs = rhs_simplified.unwrap_or_else(|| rhs.clone());
                    Some(build_expr!(#final_lhs + #final_rhs))
                } else {
                    None
                }
            },
            $lhs:expr - 0 => {
                Some(lhs.clone()) // lhs - 0 = lhs
            },
            0 - $rhs:expr => {
                let rhs_expr = rhs.clone();
                Some(build_expr!(-#rhs_expr)) // 0 - rhs = -rhs
            },
            $lhs:expr - $rhs:const if rhs < &0 => {
                let lhs_expr = lhs.clone();
                let neg_x_expr = Expression::Constant(-*rhs); // -x is positive here
                Some(build_expr!(#lhs_expr + #neg_x_expr)) // lhs - (-x) = lhs + x
            },
            $lhs:expr - -$arg:expr => {
                // lhs - (-arg) = lhs + arg
                let lhs_expr = lhs.clone();
                let arg_expr = arg.clone();
                Some(build_expr!(#lhs_expr + #arg_expr))
            },
            $lhs:expr - $rhs:expr => {
                let lhs_simplified = lhs.simplify();
                let rhs_simplified = rhs.simplify();
                if lhs_simplified.is_some() || rhs_simplified.is_some() {
                    let final_lhs = lhs_simplified.unwrap_or_else(|| lhs.clone());
                    let final_rhs = rhs_simplified.unwrap_or_else(|| rhs.clone());
                    Some(build_expr!(#final_lhs - #final_rhs))
                } else {
                    None
                }
            },
            _ * 0 => {
                Some(build_expr! {0 })
            },
            0 * _ => {
                Some(build_expr! {0 })
            },
            $lhs:expr * 1 => {
                Some(lhs.clone()) // x * 1 = x
            },
            1 * $rhs:expr => {
                Some(rhs.clone()) // 1 * x = x
            },
            $lhs:expr * -1 => {
                let lhs_expr = lhs.clone();
                Some(build_expr!(-#lhs_expr)) // x * -1 = -x
            },
            -1 * $rhs:expr => {
                let rhs_expr = rhs.clone();
                Some(build_expr!(-#rhs_expr)) // -1 * x = -x
            },
            $lhs:expr * $rhs:expr => {
                let lhs_simplified = lhs.simplify();
                let rhs_simplified = rhs.simplify();
                if lhs_simplified.is_some() || rhs_simplified.is_some() {
                    let final_lhs = lhs_simplified.unwrap_or_else(|| lhs.clone());
                    let final_rhs = rhs_simplified.unwrap_or_else(|| rhs.clone());
                    Some(build_expr!(#final_lhs * #final_rhs))
                } else {
                    None
                }
            },
            !($lhs:expr < $rhs:expr) => {
                let lhs_expr = lhs.simplify().unwrap_or_else(|| lhs.clone());
                let rhs_expr = rhs.simplify().unwrap_or_else(|| rhs.clone());
                Some(Expression::Binary {
                    op: BinaryOperator::GreaterThanOrEqual,
                    lhs: Box::new(lhs_expr),
                    rhs: Box::new(rhs_expr),
                })
            },
            !($lhs:expr <= $rhs:expr) => {
                let lhs_expr = lhs.simplify().unwrap_or_else(|| lhs.clone());
                let rhs_expr = rhs.simplify().unwrap_or_else(|| rhs.clone());
                Some(Expression::Binary {
                    op: BinaryOperator::GreaterThan,
                    lhs: Box::new(lhs_expr),
                    rhs: Box::new(rhs_expr),
                })
            },
            !($lhs:expr > $rhs:expr) => {
                let lhs_expr = lhs.simplify().unwrap_or_else(|| lhs.clone());
                let rhs_expr = rhs.simplify().unwrap_or_else(|| rhs.clone());
                Some(Expression::Binary {
                    op: BinaryOperator::LessThanOrEqual,
                    lhs: Box::new(lhs_expr),
                    rhs: Box::new(rhs_expr),
                })
            },
            !($lhs:expr >= $rhs:expr) => {
                let lhs_expr = lhs.simplify().unwrap_or_else(|| lhs.clone());
                let rhs_expr = rhs.simplify().unwrap_or_else(|| rhs.clone());
                Some(Expression::Binary {
                    op: BinaryOperator::LessThan,
                    lhs: Box::new(lhs_expr),
                    rhs: Box::new(rhs_expr),
                })
            },
            !($lhs:expr == $rhs:expr) => {
                let lhs_expr = lhs.simplify().unwrap_or_else(|| lhs.clone());
                let rhs_expr = rhs.simplify().unwrap_or_else(|| rhs.clone());
                Some(Expression::Binary {
                    op: BinaryOperator::NotEquals,
                    lhs: Box::new(lhs_expr),
                    rhs: Box::new(rhs_expr),
                })
            },
            !($lhs:expr != $rhs:expr) => {
                let lhs_expr = lhs.simplify().unwrap_or_else(|| lhs.clone());
                let rhs_expr = rhs.simplify().unwrap_or_else(|| rhs.clone());
                Some(Expression::Binary {
                    op: BinaryOperator::Equals,
                    lhs: Box::new(lhs_expr),
                    rhs: Box::new(rhs_expr),
                })
            },
            !$arg:expr => {
                arg.simplify().map(|simplified_arg| build_expr!(!#simplified_arg))
            },
            _ => None
        )
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

#[cfg(test)]
mod tests {
    use super::Expression;
    use crate::{
        disasm::v3::{common::formatting::ContextualPrettyPrint, ssa::SsaMemoryReference},
        macros::build_expr,
    };

    macro_rules! assert_simplifies_to {
        ($original:expr, $expected_str:expr) => {
            let original: Expression<SsaMemoryReference> = $original;
            let simplified = original.simplify().unwrap_or_else(|| {
                panic!(
                    "Expression {:?} was expected to simplify to '{}', but did not simplify.",
                    original, $expected_str
                )
            });
            assert_eq!(
                simplified.nocolor(),
                $expected_str,
                "Simplified expression mismatch for original: {}",
                original
            );
        };
    }

    fn assert_no_simplification(original: Expression<SsaMemoryReference>) {
        assert_eq!(
            original.simplify(),
            None,
            "Expression {:?} was expected not to simplify, but did.",
            original
        );
    }

    #[test]
    fn test_simplify_add() {
        // x + 0 = x
        assert_simplifies_to!(build_expr! { 5 + 0 }, "5");
        assert_simplifies_to!(build_expr! { [R+1].0 + 0 }, "[R+1]_0");

        // 0 + x = x
        assert_simplifies_to!(build_expr! { 0 + 5 }, "5");
        assert_simplifies_to!(build_expr! { 0 + [R+1].0 }, "[R+1]_0");

        // a + (-b_const) = a - b_const  (where b_const is positive, so -b_const is a negative const)
        assert_simplifies_to!(build_expr! { 5 + -2 }, "5 - 2"); // 5 + Constant(-2) -> 5 - Constant(2)
        assert_simplifies_to!(build_expr! { [R+1].0 + -2 }, "[R+1]_0 - 2");

        // (-a_expr) + b_expr = b_expr - a_expr
        assert_simplifies_to!(build_expr! { -[R+1].0 + [R+2].0 }, "[R+2]_0 - [R+1]_0");
        assert_simplifies_to!(build_expr! { -5 + [R+2].0 }, "[R+2]_0 - 5"); // Unary(Minus, Constant(5)) + X -> X - Constant(5)

        // a_expr + (-b_expr) = a_expr - b_expr
        assert_simplifies_to!(build_expr! { [R+1].0 + -[R+2].0 }, "[R+1]_0 - [R+2]_0");
        assert_simplifies_to!(build_expr! { 5 + -[R+2].0 }, "5 - [R+2]_0");

        // Recursive simplification of operands
        assert_simplifies_to!(build_expr! { ([R+1].0 + 0) + [R+2].0 }, "[R+1]_0 + [R+2]_0");
        assert_simplifies_to!(build_expr! { [R+1].0 + (0 + [R+2].0) }, "[R+1]_0 + [R+2]_0");
        assert_simplifies_to!(
            build_expr! { ([R+1].0 + 0) + ([R+2].0 + 0) },
            "[R+1]_0 + [R+2]_0"
        );
    }

    #[test]
    fn test_simplify_sub() {
        // x - 0 = x
        assert_simplifies_to!(build_expr! { 5 - 0 }, "5");
        assert_simplifies_to!(build_expr! { [R+1].0 - 0 }, "[R+1]_0");

        // 0 - x = -x
        assert_simplifies_to!(build_expr! { 0 - 5 }, "-5");
        assert_simplifies_to!(build_expr! { 0 - [R+1].0 }, "-[R+1]_0");

        // x - (-y_const) = x + y_const (where y_const is positive)
        assert_simplifies_to!(build_expr! { 5 - -2 }, "5 + 2"); // 5 - Constant(-2) -> 5 + Constant(2)
        assert_simplifies_to!(build_expr! { [R+1].0 - -2 }, "[R+1]_0 + 2");

        // x - (-y_expr) = x + y_expr
        assert_simplifies_to!(build_expr! { [R+1].0 - -[R+2].0 }, "[R+1]_0 + [R+2]_0");
        assert_simplifies_to!(build_expr! { 5 - -[R+2].0 }, "5 + [R+2]_0");

        // Recursive simplification of operands
        assert_simplifies_to!(build_expr! { ([R+1].0 - 0) - [R+2].0 }, "[R+1]_0 - [R+2]_0");
        assert_simplifies_to!(build_expr! { [R+1].0 - (0 - [R+2].0) }, "[R+1]_0 + [R+2]_0"); // [R+1].0 - (-[R+2].0) -> [R+1].0 + [R+2].0
        assert_simplifies_to!(
            build_expr! { ([R+1].0 - 0) - ([R+2].0 - 0) },
            "[R+1]_0 - [R+2]_0"
        );
    }

    #[test]
    fn test_simplify_mul() {
        // x * 0 = 0
        assert_simplifies_to!(build_expr! { 5 * 0 }, "0");
        assert_simplifies_to!(build_expr! { [R+1].0 * 0 }, "0");

        // 0 * x = 0
        assert_simplifies_to!(build_expr! { 0 * 5 }, "0");
        assert_simplifies_to!(build_expr! { 0 * [R+1].0 }, "0");

        // x * 1 = x
        assert_simplifies_to!(build_expr! { 5 * 1 }, "5");
        assert_simplifies_to!(build_expr! { [R+1].0 * 1 }, "[R+1]_0");

        // 1 * x = x
        assert_simplifies_to!(build_expr! { 1 * 5 }, "5");
        assert_simplifies_to!(build_expr! { 1 * [R+1].0 }, "[R+1]_0");

        // x * -1 = -x
        assert_simplifies_to!(build_expr! { 5 * -1 }, "-5");
        assert_simplifies_to!(build_expr! { [R+1].0 * -1 }, "-[R+1]_0");

        // -1 * x = -x
        assert_simplifies_to!(build_expr! { -1 * 5 }, "-5"); // Constant(-1) * 5 -> -5
        assert_simplifies_to!(build_expr! { -1 * [R+1].0 }, "-[R+1]_0");

        // Recursive simplification of operands
        assert_simplifies_to!(build_expr! { ([R+1].0 * 1) * [R+2].0 }, "[R+1]_0 * [R+2]_0");
        assert_simplifies_to!(build_expr! { [R+1].0 * (1 * [R+2].0) }, "[R+1]_0 * [R+2]_0");
        assert_simplifies_to!(
            build_expr! { ([R+1].0 * 1) * ([R+2].0 * 1) },
            "[R+1]_0 * [R+2]_0"
        );
    }

    #[test]
    fn test_simplify_not() {
        // !(a < b)  -> a >= b
        assert_simplifies_to!(build_expr! { !([R+1].0 < [R+2].0) }, "[R+1]_0 >= [R+2]_0");
        // !(a <= b) -> a > b
        assert_simplifies_to!(build_expr! { !([R+1].0 <= [R+2].0) }, "[R+1]_0 > [R+2]_0");
        // !(a > b)  -> a <= b
        assert_simplifies_to!(build_expr! { !([R+1].0 > [R+2].0) }, "[R+1]_0 <= [R+2]_0");
        // !(a >= b) -> a < b
        assert_simplifies_to!(build_expr! { !([R+1].0 >= [R+2].0) }, "[R+1]_0 < [R+2]_0");
        // !(a == b) -> a != b
        assert_simplifies_to!(build_expr! { !([R+1].0 == [R+2].0) }, "[R+1]_0 != [R+2]_0");
        // !(a != b) -> a == b
        assert_simplifies_to!(build_expr! { !([R+1].0 != [R+2].0) }, "[R+1]_0 == [R+2]_0");

        // Negation of non-comparison binary op does not use logical_negate path, falls to recursive simplify
        // !([R+1].0 + [R+2].0) has arg ([R+1].0 + [R+2].0) which doesn't simplify. So result is None.
        assert_no_simplification(build_expr! { !([R+1].0 + [R+2].0) });

        // Recursive simplification of arg if not a binary comparison that can be negated by rule
        assert_simplifies_to!(build_expr! { !([R+1].0 + 0) }, "![R+1]_0"); // arg ([R+1].0+0) simplifies to [R+1].0
        assert_simplifies_to!(build_expr! { !([R+1].0 * 1) }, "![R+1]_0"); // arg ([R+1].0*1) simplifies to [R+1].0
        assert_simplifies_to!(build_expr! { !(0 + [R+1].0) }, "![R+1]_0"); // arg (0+[R+1].0) simplifies to [R+1].0

        // Double negation: !!(cmp) -> cmp
        // !!(A==B) -> !(A!=B) -> A==B
        assert_simplifies_to!(build_expr! { !!([R+1].0 == [R+2].0) }, "[R+1]_0 == [R+2]_0");
        assert_simplifies_to!(build_expr! { !!([R+1].0 < [R+2].0) }, "[R+1]_0 < [R+2]_0");

        // Logical negation path does not simplify operands of the comparison itself
        assert_simplifies_to!(
            build_expr! { !(([R+1].0 + 0) < [R+2].0) },
            "[R+1]_0 >= [R+2]_0"
        );
        assert_simplifies_to!(
            build_expr! { !([R+1].0 < ([R+2].0 + 0)) },
            "[R+1]_0 >= [R+2]_0"
        );
        assert_simplifies_to!(
            build_expr! { !(([R+1].0 + 0) < ([R+2].0 + 0)) },
            "[R+1]_0 >= [R+2]_0"
        );
    }

    #[test]
    fn test_no_simplification_cases() {
        // Basic expressions that don't match any rule
        assert_no_simplification(build_expr! { 1 + 2 });
        assert_no_simplification(build_expr! { [R+1].0 + [R+2].0 });
        assert_no_simplification(build_expr! { [R+1].0 - [R+2].0 }); // e.g. not X-0 or 0-X
        assert_no_simplification(build_expr! { [R+1].0 * [R+2].0 }); // e.g. not *0, *1, *-1
        assert_no_simplification(build_expr! { [R+1].0 * 2 });

        // Unary minus itself (not as part of add/sub)
        assert_no_simplification(build_expr! { -[R+1].0 });
        // Unary minus where argument can be simplified, but Unary Minus itself has no top-level rule
        // This behavior is specific to current implementation: no recursive simplify for UnaryOp::Minus arg.
        assert_no_simplification(build_expr! { -([R+1].0 + 0) });

        // Unary not where arg cannot be simplified further and is not a comparison covered by logical_negate
        assert_no_simplification(build_expr! { ![R+1].0 });
        assert_no_simplification(build_expr! { !([R+1].0 + [R+2].0) }); // Arg ([R+1].0 + [R+2].0) is not a comparison and doesn't simplify

        // Comparisons themselves don't simplify
        assert_no_simplification(build_expr! {[R+1].0 < [R+2].0});
        // Operands of comparison don't simplify if the comparison itself is not simplified
        assert_no_simplification(build_expr! {([R+1].0 + 0) < [R+2].0});
    }

    #[test]
    fn test_complex_recursive_simplifications() {
        // (x+0) + (y-0) -> x+y
        assert_simplifies_to!(
            build_expr! { ([R+1].0 + 0) + ([R+2].0 - 0) },
            "[R+1]_0 + [R+2]_0"
        );
        // (x*1) - (y*0) -> x - 0 -> x
        assert_simplifies_to!(build_expr! { ([R+1].0 * 1) - ([R+2].0 * 0) }, "[R+1]_0");
        // (0 + x) * (1 * y) -> x * y
        assert_simplifies_to!(
            build_expr! { (0 + [R+1].0) * (1 * [R+2].0) },
            "[R+1]_0 * [R+2]_0"
        );

        assert_simplifies_to!(
            build_expr! { !(([R+1].0 + 0) == ([R+2].0 * 1)) },
            "[R+1]_0 != [R+2]_0"
        );

        // Add involving subtraction simplification: (a + 0) + (0 - b) -> a + (-b) -> a - b
        assert_simplifies_to!(
            build_expr! { ([R+1].0 + 0) + (0 - [R+2].0) },
            "[R+1]_0 - [R+2]_0"
        );
    }
}
