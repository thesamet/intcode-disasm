#[macro_export]
macro_rules! lir_expr {
    // Base cases:
    (const $val:expr) => {
        // Adjust path to Expression, UnaryOperator, BinaryOperator as needed
        // depending on where this macro is defined and used.
        // Assuming it can access them via $crate::disasm::v3::lir::...
        $crate::disasm::v3::lir::Expression::Constant($val)
    };
    (addr $addr:expr) => {
        $crate::disasm::v3::lir::Expression::Addressable($addr)
    };
    (input) => {
        $crate::disasm::v3::lir::Expression::Input()
    };

    // Unary operations:
    (neg {$($arg:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Unary {
            op: $crate::disasm::v3::lir::UnaryOperator::Minus,
            arg: Box::new($crate::lir_expr!($($arg)+)),
        }
    };
    (not {$($arg:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Unary {
            op: $crate::disasm::v3::lir::UnaryOperator::Not,
            arg: Box::new($crate::lir_expr!($($arg)+)),
        }
    };

    // Binary operations:
    (add {$($lhs:tt)+} {$($rhs:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Binary {
            op: $crate::disasm::v3::lir::BinaryOperator::Add,
            lhs: Box::new($crate::lir_expr!($($lhs)+)),
            rhs: Box::new($crate::lir_expr!($($rhs)+)),
        }
    };
    (sub {$($lhs:tt)+} {$($rhs:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Binary {
            op: $crate::disasm::v3::lir::BinaryOperator::Sub,
            lhs: Box::new($crate::lir_expr!($($lhs)+)),
            rhs: Box::new($crate::lir_expr!($($rhs)+)),
        }
    };
    (mul {$($lhs:tt)+} {$($rhs:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Binary {
            op: $crate::disasm::v3::lir::BinaryOperator::Mul,
            lhs: Box::new($crate::lir_expr!($($lhs)+)),
            rhs: Box::new($crate::lir_expr!($($rhs)+)),
        }
    };
    (lt {$($lhs:tt)+} {$($rhs:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Binary {
            op: $crate::disasm::v3::lir::BinaryOperator::LessThan,
            lhs: Box::new($crate::lir_expr!($($lhs)+)),
            rhs: Box::new($crate::lir_expr!($($rhs)+)),
        }
    };
    (lte {$($lhs:tt)+} {$($rhs:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Binary {
            op: $crate::disasm::v3::lir::BinaryOperator::LessThanOrEqual,
            lhs: Box::new($crate::lir_expr!($($lhs)+)),
            rhs: Box::new($crate::lir_expr!($($rhs)+)),
        }
    };
    (gt {$($lhs:tt)+} {$($rhs:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Binary {
            op: $crate::disasm::v3::lir::BinaryOperator::GreaterThan,
            lhs: Box::new($crate::lir_expr!($($lhs)+)),
            rhs: Box::new($crate::lir_expr!($($rhs)+)),
        }
    };
    (gte {$($lhs:tt)+} {$($rhs:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Binary {
            op: $crate::disasm::v3::lir::BinaryOperator::GreaterThanOrEqual,
            lhs: Box::new($crate::lir_expr!($($lhs)+)),
            rhs: Box::new($crate::lir_expr!($($rhs)+)),
        }
    };
    (eq {$($lhs:tt)+} {$($rhs:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Binary {
            op: $crate::disasm::v3::lir::BinaryOperator::Equals,
            lhs: Box::new($crate::lir_expr!($($lhs)+)),
            rhs: Box::new($crate::lir_expr!($($rhs)+)),
        }
    };
    (neq {$($lhs:tt)+} {$($rhs:tt)+}) => {
        $crate::disasm::v3::lir::Expression::Binary {
            op: $crate::disasm::v3::lir::BinaryOperator::NotEquals,
            lhs: Box::new($crate::lir_expr!($($lhs)+)),
            rhs: Box::new($crate::lir_expr!($($rhs)+)),
        }
    };

    // Debug Marker:
    (marker $char:literal {$($expr:tt)+}) => {
        $crate::disasm::v3::lir::Expression::DebugMarker($char, Box::new($crate::lir_expr!($($expr)+)))
    };
}

#[macro_export]
macro_rules! match_expr {
    // Matching Constant
    ($expr_to_match:expr, const $val_pat:pat => $body:expr) => {
        if let $crate::disasm::v3::lir::Expression::Constant($val_pat) = $expr_to_match {
            $body
        }
    };
    ($expr_to_match:expr, const $val_pat:pat if $guard:expr => $body:expr) => {
        if let $crate::disasm::v3::lir::Expression::Constant($val_pat) = $expr_to_match {
            if $guard {
                $body
            }
        }
    };

    // Matching Addressable
    ($expr_to_match:expr, addr $addr_pat:pat => $body:expr) => {
        if let $crate::disasm::v3::lir::Expression::Addressable($addr_pat) = $expr_to_match {
            $body
        }
    };
    ($expr_to_match:expr, addr $addr_pat:pat if $guard:expr => $body:expr) => {
        if let $crate::disasm::v3::lir::Expression::Addressable($addr_pat) = $expr_to_match {
            if $guard {
                $body
            }
        }
    };

    // Matching Unary with specific operator
    ($expr_to_match:expr, unary $op_pat:path, $arg_pat:pat => $body:expr) => {
        if let $crate::disasm::v3::lir::Expression::Unary {
            op: $op_pat,
            arg: $arg_pat,
        } = $expr_to_match
        {
            $body
        }
    };
    ($expr_to_match:expr, unary $op_pat:path, $arg_pat:pat if $guard:expr => $body:expr) => {
        if let $crate::disasm::v3::lir::Expression::Unary {
            op: $op_pat,
            arg: $arg_pat,
        } = $expr_to_match
        {
            if $guard {
                $body
            }
        }
    };

    // Matching Binary with specific operator
    ($expr_to_match:expr, binary $op_pat:path, $lhs_pat:pat, $rhs_pat:pat => $body:expr) => {
        if let $crate::disasm::v3::lir::Expression::Binary {
            op: $op_pat,
            lhs: $lhs_pat,
            rhs: $rhs_pat,
        } = $expr_to_match
        {
            $body
        }
    };
    ($expr_to_match:expr, binary $op_pat:path, $lhs_pat:pat, $rhs_pat:pat if $guard:expr => $body:expr) => {
        if let $crate::disasm::v3::lir::Expression::Binary {
            op: $op_pat,
            lhs: $lhs_pat,
            rhs: $rhs_pat,
        } = $expr_to_match
        {
            if $guard {
                $body
            }
        }
    }; // ... add other variants like Input, DebugMarker
}
