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
    (minus {$($arg:tt)+}) => {
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

    (binary $op:path { $($lhs:tt)+ } { $($rhs:tt)+ }) => {
        $crate::disasm::v3::lir::Expression::Binary {
            op: $op,
            lhs: Box::new($crate::lir_expr!($($lhs)+)),
            rhs: Box::new($crate::lir_expr!($($rhs)+)),
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

    // must be last: any other expression is passed through. Used to pass through
    // already formed expression from outside of the macro.
    //
    ($e:expr) => { $e }
}

#[macro_export]
macro_rules! match_expr {
    ($expr: expr, const $val_pat:pat $(if $val_guard:expr)? => $body:expr) => {
        if let $crate::disasm::v3::lir::Expression::Constant($val_pat) = $expr {
            if true $(&& $val_guard)? {
                $body
            }
        }
    };
    ($expr: expr, addr $addr_pat:pat $(if $addr_guard:expr)? => $body:expr) => {
        if let $crate::disasm::v3::lir::Expression::Addressable($addr_pat) = $expr {
            if true $(&& $addr_guard)? {
                $body
            }
        }
    };
    ($expr: expr, binary $op_pat2:path { $lhs_pat:pat, $rhs_pat:pat } $(if $binary_guard:expr)? => $body_binary:expr) => {
        if let $crate::disasm::v3::lir::Expression::Binary {
            op: $op_pat2,
            lhs: $lhs_pat,
            rhs: $rhs_pat,
        } = $expr
        {
            if true $(&& $binary_guard)? {
                $body_binary
            }
        }
    };
    ($expr: expr, unary $op_pat:path { $arg_pat:pat } $(if $unary_guard:expr)? => $body_unary:expr) => {
        if let $crate::disasm::v3::lir::Expression::Unary {
            op: $op_pat,
            arg: $arg_pat,
        } = $expr
        {
            if true $(&& $unary_guard)? {
                $body_unary
            }
        }
    };
}
