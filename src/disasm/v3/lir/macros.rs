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

    // must be last: any other expression is passed through. Used to pass through
    // already formed expression from outside of the macro.
    //
    ($e:expr) => { $e }
}

#[macro_export]
macro_rules! match_arm {
    ($expr_to_match:expr, _ => $default_body: expr) => {
        $default_body
    };
    ($expr_to_match:expr, $pattern:pat => { $body:expr }, $($tail:tt)*) => {
        if let $pattern = $expr_to_match {
            $body
        } else { $crate::match_arm!($expr_to_match, $($tail)*) }
    };
}

#[macro_export]
macro_rules! match_expr {
        ($expr_to_match:expr, {
            $($pats:tt)*
            // $( $pattern:pat => $body:expr ),*
        }) => {
            $crate::match_arm!($expr_to_match, $($pats)*);
        }
    }

/*
        $( const $val_pat:pat $(if $guard_const:expr)? => $body_const:expr, )*
        $( addr $addr_pat:pat $(if $guard_addr:expr)? => $body_addr:expr, )*
        $( unary $op_pat:path, $arg_pat:pat $(if $guard_unary:expr)? => $body_unary:expr, )*
        $( binary $op_pat2:path, $lhs_pat:pat, $rhs_pat:pat $(if $guard_binary:expr)? => $body_binary:expr, )*
        $( _ => $default_body:expr )?
       ) => {
           $(
               if let $crate::disasm::v3::lir::Expression::Constant($val_pat) = $expr_to_match {
                   $(if $guard_const)? {
                       $body_const
                   } else {
                       continue;
                   }
               }
           )*
           $(
               if let $crate::disasm::v3::lir::Expression::Addressable($addr_pat) = $expr_to_match {
                   $(if $guard_addr)? {
                       $body_addr
                   } else {
                       continue;
                   }
               }
           )*
           $(
               if let $crate::disasm::v3::lir::Expression::Unary { op: $op_pat, arg: $arg_pat } = $expr_to_match {
                   $(if $guard_unary)? {
                       $body_unary
                   } else {
                       continue;
                   }
               }
           )*
           $(
               if let $crate::disasm::v3::lir::Expression::Binary { op: $op_pat, lhs: $lhs_pat, rhs: $rhs_pat } = $expr_to_match {
                   $(if $guard_binary)? {
                       $body_binary
                   } else {
                       continue;
                   }
               }
           )*
           $(
               { $default_body }
           )?
       };
    }
}
*/
