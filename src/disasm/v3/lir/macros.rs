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
