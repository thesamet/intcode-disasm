#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::disasm::{
        test_utils::TestContextBuilder,
        v3::{model::FoldedSsaComplete, pretty_print::pretty_print_folded_ssa},
    };

    // Helper macro for creating versioned memory references, similar to ssa/tests.rs
    macro_rules! vmr {
        ($name:ident, $version:expr) => {
            SsaMemoryReference::versioned(stringify!($name), $version)
        };
        ($name:ident) => {
            SsaMemoryReference::versioned(stringify!($name), 0)
        };
    }

    // Helper macro for creating expressions from versioned memory references
    macro_rules! expr_vmr {
        ($name:ident, $version:expr) => {
            Expression::Addressable(vmr!($name, $version))
        };
        ($name:ident) => {
            Expression::Addressable(vmr!($name))
        };
    }

    #[test]
    fn test_placeholder_folded_ssa() {
        let ctx = FoldedSsaComplete::test_context(
            r#"
            R += 4
            [R-1] = [R-2] * 5
            [R-1] = [R-1] + 7
            [R-1] = [R-1] * [R-3]
            halt
            "#,
        )
        .unwrap();
        println!("{}", pretty_print_folded_ssa(&ctx.model));
        assert!(false);
    }
}
