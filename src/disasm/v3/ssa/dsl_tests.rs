#[cfg(test)]
mod tests {

    use crate::disasm::v3::lir::Expression;
    use crate::disasm::v3::{common::formatting::ContextualPrettyPrint, lir::InstructionNode};
    use crate::disasm::v3::{FunctionId, InstructionId};
    use model_macros::{build_expr, build_instruction};

    use crate::disasm::v3::ssa::SsaMemoryReference;

    #[test]
    fn test() {
        assert_eq!(build_expr! { [R-3].5 }.nocolor(), "[R-3]_5");
        assert_eq!(build_expr! { [R+2].7 }.nocolor(), "[R+2]_7");
        assert_eq!(build_expr! { [155].7 }.nocolor(), "[155]_7");
        assert_eq!(build_expr! { [155].7 }.nocolor(), "[155]_7");
        assert_eq!(build_expr! { [155].7 }.nocolor(), "[155]_7");
        assert_eq!(
            build_expr! { [R+2].7 + [R-3].5 }.nocolor(),
            "[R+2]_7 + [R-3]_5"
        );
        assert_eq!(
            build_expr! { [R+2].3 - [R+3].0 }.nocolor(),
            "[R+2]_3 - [R+3]_0"
        );
        assert_eq!(
            build_expr! { [R+2].7 + [R-3].5 }.nocolor(),
            "[R+2]_7 + [R-3]_5"
        );
        assert_eq!(
            build_expr! { [R+1].3 * [R-2].2 }.nocolor(),
            "[R+1]_3 * [R-2]_2"
        );
        assert_eq!(
            build_expr! { [R+1].3 + [354].7 * [R-2].7 }.nocolor(),
            "[R+1]_3 + [354]_7 * [R-2]_7"
        );
        assert_eq!(
            build_expr! { ([R+1].3 + [R+1].5) * [R-2].7 }.nocolor(),
            "([R+1]_3 + [R+1]_5) * [R-2]_7"
        );
        assert_eq!(
            build_expr! { [R+1].3 * ([R+1].5 + [R-2].7) }.nocolor(),
            "[R+1]_3 * ([R+1]_5 + [R-2]_7)"
        );
        assert_eq!(
            build_expr! { [R+1].3 * ([R+1].5 + [R-2].7) - [123].1 }.nocolor(),
            "[R+1]_3 * ([R+1]_5 + [R-2]_7) - [123]_1"
        );
        assert_eq!(
            build_expr! { [R+1].3 * ([R+1].5 + [R-2].7) - [123].1 * [R+4].9 }.nocolor(),
            "[R+1]_3 * ([R+1]_5 + [R-2]_7) - [123]_1 * [R+4]_9"
        );
        assert_eq!(
            build_expr! { ([R+1].3 * ([R+1].5 + [R-2].7) - [123].1) * [R+4].9 }.nocolor(),
            "([R+1]_3 * ([R+1]_5 + [R-2]_7) - [123]_1) * [R+4]_9"
        );
        let expr: Expression<SsaMemoryReference> = build_expr! { 123 };
        assert_eq!(expr.nocolor(), "123");
        let expr: Expression<SsaMemoryReference> = build_expr! { 123 + 456 };
        assert_eq!(expr.nocolor(), "123 + 456");
        let expr: Expression<SsaMemoryReference> = build_expr! { 123 * 456 };
        assert_eq!(expr.nocolor(), "123 * 456");
        let expr: Expression<SsaMemoryReference> = build_expr! { 123 * (456 + 789) };
        assert_eq!(expr.nocolor(), "123 * (456 + 789)");
        let expr: Expression<SsaMemoryReference> = build_expr! { (123 + 456) * 789 };
        assert_eq!(expr.nocolor(), "(123 + 456) * 789");
        assert_eq!(
            build_expr! { [R+1].3 * (123 + [R-2].7) }.nocolor(),
            "[R+1]_3 * (123 + [R-2]_7)"
        );
        assert_eq!(
            build_expr! { ([R+1].3 + 123) * [R-2].7 }.nocolor(),
            "([R+1]_3 + 123) * [R-2]_7" // Assuming . pretty print
        );

        // Deref tests
        let expr_deref_const: Expression<SsaMemoryReference> = build_expr! { *(123) };
        assert_eq!(expr_deref_const.nocolor(), "*(123)");

        let expr_deref_mem: Expression<SsaMemoryReference> = build_expr! { *([R+5].1) };
        assert_eq!(expr_deref_mem.nocolor(), "*([R+5]_1)"); // Assuming . pretty print

        let expr_deref_expr: Expression<SsaMemoryReference> = build_expr! { *([R+1].3 + 123) };
        assert_eq!(expr_deref_expr.nocolor(), "*([R+1]_3 + 123)"); // Assuming . pretty print

        assert_eq!(
            build_expr! { *([R+1].3) + 123 }.nocolor(),
            "*([R+1]_3) + 123"
        );

        assert_eq!(
            build_expr! { 5 * *([R+1].3 + [R-2].2) }.nocolor(),
            "5 * *(([R+1]_3 + [R-2]_2))"
        );
    }

    #[test]
    fn test_assigmment() {
        assert_eq!(
            build_instruction! { [R+1].3 = 123 }.nocolor(),
            "[R+1]_3 = 123"
        );
        assert_eq!(
            build_instruction! { [R+2].5 = [R+3].7 }.nocolor(),
            "[R+2]_5 = [R+3]_7"
        );
        assert_eq!(
            build_instruction! { [R+4].9 = [R+5].1 + 456 }.nocolor(),
            "[R+4]_9 = [R+5]_1 + 456"
        );
        assert_eq!(
            build_instruction! { [R+6].2 = [R+7].4 * 789 }.nocolor(),
            "[R+6]_2 = [R+7]_4 * 789"
        );
        assert_eq!(
            build_instruction! { [R+8].6 = *([R+9].8 + 101) }.nocolor(),
            "[R+8]_6 = *([R+9]_8 + 101)"
        );
        assert_eq!(
            build_instruction! { [R+10].0 = *([R+11].2) + 112 }.nocolor(),
            "[R+10]_0 = *([R+11]_2) + 112"
        );
        assert_eq!(
            build_instruction! { [R+12].4 = 123 + *([R+13].6) }.nocolor(),
            "[R+12]_4 = 123 + *([R+13]_6)"
        );
        assert_eq!(
            build_instruction! { [R+14].8 = *(*([R+15].0)) }.nocolor(),
            "[R+14]_8 = *(*([R+15]_0))"
        );
    }
}
