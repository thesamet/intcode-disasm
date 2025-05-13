#[cfg(test)]
mod tests {

    use crate::disasm::{
        test_utils::TestContextBuilder,
        v3::{common::formatting::ContextualPrettyPrint, model::FoldedSsaComplete},
    };

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
        let inst = &ctx
            .main_function()
            .block(&ctx.main_function().entry_block())
            .folded_ssa()
            .instructions[0];
        assert_eq!(inst.nocolor(), "[R-1]_3 = ([R-2]_0 * 5 + 7) * [R-3]_0");
    }
}
