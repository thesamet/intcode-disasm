#[cfg(test)]
mod tests {

    use disasm::disasm::v3::lir::Expression;
    use disasm::disasm::v3::{common::formatting::ContextualPrettyPrint, lir::InstructionNode};

    use disasm::macros::{build_expr, build_instruction, match_dsl};

    use disasm::disasm::v3::ssa::SsaMemoryReference;

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

    #[test]
    fn test_output_instruction() {
        assert_eq!(
            (build_instruction! { output 123 } as InstructionNode<SsaMemoryReference>).nocolor(),
            "output 123"
        );
        assert_eq!(
            build_instruction! { output [R+1].5 }.nocolor(),
            "output [R+1]_5"
        );
        assert_eq!(
            build_instruction! { output ([R+2].3 + 45) }.nocolor(),
            "output [R+2]_3 + 45"
        );
        assert_eq!(
            build_instruction! { output *([R+7].0 - [R-1].2) }.nocolor(),
            "output *([R+7]_0 - [R-1]_2)"
        );
    }

    #[test]
    fn mix_external_expressions() {
        let expr: Expression<SsaMemoryReference> = build_expr! { [R+1].3 + 123 };
        let complex_expr = build_expr! { (3 + #expr) * [R-1].7 };
        assert_eq!(complex_expr.nocolor(), "(3 + [R+1]_3 + 123) * [R-1]_7");
        let expr: Expression<SsaMemoryReference> = build_expr! { [R+1].3 + 123 };
        let use_expr = build_instruction! { [R+2].5 = 7 * #expr };
        assert_eq!(use_expr.nocolor(), "[R+2]_5 = 7 * ([R+1]_3 + 123)");
    }

    #[test]
    fn test_unary_expressions() {
        let expr_neg_const: Expression<SsaMemoryReference> = build_expr! { -123 };
        assert_eq!(expr_neg_const.nocolor(), "-123");

        let expr_not_const: Expression<SsaMemoryReference> = build_expr! { !123 };
        assert_eq!(expr_not_const.nocolor(), "!123");

        let expr_neg_mem: Expression<SsaMemoryReference> = build_expr! { -[R+1].5 };
        assert_eq!(expr_neg_mem.nocolor(), "-[R+1]_5");

        let expr_not_mem: Expression<SsaMemoryReference> = build_expr! { ![R+1].5 };
        assert_eq!(expr_not_mem.nocolor(), "![R+1]_5");

        let expr_neg_paren: Expression<SsaMemoryReference> = build_expr! { -(123 + [R+1].5) };
        assert_eq!(expr_neg_paren.nocolor(), "-(123 + [R+1]_5)");

        let expr_not_paren: Expression<SsaMemoryReference> = build_expr! { !(123 + [R+1].5) };
        assert_eq!(expr_not_paren.nocolor(), "!(123 + [R+1]_5)");

        assert_eq!(
            build_expr! { -([R+1].3 + 123) * [R-2].7 }.nocolor(),
            "-([R+1]_3 + 123) * [R-2]_7"
        );

        assert_eq!(
            build_expr! { ![R+1].3 + 123 }.nocolor(), // Precedence: (!([R+1].3)) + 123
            "![R+1]_3 + 123"
        );

        let expr: Expression<SsaMemoryReference> = build_expr! { -5 * 10 }; // Precedence: (-5) * 10
        assert_eq!(expr.nocolor(), "-5 * 10");

        let expr: Expression<SsaMemoryReference> = build_expr! { 5 * -10 }; // Precedence: 5 * (-10)
        assert_eq!(expr.nocolor(), "5 * -10");

        let expr: Expression<SsaMemoryReference> = build_expr! { --5 };
        assert_eq!(expr.nocolor(), "--5");
        let expr: Expression<SsaMemoryReference> = build_expr! { !!5 };
        assert_eq!(expr.nocolor(), "!!5");
        let expr: Expression<SsaMemoryReference> = build_expr! { -!5 };
        assert_eq!(expr.nocolor(), "-!5");
    }

    #[test]
    fn test_deref() {
        let expr_deref_const: Expression<SsaMemoryReference> = build_expr! { *(123) };
        assert_eq!(expr_deref_const.nocolor(), "*(123)");
        let expr_deref_mem: Expression<SsaMemoryReference> = build_expr! { *([R+5].1) };
        assert_eq!(expr_deref_mem.nocolor(), "*([R+5]_1)");

        let expr_deref_expr: Expression<SsaMemoryReference> = build_expr! { *([R+1].3 + 123) };
        assert_eq!(expr_deref_expr.nocolor(), "*([R+1]_3 + 123)");

        let expr_deref_expr_mem: Expression<SsaMemoryReference> =
            build_expr! { *([R+1].3 + [R-2].2) };
        assert_eq!(expr_deref_expr_mem.nocolor(), "*([R+1]_3 + [R-2]_2)");

        assert_eq!(
            build_expr! { *([R+1].3) + 123 }.nocolor(),
            "*([R+1]_3) + 123"
        );

        assert_eq!(
            build_expr! { 5 * *([R+1].3 + [R-2].2) }.nocolor(),
            "5 * *(([R+1]_3 + [R-2]_2))"
        );

        // Deref address expressions
        let expr_deref_addr_const: Expression<SsaMemoryReference> =
            build_expr! { *([R+1].0 + 123) };
        assert_eq!(expr_deref_addr_const.nocolor(), "*([R+1]_0 + 123)");

        let expr_deref_addr_addr: Expression<SsaMemoryReference> =
            build_expr! { *([R+1].0 + [R+2].0) };
        assert_eq!(expr_deref_addr_addr.nocolor(), "*([R+1]_0 + [R+2]_0)");
    }

    #[test]
    fn test_match_dsl_basic_patterns() {
        // Test basic patterns
        let reg = build_expr! { [R-3].5 };
        let num: Expression<SsaMemoryReference> = build_expr! { 123 };
        assert_eq!(
            match_dsl!(&reg,
                _ => 4
            ),
            4
        );

        assert_eq!(
            match_dsl!(&num,
                123 => 123,
                _ => 4,
            ),
            123,
        );

        assert_eq!(
            match_dsl!(&reg,
                123 => 123,
                _ => 4,
            ),
            4,
        );

        assert_eq!(
            match_dsl!(&reg,
                [R-3].5 => 26664,
                _ => 4,
            ),
            26664,
        );

        let deref = build_expr! { *([R+7].0) };

        assert_eq!(
            match_dsl!(&deref,
                *([R+7].0) => 51117,
                _ => 14,
            ),
            51117
        );

        assert_eq!(
            match_dsl!(&deref,
                *([R+7].1) => 51117,
                _ => 14,
            ),
            14
        );
    }

    #[test]
    fn test_match_dsl_bindings() {
        // Test binding a constant
        let const_expr: Expression<SsaMemoryReference> = build_expr! { 35549 };
        let result_const = match_dsl!(&const_expr,
            $a:const => {
                // Assert the bound value is correct
                assert_eq!(a, 35549);
                1 // Return a value to indicate success
            },
            _ => {
                // Should not reach here
                assert!(false, "Did not match constant pattern");
                0
            }
        );
        assert_eq!(result_const, 1);

        // Test binding a memory reference (address)
        let addr_expr: Expression<SsaMemoryReference> = build_expr! { [R+5].10 };
        let result = match_dsl!(&addr_expr,
            $b:addr => {
                // Assert the bound value is correct
                b.nocolor()
            },
            _ => {
                panic!("Did not match address pattern");
            }
        );
        assert_eq!(result, "[R+5]_10");

        // Test binding a generic expression
        let generic_expr: Expression<SsaMemoryReference> = build_expr! { 123 + 456 };
        let result_expr_str = match_dsl!(&generic_expr,
            $c:expr => {
                c.nocolor() // Return String
            },
            _ => {
                panic!("Did not match $c:expr pattern");
            }
        );
        assert_eq!(result_expr_str, "123 + 456");

        // Test a pattern that should *not* match and fall through
        // The pattern [R+1].$a:const is removed as it's not supported.
        // We test a literal pattern that won't match.
        let wrong_mem_ref_expr: Expression<SsaMemoryReference> = build_expr! { [R+2].10 };
        let result_no_match = match_dsl!(&wrong_mem_ref_expr,
            [R+1].5 => { // Literal pattern that won't match wrong_mem_ref_expr
                panic!("Matched [R+1].5 pattern unexpectedly");
            },
            _ => {
                5i128 // This should match and return
            }
        );
        assert_eq!(result_no_match, 5i128);

        // Test binding a constant value
        let const_expr: Expression<SsaMemoryReference> = build_expr! { 456 };
        let result_bind_const = match_dsl!(&const_expr,
            $x:const => {
                x // Return the bound i128 value
            },
            _ => {
                panic!("Did not match $x:const pattern");
            }
        );
        assert_eq!(result_bind_const, 456i128);

        // Test binding an addressable value (SsaMemoryReference)
        let addr_expr: Expression<SsaMemoryReference> = build_expr! { [R-2].0 };
        let result_bind_addr_str = match_dsl!(&addr_expr,
            $x:addr => { // $x is SsaMemoryReference
                x.nocolor() // Assuming SsaMemoryReference implements nocolor()
            },
            _ => {
                panic!("Did not match $x:addr pattern");
            }
        );
        assert_eq!(result_bind_addr_str, "[R-2]_0");

        // Test binding a generic expression (already covered, but good to have explicitly)
        let another_generic_expr: Expression<SsaMemoryReference> = build_expr! { [R+1].3 + 5 };
        let result_bind_generic_str = match_dsl!(&another_generic_expr,
            $x:expr => { // $x is Expression<SsaMemoryReference>
                x.nocolor()
            },
            _ => {
                panic!("Did not match $x:expr pattern");
            }
        );
        assert_eq!(result_bind_generic_str, "[R+1]_3 + 5");
        // Test binding in a binary expression
        /*
        let binary_expr: Expression<SsaMemoryReference> = build_expr! { 10 + [R+2].5 };
        let (a, b) = match_dsl!(&binary_expr,
             $a:const + $b:addr => {
                 // Construct a string or tuple to return multiple values for assertion
                 (a, b.nocolor())
             },
             _ => {
                 panic!("Did not match $a:const + $b:addr pattern");
             }
        );
        assert_eq!(result_binary_binding_str, "const:10, addr:[R+2]_5");
        */

        /*
        // Test binding in a unary expression
        let unary_expr: Expression<SsaMemoryReference> = build_expr! { -100 };
        let result_unary_binding_val = match_dsl!(&unary_expr,
            -$a:const => {
                 a // Return the bound constant
             },
            _ => {
                 panic!("Did not match -$a:const pattern");
            }
        );
        assert_eq!(result_unary_binding_val, 100i128);

        // Test binding in a deref expression
        let deref_expr: Expression<SsaMemoryReference> = build_expr! { *([R+3].8 + 20) };
        let result_deref_binding_str = match_dsl!(&deref_expr,
            *($a:expr) => {
                 a.nocolor() // Return the nocolor string of the bound expression
             },
            _ => {
                 panic!("Did not match *($a:expr) pattern");
            }
        );
        assert_eq!(result_deref_binding_str, "[R+3]_8 + 20");
        //
        // Test binding in a deref expression
        let deref_expr: Expression<SsaMemoryReference> = build_expr! { *([R+3].8 + 20) };
        let result_deref_binding_str = match_dsl!(&deref_expr,
            *([R+3].8 + $a:const) => {
                 a
             },
            _ => {
                 panic!("Did not match *($a:expr) pattern");
            }
        );
        assert_eq!(a, 20);
        */
    }

    /*
    #[test]
    fn test_match_dsl_operators() {
        // Test patterns with operators
        let match_input = match_dsl! {
            $a:const + $b:const => {}
        };
        assert_eq!(match_input.nocolor(), "$a:const + $b:const => { ... }");

        let match_input = match_dsl! {
            $c:expr * 123 => {}
        };
        assert_eq!(match_input.nocolor(), "$c:expr * 123 => { ... }");

        let match_input = match_dsl! {
            ([R+2].3 - $d:expr) + $_ => {}
        };
        // Assuming parenthesis are preserved when necessary based on precedence
        assert_eq!(match_input.nocolor(), "([R+2]_3 - $d:expr) + $_ => { ... }");

        let match_input = match_dsl! {
            - $a:const => {}
        };
        assert_eq!(match_input.nocolor(), "-$a:const => { ... }");

        let match_input = match_dsl! {
            ! $b:expr => {}
        };
        assert_eq!(match_input.nocolor(), "!$b:expr => { ... }");

        let match_input = match_dsl! {
            * ($c:expr + 10) => {}
        };
        assert_eq!(match_input.nocolor(), "*($c:expr + 10) => { ... }");

        let match_input = match_dsl! {
           $a:const + - $b:const => {}
        };
        assert_eq!(match_input.nocolor(), "$a:const + -$b:const => { ... }");
    }

    #[test]
    fn test_match_dsl_multiple_arms() {
        // Test multiple arms
        let match_input = match_dsl! {
            123 => {},
            [R+2].7 => {},
            _ => {}
        };
        // Assuming arms are separated by comma and space in pretty print
        assert_eq!(
            match_input.nocolor(),
            "123 => { ... }, [R+2]_7 => { ... }, _ => { ... }"
        );

        let match_input = match_dsl! {
            $a:const + $b:const => {},
            [R+1].$c:const => {},
            *($_ + 5) => {}
        };
        assert_eq!(
            match_input.nocolor(),
            "$a:const + $b:const => { ... }, [R+1]_$c:const => { ... }, *($_ + 5) => { ... }"
        );
    }

    #[test]
    fn test_match_dsl_complex_patterns() {
        // Test more complex nested patterns
        let match_input = match_dsl! {
            *($a:expr + 123) * ![R+1].$b:const => {}
        };
        assert_eq!(
            match_input.nocolor(),
            "*($a:expr + 123) * ![R+1]_$b:const => { ... }"
        );

        let match_input = match_dsl! {
            ([R+5].$a:const - $_:addr) + *($b:expr * [R-2].7) => {}
        };
        assert_eq!(
            match_input.nocolor(),
            "([R+5]_$a:const - $_:addr) + *($b:expr * [R-2]_7) => { ... }"
        );
    }
    */
}
