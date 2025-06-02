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
    fn test_binary_comparison_operators() {
        // Test patterns with binary comparison operators
        let expr: Expression<SsaMemoryReference> = build_expr! { 33 == 45 };
        assert_eq!(expr.nocolor(), "33 == 45");

        let expr: Expression<SsaMemoryReference> = build_expr! { 33 != 45 };
        assert_eq!(expr.nocolor(), "33 != 45");

        let expr: Expression<SsaMemoryReference> = build_expr! { 33 > 45 };
        assert_eq!(expr.nocolor(), "33 > 45");

        let expr: Expression<SsaMemoryReference> = build_expr! { 33 < 45 };
        assert_eq!(expr.nocolor(), "33 < 45");

        let expr: Expression<SsaMemoryReference> = build_expr! { 33 >= 45 };
        assert_eq!(expr.nocolor(), "33 >= 45");

        let expr: Expression<SsaMemoryReference> = build_expr! { 33 <= 45 };
        assert_eq!(expr.nocolor(), "33 <= 45");
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
        let num: Expression<SsaMemoryReference> = build_expr! { 12376 };
        assert_eq!(
            match_dsl!(&reg,
                _ => 4
            ),
            4
        );

        assert_eq!(
            match_dsl!(&num,
                15 => 17,
                12376 => 99,
                _ => 4,
            ),
            99,
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

        assert_eq!(
            match_dsl!(&build_expr!(*([145].7)),
                *([145].7) => 51131,
                _ => 14,
            ),
            51131
        );
    }

    #[test]
    fn test_match_dsl_bindings() {
        // Test binding a constant
        let const_expr: Expression<SsaMemoryReference> = build_expr! { 35549 };
        let result_const = match_dsl!(&const_expr,
            $a:const => {
                // Assert the bound value is correct
                assert_eq!(*a, 35549);
                1 // Return a value to indicate success
            },
            _ => {
                // Should not reach here
                unreachable!()
            }
        );
        assert_eq!(result_const, 1);

        let result_const = match_dsl!(build_expr!(31275),
            $a:const => {
                *a + 10
            },
            _ => {
                0
            }
        );
        assert_eq!(result_const, 31285);

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
                x // Return the bound &i128 value
            },
            _ => {
                panic!("Did not match $x:const pattern");
            }
        );
        assert_eq!(*result_bind_const, 456i128);

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
        assert_eq!(*a, 10);
        assert_eq!(b, "[R+2]_5");

        // Test binding in a unary expression
        let unary_expr: Expression<SsaMemoryReference> = build_expr! { -100 };
        let result_unary_binding_val = match_dsl!(&unary_expr,
            -$a:const => {
                 a // Return the bound &i128 constant
             },
            _ => {
                 panic!("Did not match -$a:const pattern");
            }
        );
        assert_eq!(*result_unary_binding_val, 100i128);

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

        // Test binding in a deref expression
        let deref_expr: Expression<SsaMemoryReference> = build_expr! { *([R+3].8 + 20) };
        let a_bind = match_dsl!(&deref_expr,
            *([R+3].8 + $a:const) => {
                 a
             },
            _ => {
                 panic!("Did not match *($a:expr) pattern");
            }
        );
        assert_eq!(*a_bind, 20);
    }

    #[test]
    fn test_match_dsl_operators() {
        // Test patterns with operators
        let match_input = match_dsl!(build_expr!(33 + 45),
            $a:const + $b:const => (*a, *b),
            _ => panic!("no match")
        );
        assert_eq!(match_input, (33, 45));

        let expr = build_expr! { [R+2].3 * 123 };
        let match_input = match_dsl!(&expr,
            $c:expr * 123 => c.nocolor(),
            _ =>  panic!("no match"),
        );
        assert_eq!(match_input, "[R+2]_3");

        let expr = build_expr! { ([R+2].3 - [R+3].5) + [R+4].7 };
        let match_input = match_dsl!(&expr,
            ([R+2].3 - $d:expr) + _ => d.nocolor(),
            _ =>  panic!("no match"),
        );
        // Assuming parenthesis are preserved when necessary based on precedence
        assert_eq!(match_input, "[R+3]_5");

        let expr = build_expr! { -123 };
        let match_input = match_dsl!(&expr,
            - $a:const => *a,
            _ =>  panic!("no match"),
        );
        assert_eq!(match_input, 123);

        let expr = build_expr! { ![R+3].5 };
        let match_input = match_dsl!(&expr,
            ! $b:expr => b.nocolor(),
            _ =>  panic!("no match"),
        );
        assert_eq!(match_input, "[R+3]_5");

        let expr = build_expr! { *([R+2].3 + 10) };
        let match_input = match_dsl!(&expr,
            * ($c:expr) => c.nocolor(),
            _ =>  panic!("no match"),
        );
        assert_eq!(match_input, "[R+2]_3 + 10");

        let expr = build_expr! { 32 + -15 };
        let match_input = match_dsl!(&expr,
           $a:const + -$b:const => (*a, *b),
           _ =>  panic!("no match"),
        );
        assert_eq!(match_input, (32, 15));
    }

    #[test]
    fn test_match_dsl_binary_comparison_operators() {
        // Test patterns with binary comparison operators
        let expr = build_expr! { 33 == 45 };
        let match_input = match_dsl!(&expr,
            $a:const == $b:const => (*a, *b),
            _ => panic!("no match")
        );
        assert_eq!(match_input, (33, 45));

        let expr = build_expr! { 33 != 45 };
        let match_input = match_dsl!(&expr,
            $a:const != $b:const => (*a, *b),
            _ => panic!("no match")
        );
        assert_eq!(match_input, (33, 45));

        let expr = build_expr! { 33 > 45 };
        let match_input = match_dsl!(&expr,
            $a:const > $b:const => (*a, *b),
            _ => panic!("no match")
        );
        assert_eq!(match_input, (33, 45));

        let expr = build_expr! { 33 < 45 };
        let match_input = match_dsl!(&expr,
            $a:const < $b:const => (*a, *b),
            _ => panic!("no match")
        );
        assert_eq!(match_input, (33, 45));

        let expr = build_expr! { 33 >= 45 };
        let match_input = match_dsl!(&expr,
            $a:const >= $b:const => (*a, *b),
            _ => panic!("no match")
        );
        assert_eq!(match_input, (33, 45));

        let expr = build_expr! { 33 <= 45 };
        let match_input = match_dsl!(&expr,
            $a:const <= $b:const => (*a, *b),
            _ => panic!("no match")
        );
        assert_eq!(match_input, (33, 45));
    }

    #[test]
    fn test_match_dsl_binary_comparison_operators_complex() {
        // Test patterns with binary comparison operators and more complex expressions
        let expr = build_expr! { [R+1].3 + 5 == 10 };
        let match_input = match_dsl!(&expr,
            $a:expr == $b:const => (a.nocolor(), *b),
            _ => panic!("no match")
        );
        assert_eq!(match_input, ("[R+1]_3 + 5".to_string(), 10));

        let expr = build_expr! { 33 != [R+2].7 * 2 };
        let match_input = match_dsl!(&expr,
            $a:const != $b:expr => (*a, b.nocolor()),
            _ => panic!("no match")
        );
        assert_eq!(match_input, (33, "[R+2]_7 * 2".to_string()));

        let expr = build_expr! { [R+3].0 > 45 - 10 };
        let match_input = match_dsl!(&expr,
            $a:addr > $b:expr => (a.nocolor(), b.nocolor()),
            _ => panic!("no match")
        );
        assert_eq!(match_input, ("[R+3]_0".to_string(), "45 - 10".to_string()));

        let expr = build_expr! { 33 < [R+4].2 + 1 };
        let match_input = match_dsl!(&expr,
            $a:const < $b:expr => (*a, b.nocolor()),
            _ => panic!("no match")
        );
        assert_eq!(match_input, (33, "[R+4]_2 + 1".to_string()));

        let expr = build_expr! { [R+5].4 >= 45 * 3 };
        let match_input = match_dsl!(&expr,
            $a:expr >= $b:expr => (a.nocolor(), b.nocolor()),
            _ => panic!("no match")
        );
        assert_eq!(match_input, ("[R+5]_4".to_string(), "45 * 3".to_string()));

        let expr = build_expr! { 33 * 2 <= [R+6].6 };
        let match_input = match_dsl!(&expr,
            $a:expr <= $b:addr => (a.nocolor(), b.nocolor()),
            _ => panic!("no match")
        );
        assert_eq!(match_input, ("33 * 2".to_string(), "[R+6]_6".to_string()));

        let expr = build_expr! { *([R+1].1 + *([R+2].2)) > 100 - 50 };
        let match_input = match_dsl!(&expr,
            *($a:expr + *($b:addr)) > $c:expr => (a.nocolor(), b.nocolor(), c.nocolor()),
            _ => panic!("no match")
        );
        assert_eq!(
            match_input,
            (
                "[R+1]_1".to_string(),
                "[R+2]_2".to_string(),
                "100 - 50".to_string()
            )
        );

        let expr = build_expr! { !([R+3].3 * 5) <= -([R+4].4 + 10) };
        let match_input = match_dsl!(&expr,
            !($a:expr * $b:const) <= -($c:addr + $d:const) => (a.nocolor(), *b, c.nocolor(), *d),
            _ => panic!("no match")
        );
        assert_eq!(
            match_input,
            ("[R+3]_3".to_string(), 5, "[R+4]_4".to_string(), 10)
        );

        let expr = build_expr! { 10 + *([R+5].5 - 7) == [R+6].6 };
        let match_input = match_dsl!(&expr,
            10 + *($a:addr - $b:const) == $c:addr => (a.nocolor(), *b, c.nocolor()),
            _ => panic!("no match")
        );
        assert_eq!(
            match_input,
            ("[R+5]_5".to_string(), 7, "[R+6]_6".to_string())
        );

        let expr = build_expr! {*([R+7].7 + !([R+8].8)) >= 5 * ([R+9].9 - 2)};
        let match_input = match_dsl!(&expr,
            *($a:addr + !($b:addr)) >= 5 * ($c:addr - $d:const) => (a.nocolor(), b.nocolor(), c.nocolor(), *d),
            _ => panic!("no match")
        );
        assert_eq!(
            match_input,
            (
                "[R+7]_7".to_string(),
                "[R+8]_8".to_string(),
                "[R+9]_9".to_string(),
                2
            )
        );

        let expr = build_expr! { -*([R+10].10) < 15 + !([R+11].11 * 3) };
        let match_input = match_dsl!(&expr,
            -*($a:addr) < 15 + !($b:addr * $c:const) => (a.nocolor(), b.nocolor(), *c),
            _ => panic!("no match")
        );
        assert_eq!(
            match_input,
            ("[R+10]_10".to_string(), "[R+11]_11".to_string(), 3)
        );
    }

    #[test]
    fn test_match_dsl_multiple_arms() {
        // Test multiple arms
        let expr = build_expr! { 123 };
        let match_input = match_dsl!(&expr,
            123 => 1,
            [R+2].7 => 2,
            _ => 3,
        );
        assert_eq!(match_input, 1);

        let expr = build_expr! { 10 + 20 };
        let match_input = match_dsl!(&expr,
            [R+1].17 => 1,
            $a:const + $b:const => a+b,
            *(_ + 5) => 3,
            _ => 4,
        );
        assert_eq!(match_input, 30);
    }

    #[test]
    fn test_match_dsl_complex_patterns() {
        // Test more complex nested patterns
        let expr = build_expr! { *([R+2].3 + 123) * ![R+1].5 };
        let match_input = match_dsl!(&expr,
            *($a:expr + 123) * !$b => (a.nocolor(), b.nocolor()),
            _ => panic!("no match"),
        );
        assert_eq!(match_input, ("[R+2]_3".to_string(), "[R+1]_5".to_string()));

        let expr = build_expr! { ([R+5].8 - [R+6].0) + *([R+7].2 * [R-2].7) };
        let match_input = match_dsl!(&expr,
            ($a - _) + *($b:expr * [R-2].7) => (a.nocolor(), b.nocolor()),
            _ => panic!("no match"),
        );
        assert_eq!(match_input, ("[R+5]_8".to_string(), "[R+7]_2".to_string()));
    }

    #[test]
    fn test_pointer_syntax() {
        // Basic pointer syntax
        let ptr_expr = build_expr! { [P 123].8 };
        assert_eq!(ptr_expr.nocolor(), "[P123]_8");

        // Pointer in complex expressions
        let complex_expr = build_expr! { [P 123].8 + [R+5].3 };
        assert_eq!(complex_expr.nocolor(), "[P123]_8 + [R+5]_3");

        // Multiple pointers in expressions
        let multi_ptr_expr = build_expr! { [P 123].8 + [P 456].9 };
        assert_eq!(multi_ptr_expr.nocolor(), "[P123]_8 + [P456]_9");

        // Pointer with arithmetic operations
        let ptr_arith_expr = build_expr! { [P 123].8 * 4 };
        assert_eq!(ptr_arith_expr.nocolor(), "[P123]_8 * 4");

        // Pointer with comparison operations
        let ptr_cmp_expr = build_expr! { [P 123].8 == [P 456].9 };
        assert_eq!(ptr_cmp_expr.nocolor(), "[P123]_8 == [P456]_9");

        // Pointer with unary operations
        let ptr_unary_expr = build_expr! { -[P 123].8 };
        assert_eq!(ptr_unary_expr.nocolor(), "-[P123]_8");

        // Dereferencing pointers
        let deref_expr = build_expr! { *([P 123].8) };
        assert_eq!(deref_expr.nocolor(), "*([P123]_8)");

        // Nested dereferencing of pointers
        let nested_deref_expr = build_expr! { *(*([P 123].8)) };
        assert_eq!(nested_deref_expr.nocolor(), "*(*([P123]_8))");

        // Dereferencing with arithmetic
        let deref_arith_expr = build_expr! { *([P 123].8) + 10 };
        assert_eq!(deref_arith_expr.nocolor(), "*([P123]_8) + 10");

        // Pointers in assignments
        let assign_instr = build_instruction! { [P 123].8 = 456 };
        assert_eq!(assign_instr.nocolor(), "[P123]_8 = 456");

        // Pointer-to-pointer assignments
        let ptr_to_ptr_assign = build_instruction! { [P 123].8 = [P 456].9 };
        assert_eq!(ptr_to_ptr_assign.nocolor(), "[P123]_8 = [P456]_9");

        // Assigning dereferenced pointer
        let deref_assign = build_instruction! { [R+1].3 = *([P 123].8) };
        assert_eq!(deref_assign.nocolor(), "[R+1]_3 = *([P123]_8)");

        // Assigning to dereferenced pointer
        let assign_to_deref = build_instruction! { *([P 123].8) = [R+1].3 };
        assert_eq!(assign_to_deref.nocolor(), "*([P123]_8) = [R+1]_3");
    }

    #[test]
    fn test_match_dsl_with_pointers() {
        // Binding pointer expressions with $p:addr
        let ptr_expr = build_expr! { [P 123].8 };

        // Use pattern binding instead of literal pattern
        let result = match_dsl!(&ptr_expr,
            $p:addr => {
                // Verify we can access the bound pointer
                assert_eq!(p.nocolor(), "[P123]_8");
                p.nocolor().to_string()
            },
            _ => "no match".to_string()
        );
        assert_eq!(result, "[P123]_8");

        // Complex expressions with pointers
        let complex_expr = build_expr! { [P 123].8 + [R+5].3 };
        let (p, r) = match_dsl!(&complex_expr,
            $p:addr + $r:addr => (p.nocolor().to_string(), r.nocolor().to_string()),
            _ => ("no match".to_string(), "no match".to_string())
        );
        assert_eq!(p, "[P123]_8");
        assert_eq!(r, "[R+5]_3");

        // Matching dereferenced pointers
        let deref_expr = build_expr! { *([P 123].8) };
        let inner_ptr = match_dsl!(&deref_expr,
            *($inner:addr) => inner.nocolor().to_string(),
            _ => "no match".to_string()
        );
        assert_eq!(inner_ptr, "[P123]_8");

        // Matching pointers in binary operations
        let binary_expr = build_expr! { [P 123].8 * 5 };
        let (ptr, val) = match_dsl!(&binary_expr,
            $ptr:addr * $val:const => (ptr.nocolor().to_string(), *val),
            _ => ("no match".to_string(), 0i128)
        );
        assert_eq!(ptr, "[P123]_8");
        assert_eq!(val, 5i128);

        // Matching pointers in comparison operations
        let cmp_expr = build_expr! { [P 123].8 == [P 456].9 };
        let (left, right) = match_dsl!(&cmp_expr,
            $left:addr == $right:addr => (left.nocolor().to_string(), right.nocolor().to_string()),
            _ => ("no match".to_string(), "no match".to_string())
        );
        assert_eq!(left, "[P123]_8");
        assert_eq!(right, "[P456]_9");

        // Matching pointers with unary operations
        let unary_expr = build_expr! { -[P 123].8 };
        let ptr = match_dsl!(&unary_expr,
            -$ptr:addr => ptr.nocolor().to_string(),
            _ => "no match".to_string()
        );
        assert_eq!(ptr, "[P123]_8");

        // Matching nested pointer expressions
        let nested_expr = build_expr! { *(*([P 123].8)) };
        let inner_ptr = match_dsl!(&nested_expr,
            *(*($ptr:addr)) => ptr.nocolor().to_string(),
            _ => "no match".to_string()
        );
        assert_eq!(inner_ptr, "[P123]_8");

        // Matching with wildcard and pointer
        let mixed_expr = build_expr! { [P 123].8 + 42 };
        let ptr = match_dsl!(&mixed_expr,
            $ptr:addr + _ => ptr.nocolor().to_string(),
            _ => "no match".to_string()
        );
        assert_eq!(ptr, "[P123]_8");
    }
}
