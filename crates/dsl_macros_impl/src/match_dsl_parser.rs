// disasm/model_macros/macro/src/match_dsl_parser.rs
use proc_macro2::{Ident, TokenStream as TokenStream2};
use syn::parse::{Parse, ParseStream, Peek};
use syn::{spanned::Spanned, Block, Expr, LitInt, Result, Token};

// Assuming these provide the correct base paths
use quote::quote; // Required for path generation in stubs

// Imports from the dsl module for pattern parsing
use crate::dsl::{parse_expr_generic, PatternExpression, PatternParseStrategy};

// Helper module for parsing tokens until a specific delimiter
mod limited_scope_parser {
    use super::*;
    use proc_macro2::TokenTree;

    // Parses tokens from the input stream until a FatArrow `=>` is encountered,
    // or the stream is empty. The FatArrow is NOT consumed.
    pub fn parse_until_fat_arrow(input: ParseStream) -> Result<TokenStream2> {
        let mut tokens = Vec::new();
        let start_span = input.span();

        while !input.is_empty() && !input.peek(Token![=>]) {
            let tt = input.parse::<TokenTree>()?;
            tokens.push(tt);
        }

        if tokens.is_empty() && !input.peek(Token![=>]) {
            // Error only if truly empty AND no arrow next
            return Err(syn::Error::new(
                start_span,
                "Expected expression or code block before '=>' or end of arm",
            ));
        }
        Ok(TokenStream2::from_iter(tokens))
    }

    // Parses tokens from the input stream until a FatArrow `=>` or an `if` keyword is encountered,
    // or the stream is empty. The delimiter is NOT consumed.
    pub fn parse_tokens_until_if_or_fat_arrow(input: ParseStream) -> Result<TokenStream2> {
        let mut tokens = Vec::new();
        let start_span = input.span();

        while !input.is_empty() && !input.peek(Token![=>]) && !input.peek(Token![if]) {
            let tt = input.parse::<TokenTree>()?;
            tokens.push(tt);
        }

        if tokens.is_empty() {
            // It's okay for a pattern to be empty if followed by `if` or `=>` immediately,
            // but the pattern parser itself should handle "empty pattern" error.
            // Here, we check if we consumed nothing AND there's no delimiter.
            if !input.peek(Token![=>]) && !input.peek(Token![if]) {
                return Err(syn::Error::new(start_span, "Expected a pattern expression"));
            }
        }
        Ok(TokenStream2::from_iter(tokens))
    }
} // Closing brace for mod limited_scope_parser was missing in diff, ensuring it's here.

// Wrapper struct to enable parsing a TokenStream2 into a PatternExpression
// using the generic parsing infrastructure from dsl.rs.
struct ParsablePatternExpression(PatternExpression);

impl Parse for ParsablePatternExpression {
    fn parse(input: ParseStream) -> Result<Self> {
        let strategy = PatternParseStrategy {}; // Use the strategy for parsing patterns
        let pattern_expr = parse_expr_generic(input, &strategy)?;
        // Ensure the entire stream was consumed by the pattern parser
        if !input.is_empty() {
            return Err(input.error("Unexpected tokens after pattern expression"));
        }
        Ok(ParsablePatternExpression(pattern_expr))
    }
}

#[derive(Debug)]
pub struct MatchArmInput {
    // pub pattern_ts: TokenStream2, // The raw TokenStream for the pattern
    pub pattern: PatternExpression, // The parsed pattern AST
    pub guard: Option<Expr>,        // Optional if condition: if $var > 10
    pub body: Block,
}

impl Parse for MatchArmInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // 1. Parse the pattern part (everything before `if` or `=>`)
        let pattern_tokens = limited_scope_parser::parse_tokens_until_if_or_fat_arrow(input)?;

        // Convert the collected pattern tokens into a PatternExpression AST node
        let parsed_wrapper: ParsablePatternExpression = syn::parse2(pattern_tokens)
            .map_err(|e| syn::Error::new(e.span(), format!("Failed to parse pattern: {}", e)))?;
        let pattern: PatternExpression = parsed_wrapper.0; // Extract the PatternExpression

        // 2. Check for an optional guard
        let guard: Option<Expr>;
        if input.peek(Token![if]) {
            let _if_token: Token![if] = input.parse()?;
            // Similar to limited_scope_parser, parse until `=>`
            let guard_tokens = limited_scope_parser::parse_until_fat_arrow(input)?;
            guard = Some(syn::parse2(guard_tokens)?);
        } else {
            guard = None;
        }

        // 3. Parse the `=>` token
        let _arrow_token: Token![=>] = input.parse()?;

        // 4. Parse the body
        let body: Block = input.parse()?;

        Ok(MatchArmInput {
            pattern,
            guard,
            body,
        })
    }
}

#[derive(Debug)]
pub struct MatchDslInput {
    pub target_expr: Expr,
    pub arms: Vec<MatchArmInput>,
}

impl Parse for MatchDslInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let target_expr: Expr = input.parse()?;
        let _comma_after_target: Token![,] = input.parse().map_err(|e| {
            syn::Error::new(
                target_expr.span(),
                format!(
                    "Expected a comma after the target expression. Original error: {}",
                    e
                ),
            )
        })?;

        let mut arms = Vec::new();
        while !input.is_empty() {
            arms.push(input.parse()?); // Parses one MatchArmInput

            if input.peek(Token![,]) {
                let _comma: Token![,] = input.parse()?;
                if input.is_empty() {
                    // Trailing comma allowed
                    break;
                }
            } else if !input.is_empty() {
                return Err(input
                    .error("Expected ',' to separate match arms or end of input after an arm."));
            }
        }

        if arms.is_empty() {
            return Err(syn::Error::new(
                target_expr.span(),
                "match_dsl! requires at least one arm",
            ));
        }

        Ok(MatchDslInput { target_expr, arms })
    }
}

impl MatchDslInput {
    pub fn expanded(&self) -> TokenStream2 {
        // For debugging Phase 1:
        // Output a textual representation of the parsed structure.
        let target_expr_code = &self.target_expr;
        let arms_count = self.arms.len();
        let mut arm_debug_strings = Vec::new();

        for (i, arm) in self.arms.iter().enumerate() {
            // Use Debug formatting for PatternExpression (PatternExpression) as Display might not be implemented yet.
            let pattern_str = format!("{:?}", arm.pattern);
            // Using format! to build parts of the debug string
            arm_debug_strings.push(format!("Arm {}: Pattern=\'{}\'", i, pattern_str));
        }

        // Create a single string for all arm representations
        let all_arms_debug_str = arm_debug_strings.join("\\\\n"); // Use \\\\n for newline in string literal

        let expanded = quote! {
            {
                // This block is just for demonstrating the parser worked.
                // It doesn't execute the match logic.
                // Using a compile-time println via a const to ensure it appears during build.
                const _: () = {
                    // Note: eprintn! might be more visible during proc_macro compilation
                    eprintln!(
                        "match_dsl! Parsed:\\nTarget: {}\\nArms ({}): \\n{}",
                        stringify!(#target_expr_code),
                        #arms_count,
                        #all_arms_debug_str
                    );
                };

                // The actual match logic (if/else if chain) will be generated here in later phases.
                // For now, the macro needs to evaluate to *something*. Let's return unit.
                ()
            }
        };
        expanded.into() // Convert TokenStream2 back to proc_macro::TokenStream
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module (match_dsl_parser)
    use crate::dsl::{PatternBinaryOperator, PatternUnaryOperator}; // DSL specific operators
    use crate::dsl::{
        PatternBindType, PatternBindVariable, PatternExpression, PatternSsaMemoryReference,
        VersionedElement,
    }; // Import AST components from dsl
    use proc_macro2::Span;
    use syn::{parse_quote, LitInt};

    // Helper to create a simple block for test bodies
    fn test_body() -> Block {
        parse_quote!({
            // Test body
        })
    }

    #[test]
    fn test_parse_match_arm_simple_pattern() {
        let input_str = "_ => { }";
        let result = syn::parse_str::<MatchArmInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse simple arm: {:?}",
            result.err()
        );
        let arm = result.unwrap();
        assert!(matches!(arm.pattern, PatternExpression::Wildcard));
        assert!(arm.guard.is_none());
    }

    #[test]
    fn test_parse_match_arm_constant_pattern() {
        let input_str = "123 => { }";
        let result = syn::parse_str::<MatchArmInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse constant pattern arm: {:?}",
            result.err()
        );
        let arm = result.unwrap();
        match arm.pattern {
            PatternExpression::Constant(lit) => {
                assert_eq!(lit.base10_digits(), "123");
            }
            _ => panic!(
                "Expected PatternExpression::Constant, got {:?}",
                arm.pattern
            ),
        }
        assert!(arm.guard.is_none());
    }

    #[test]
    fn test_parse_match_arm_variable_binding() {
        let input_str = "$x:expr => { }";
        let result = syn::parse_str::<MatchArmInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse variable binding arm: {:?}",
            result.err()
        );
        let arm = result.unwrap();
        match arm.pattern {
            PatternExpression::Bind(PatternBindVariable { ident, bind_type }) => {
                assert_eq!(ident.to_string(), "x");
                assert!(matches!(bind_type, PatternBindType::Expression));
            }
            _ => panic!("Expected PatternExpression::Bind, got {:?}", arm.pattern),
        }
    }

    #[test]
    fn test_parse_match_arm_with_guard() {
        let input_str = "$y:const if y > 10 => { }";
        let result = syn::parse_str::<MatchArmInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse arm with guard: {:?}",
            result.err()
        );
        let arm = result.unwrap();
        match arm.pattern {
            PatternExpression::Bind(PatternBindVariable { ident, bind_type }) => {
                assert_eq!(ident.to_string(), "y");
                assert!(matches!(bind_type, PatternBindType::Constant));
            }
            _ => panic!("Expected PatternExpression::Bind, got {:?}", arm.pattern),
        }
        assert!(arm.guard.is_some());
        // Further checks on guard expression possible if needed
    }

    #[test]
    fn test_parse_match_arm_complex_pattern() {
        let input_str = "([R+1].5 * $val) + _ => { }";
        let result = syn::parse_str::<MatchArmInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse complex pattern arm: {:?}",
            result.err()
        );
        // Detailed AST structure check would be verbose.
        // Relying on the dsl.rs pattern parser tests for full structure validation.
        // Here, we just ensure it parses without error.
    }

    #[test]
    fn test_parse_match_dsl_input_single_arm() {
        let input_str = "my_expr, _ => { }";
        let result = syn::parse_str::<MatchDslInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse DSL input with single arm: {:?}",
            result.err()
        );
        let dsl_input = result.unwrap();
        assert_eq!(dsl_input.arms.len(), 1);
        // Target expression check:
    }

    #[test]
    fn test_parse_match_dsl_input_multiple_arms() {
        let input_str = "another_expr, $a:addr => { }, [R-10].0 => { }, _ if guard_cond => { }";
        let result = syn::parse_str::<MatchDslInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse DSL input with multiple arms: {:?}",
            result.err()
        );
        let dsl_input = result.unwrap();
        assert_eq!(dsl_input.arms.len(), 3);
    }

    #[test]
    fn test_parse_match_dsl_input_trailing_comma_arm() {
        let input_str = "my_expr, _ => { },";
        let result = syn::parse_str::<MatchDslInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse DSL input with trailing comma: {:?}",
            result.err()
        );
        let dsl_input = result.unwrap();
        assert_eq!(dsl_input.arms.len(), 1);
    }

    #[test]
    fn test_parse_match_dsl_input_no_arms() {
        let input_str = "my_expr,";
        let result = syn::parse_str::<MatchDslInput>(input_str);
        assert!(
            result.is_err(),
            "Expected error for no arms, but parsed successfully."
        );
    }

    #[test]
    fn test_parse_match_dsl_input_missing_comma_after_target() {
        let input_str = "my_expr _ => { }"; // Missing comma
        let result = syn::parse_str::<MatchDslInput>(input_str);
        assert!(
            result.is_err(),
            "Expected error for missing comma after target."
        );
    }

    #[test]
    fn test_parse_match_dsl_input_missing_comma_between_arms() {
        let input_str = "my_expr, _ => { } $x => { }"; // Missing comma
        let result = syn::parse_str::<MatchDslInput>(input_str);
        assert!(
            result.is_err(),
            "Expected error for missing comma between arms."
        );
    }

    #[test]
    fn test_parse_match_arm_versioned_element_pattern() {
        let input_str = "[R+123].45 => {}";
        let result = syn::parse_str::<MatchArmInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse VersionedElement pattern: {:?}",
            result.err()
        );
        let arm = result.unwrap();
        match arm.pattern {
            PatternExpression::Addressable(PatternSsaMemoryReference::Versioned(ve)) => {
                // Can check ve.sign, ve.offset, ve.version if LitInt had an easy way to get value
                // For now, this structural match is good.
                assert_eq!(ve.offset.base10_digits(), "123");
                assert_eq!(ve.version.base10_digits(), "45");
                assert!(ve.is_relative);
            }
            _ => panic!("Expected Versioned Element, got {:?}", arm.pattern),
        }
    }

    #[test]
    fn test_parse_match_arm_deref_pattern() {
        let input_str = "*($x:expr) => {}";
        let result = syn::parse_str::<MatchArmInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse Deref pattern: {:?}",
            result.err()
        );
        let arm = result.unwrap();
        match arm.pattern {
            PatternExpression::Addressable(PatternSsaMemoryReference::Deref(boxed_inner)) => {
                match *boxed_inner {
                    PatternExpression::Bind(PatternBindVariable { ident, bind_type }) => {
                        assert_eq!(ident.to_string(), "x");
                        assert!(matches!(bind_type, PatternBindType::Expression));
                    }
                    _ => panic!("Expected inner Bind, got {:?}", *boxed_inner),
                }
            }
            _ => panic!("Expected Deref pattern, got {:?}", arm.pattern),
        }
    }
    #[test]
    fn test_parse_match_arm_binary_op_pattern() {
        let input_str = "$lhs + 100 => {}";
        let result = syn::parse_str::<MatchArmInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse binary op pattern: {:?}",
            result.err()
        );
        let arm = result.unwrap();
        match arm.pattern {
            PatternExpression::Binary { op, lhs, rhs } => {
                assert_eq!(op, PatternBinaryOperator::Add);
                match *lhs {
                    PatternExpression::Bind(PatternBindVariable { ident, .. }) => {
                        assert_eq!(ident.to_string(), "lhs");
                    }
                    _ => panic!("Expected LHS to be Bind, got {:?}", lhs),
                }
                match *rhs {
                    PatternExpression::Constant(lit) => assert_eq!(lit.base10_digits(), "100"),
                    _ => panic!("Expected RHS to be Constant, got {:?}", rhs),
                }
            }
            _ => panic!("Expected Binary op pattern, got {:?}", arm.pattern),
        }
    }

    #[test]
    fn test_parse_match_arm_unary_op_pattern() {
        let input_str = "-$val => {}";
        let result = syn::parse_str::<MatchArmInput>(input_str);
        assert!(
            result.is_ok(),
            "Failed to parse unary op pattern: {:?}",
            result.err()
        );
        let arm = result.unwrap();
        match arm.pattern {
            PatternExpression::Unary { op, arg } => {
                assert_eq!(op, PatternUnaryOperator::Minus);
                match *arg {
                    PatternExpression::Bind(PatternBindVariable { ident, .. }) => {
                        assert_eq!(ident.to_string(), "val");
                    }
                    _ => panic!("Expected arg to be Bind, got {:?}", arg),
                }
            }
            _ => panic!("Expected Unary op pattern, got {:?}", arm.pattern),
        }
    }
}
