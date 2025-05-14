// disasm/model_macros/macro/src/match_dsl_parser.rs
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use syn::parse::{Parse, ParseStream, Peek};
use syn::{spanned::Spanned, Block, Expr, LitInt, Result, Token};

// Assuming these provide the correct base paths
use quote::quote; // Required for path generation in stubs

// Imports from the dsl module for pattern parsing
use crate::dsl::{
    lir_path as dsl_lir_path, parse_expr_generic, PatternExpression, PatternParseStrategy,
}; // Renamed lir_path to avoid conflict

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
//
// Helper function to generate matching conditions and bindings
fn generate_match_conditions_and_bindings(
    target_path: &TokenStream2, // Path to the current part of the target expression being matched
    pattern: &PatternExpression,
    bindings: &mut Vec<TokenStream2>, // Accumulates `let` bindings
    lir_path: &TokenStream2,          // Path to LIR types (e.g., quote!(crate::disasm::v3::lir))
) -> Result<TokenStream2> {
    // Returns the condition code for an `if` statement
    match pattern {
        PatternExpression::Wildcard => {
            // Wildcard always matches, condition is true. No bindings.
            Ok(quote!(true))
        }
        PatternExpression::Constant(pattern_lit) => {
            // Target must be an LIR Constant expression and its value must match pattern_lit.
            // We expect target_path to be a reference (e.g., &lir::Expression), so we dereference it in the pattern match.
            let condition = quote! {
                (
                    if let #lir_path::Expression::Constant(ref __matched_val) = *#target_path {
                        *__matched_val == #pattern_lit
                    } else {
                        false
                    }
                )
            };
            Ok(condition)
        }
        PatternExpression::Bind(var_bind) => {
            Err(syn::Error::new(
                var_bind.ident.span(), // Use the span of the binding identifier
                "PatternExpression::Bind not yet implemented in code generation",
            ))
        }
        PatternExpression::Addressable(pattern_ssa) => {
            // Attempt to get a reasonable span for the error
            let error_span = match pattern_ssa {
                crate::dsl::PatternSsaMemoryReference::Versioned(ve) => ve.offset.span(), // Span of the offset LitInt
                crate::dsl::PatternSsaMemoryReference::Deref(_) => {
                    // Fallback for Deref span, as inner PatternExpression doesn't directly carry a span easily
                    Span::call_site()
                }
            };
            Err(syn::Error::new(
                error_span,
                "PatternExpression::Addressable not yet implemented",
            ))
        }
        PatternExpression::Unary { op: _, arg: _ } => {
            Err(syn::Error::new(
                Span::call_site(), // Placeholder: improve span, perhaps from op or arg if possible
                "PatternExpression::Unary not yet implemented",
            ))
        }
        PatternExpression::Binary {
            op: _,
            lhs: _,
            rhs: _,
        } => {
            Err(syn::Error::new(
                Span::call_site(), // Placeholder: improve span
                "PatternExpression::Binary not yet implemented",
            ))
        }
    }
}

impl MatchDslInput {
    pub fn expanded(&self) -> TokenStream2 {
        let target_expr_to_match = &self.target_expr;
        let match_target_ident = Ident::new("__match_dsl_target", Span::call_site());

        // Get LIR path using the imported and possibly renamed dsl_lir_path
        let lir_path = crate::dsl::lir_path();

        let mut arm_results = Vec::new();

        for arm in &self.arms {
            let mut bindings = Vec::new();
            let initial_target_path = quote!(#match_target_ident);

            match generate_match_conditions_and_bindings(
                &initial_target_path,
                &arm.pattern,
                &mut bindings,
                &lir_path,
            ) {
                Ok(condition_code) => {
                    let arm_body = &arm.body;
                    let full_arm_body_code = if let Some(guard_expr) = &arm.guard {
                        quote! {
                            if #guard_expr {
                                #arm_body
                            } else {
                                // If guard fails, this arm doesn't match.
                                // To fit into an if/else if chain, this branch could do nothing
                                // or we could structure the condition differently.
                                // For now, the outer `if #condition_code` handles the main pattern match.
                                // The guard is an additional condition *inside* the successful match.
                                // So, if guard fails, the body is simply not executed.
                                // This means the else branch for the guard is not strictly needed
                                // if the guard is part of the main `if` condition.
                                // Let's integrate guard into the main condition for now.
                            }
                        }
                    } else {
                        quote!(#arm_body)
                    };

                    // Integrate guard into the main condition
                    let final_condition = if let Some(guard_expr) = &arm.guard {
                        quote!(#condition_code && (#guard_expr))
                    } else {
                        condition_code
                    };

                    arm_results.push(quote! {
                        if #final_condition {
                            #(#bindings)*
                            #full_arm_body_code
                        }
                    });
                }
                Err(e) => {
                    // If generating conditions/bindings for an arm fails, propagate as compile error
                    return e.to_compile_error().into();
                }
            }
        }

        let final_match_logic = if arm_results.is_empty() {
            // This should be caught by the parser, but as a defensive measure:
            syn::Error::new(
                Span::call_site(),
                "match_dsl! macro requires at least one arm.",
            )
            .to_compile_error()
        } else {
            let mut chained_code = arm_results[0].clone();
            for i in 1..arm_results.len() {
                let next_arm_code = &arm_results[i];
                chained_code = quote! {
                    #chained_code else #next_arm_code
                };
            }
            // Add a final `else {}` to make it an expression and ensure it type-checks
            // if the bodies don't all return or have the same type.
            // User might need to ensure bodies are compatible or the last arm is a wildcard.
            quote! {
                #chained_code
                else {
                    // Default case if no arms match.
                    // Could be panic!("non-exhaustive patterns in match_dsl!"), or just ().
                    // For now, let it be an empty block, meaning it evaluates to ().
                }
            }
        };

        let expanded_code = quote! {
            {
                let #match_target_ident = &#target_expr_to_match;
                #final_match_logic
            }
        };

        expanded_code.into()
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

    #[test]
    fn test_generated_code_wildcard() {
        let input_str = "my_var, _ => {println!(\"wildcard\");}"; // "ทำงาน" means "work" or "execute"
        let parsed_dsl: MatchDslInput = syn::parse_str(input_str).unwrap();
        let generated_ts = parsed_dsl.expanded();
        assert!(!generated_ts.to_string().is_empty());
    }

    #[test]
    fn test_generated_code_constant() {
        let input_str = "another_var, 123 => {println!(\"constant_123\");}";
        let parsed_dsl: MatchDslInput = syn::parse_str(input_str).unwrap();
        let generated_ts = parsed_dsl.expanded();
        // println!("{}", generated_ts.to_string());
        println!("{}", generated_ts.to_string()); // Optional: print to see generated code
                                                  // Further assertions could try to parse generated_ts into a syn::File or syn::Block
                                                  // and inspect its structure, but that's more advanced.
                                                  // For now, ensuring it compiles and looks reasonable if printed is a good start.
        assert!(!generated_ts.to_string().is_empty());
    }
}
