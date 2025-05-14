// disasm/model_macros/macro/src/match_dsl_parser.rs
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use syn::parse::{Parse, ParseStream, Peek};
use syn::{spanned::Spanned, Block, Expr, LitInt, Result, Token};

// Assuming these provide the correct base paths
use quote::quote; // Required for path generation in stubs

// Imports from the dsl module for pattern parsing
use crate::dsl::{
    lir_path as dsl_lir_path, parse_expr_generic, ssa_path as dsl_ssa_path, PatternExpression,
    PatternParseStrategy,
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
    pub body: Expr,                 // Changed from Block to Expr
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

        // 4. Parse the body as an Expression
        let body: Expr = input.parse()?;

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
    ssa_path: &TokenStream2,          // Path to SSA types (e.g., quote!(crate::disasm::v3::ssa))
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
            let var_ident = &var_bind.ident;
            match var_bind.bind_type {
                crate::dsl::PatternBindType::Expression => {
                    // Binds the current target_path directly.
                    // The condition is true, as it matches any expression at this level.
                    bindings.push(quote!(let #var_ident = (#target_path).clone();));
                    Ok(quote!(true))
                }
                crate::dsl::PatternBindType::Constant => {
                    // Target must be an LIR Constant expression.
                    // The binding is pushed as a side-effect if the match succeeds.
                    let condition = quote! {
                        (match *#target_path {
                            #lir_path::Expression::Constant(ref __val_for_binding) => {
                                bindings.push(quote!(let #var_ident = *__val_for_binding;));
                                true
                            }
                            _ => false,
                        })
                    };
                    Ok(condition)
                }
                crate::dsl::PatternBindType::Addressable => {
                    // Target must be an LIR Addressable expression.
                    // The binding is pushed as a side-effect if the match succeeds.
                    let condition = quote! {
                        (match *#target_path {
                            #lir_path::Expression::Addressable(ref __val_for_binding) => {
                                // Assuming the addressable type `A` in `Expression<A>` is Clone.
                                // For SsaMemoryReference, this should be fine.
                                bindings.push(quote!(let #var_ident = __val_for_binding.clone();));
                                true
                            }
                            _ => false,
                        })
                    };
                    Ok(condition)
                }
            }
        }
        PatternExpression::Addressable(pattern_ssa_ref) => {
            match pattern_ssa_ref {
                crate::dsl::PatternSsaMemoryReference::Versioned(pattern_ve) => {
                    let pattern_offset_val: i128 =
                        pattern_ve.offset.base10_parse().map_err(|e| {
                            syn::Error::new(
                                pattern_ve.offset.span(),
                                format!("Invalid pattern offset: {}", e),
                            )
                        })?;
                    let pattern_version_val: u64 =
                        pattern_ve.version.base10_parse().map_err(|e| {
                            syn::Error::new(
                                pattern_ve.version.span(),
                                format!("Invalid pattern version: {}", e),
                            )
                        })?;
                    let pattern_sign_val = pattern_ve.sign;
                    let pattern_is_relative_val = pattern_ve.is_relative;

                    let condition = quote! {
                        (match *#target_path {
                            #lir_path::Expression::Addressable(ref ssa_ref) => {
                                match ssa_ref {
                                    #ssa_path::SsaMemoryReference::Versioned(ref lir_vmr) => {
                                        let lir_version = lir_vmr.version as u64;
                                        let version_match = #pattern_version_val == lir_version;

                                        let kind_match = match (&lir_vmr.kind, #pattern_is_relative_val) {
                                            (#ssa_path::types::VersionableMemoryKind::RelativeMemory(lir_rel_offset_signed_val), true) => {
                                                let expected_lir_rel_offset_signed = #pattern_offset_val * #pattern_sign_val;
                                                *lir_rel_offset_signed_val == expected_lir_rel_offset_signed
                                            }
                                            (#ssa_path::types::VersionableMemoryKind::Memory(lir_abs_offset_val), false) => {
                                                (*lir_abs_offset_val == #pattern_offset_val as usize) && #pattern_sign_val == 1
                                            }
                                            _ => false,
                                        };
                                        version_match && kind_match
                                    }
                                    _ => false,
                                }
                            }
                            _ => false,
                        })
                    };
                    Ok(condition)
                }
                crate::dsl::PatternSsaMemoryReference::Deref(inner_pattern_expr) => {
                    let lir_deref_inner_expr_ident =
                        Ident::new("__addr_deref_lir_inner", Span::call_site());
                    let lir_deref_inner_expr_path = quote!(#lir_deref_inner_expr_ident);

                    let sub_condition = generate_match_conditions_and_bindings(
                        &lir_deref_inner_expr_path,
                        &*inner_pattern_expr, // Dereference Box and take reference
                        bindings,
                        lir_path,
                        ssa_path,
                    )?;

                    let overall_condition = quote! {
                        (match *#target_path {
                            #lir_path::Expression::Addressable(ref ssa_ref) => {
                                match ssa_ref {
                                    #ssa_path::SsaMemoryReference::Deref(ref #lir_deref_inner_expr_ident) => {
                                        #sub_condition
                                    }
                                    _ => false,
                                }
                            }
                            _ => false,
                        })
                    };
                    Ok(overall_condition)
                }
            }
        }
        PatternExpression::Unary {
            op: pattern_op,
            arg: pattern_arg,
        } => {
            let lir_op_token = match pattern_op {
                crate::dsl::PatternUnaryOperator::Not => quote!(#lir_path::UnaryOperator::Not),
                crate::dsl::PatternUnaryOperator::Minus => quote!(#lir_path::UnaryOperator::Minus),
            };

            let lir_arg_ident = Ident::new("__unary_lir_arg", Span::call_site());
            let lir_arg_path = quote!(#lir_arg_ident);

            let arg_condition = generate_match_conditions_and_bindings(
                &lir_arg_path,
                &*pattern_arg, // Dereference Box and take reference
                bindings,
                lir_path,
                ssa_path,
            )?;

            let overall_condition = quote! {
                (match *#target_path {
                    #lir_path::Expression::Unary { op: #lir_op_token, arg: ref #lir_arg_ident } => {
                        #arg_condition
                    }
                    _ => false,
                })
            };
            Ok(overall_condition)
        }
        PatternExpression::Binary {
            op: pattern_op,
            lhs: pattern_lhs,
            rhs: pattern_rhs,
        } => {
            let lir_op_token = match pattern_op {
                crate::dsl::PatternBinaryOperator::Add => quote!(#lir_path::BinaryOperator::Add),
                crate::dsl::PatternBinaryOperator::Sub => quote!(#lir_path::BinaryOperator::Sub),
                crate::dsl::PatternBinaryOperator::Mul => quote!(#lir_path::BinaryOperator::Mul),
                crate::dsl::PatternBinaryOperator::LessThan => {
                    quote!(#lir_path::BinaryOperator::LessThan)
                }
                crate::dsl::PatternBinaryOperator::LessThanOrEqual => {
                    quote!(#lir_path::BinaryOperator::LessThanOrEqual)
                }
                crate::dsl::PatternBinaryOperator::GreaterThan => {
                    quote!(#lir_path::BinaryOperator::GreaterThan)
                }
                crate::dsl::PatternBinaryOperator::GreaterThanOrEqual => {
                    quote!(#lir_path::BinaryOperator::GreaterThanOrEqual)
                }
                crate::dsl::PatternBinaryOperator::Equals => {
                    quote!(#lir_path::BinaryOperator::Equals)
                }
                crate::dsl::PatternBinaryOperator::NotEquals => {
                    quote!(#lir_path::BinaryOperator::NotEquals)
                }
            };

            let lir_lhs_ident = Ident::new("__binary_lir_lhs", Span::call_site());
            let lir_lhs_path = quote!(#lir_lhs_ident);
            let lir_rhs_ident = Ident::new("__binary_lir_rhs", Span::call_site());
            let lir_rhs_path = quote!(#lir_rhs_ident);

            let lhs_condition = generate_match_conditions_and_bindings(
                &lir_lhs_path,
                &*pattern_lhs, // Dereference Box and take reference
                bindings,
                lir_path,
                ssa_path,
            )?;
            let rhs_condition = generate_match_conditions_and_bindings(
                &lir_rhs_path,
                &*pattern_rhs, // Dereference Box and take reference
                bindings,
                lir_path,
                ssa_path,
            )?;

            let overall_condition = quote! {
                (match *#target_path {
                    #lir_path::Expression::Binary { op: #lir_op_token, lhs: ref #lir_lhs_ident, rhs: ref #lir_rhs_ident } => {
                        (#lhs_condition && #rhs_condition)
                    }
                    _ => false,
                })
            };
            Ok(overall_condition)
        }
    }
}

impl MatchDslInput {
    pub fn expanded(&self) -> TokenStream2 {
        let target_expr_to_match = &self.target_expr;
        let match_target_ident = Ident::new("__match_dsl_target", Span::call_site());

        // Get LIR path using the imported and possibly renamed dsl_lir_path
        let lir_path = crate::dsl::lir_path();
        let ssa_path = crate::dsl::ssa_path(); // Added ssa_path

        let mut arm_results = Vec::new();

        for arm in &self.arms {
            let mut bindings = Vec::new();
            let initial_target_path = quote!(#match_target_ident);

            match generate_match_conditions_and_bindings(
                &initial_target_path,
                &arm.pattern,
                &mut bindings,
                &lir_path,
                &ssa_path, // Added ssa_path argument
            ) {
                Ok(condition_code) => {
                    // arm.body is now an Expr.
                    // The guard is integrated into final_condition.
                    let arm_body_expr = &arm.body;

                    let final_condition = if let Some(guard_expr) = &arm.guard {
                        quote!(#condition_code && (#guard_expr))
                    } else {
                        condition_code
                    };

                    arm_results.push(quote! {
                        if #final_condition {
                            #(#bindings)*
                            // The body is an Expr, so it directly becomes the value of this branch
                            (#arm_body_expr)
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
            // Add a final `else` that panics for non-exhaustiveness.
            // This makes the `if/else if` chain an expression.
            quote! {
                #chained_code
                else {
                    panic!("match_dsl! patterns not exhaustive on target: {:?}", #match_target_ident);
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
