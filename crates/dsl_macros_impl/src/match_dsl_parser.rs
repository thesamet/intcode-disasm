// disasm/model_macros/macro/src/match_dsl_parser.rs
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use syn::parse::{Parse, ParseStream, Peek};
use syn::Type;
use syn::{spanned::Spanned, Block, Expr, LitInt, Result, Token};

// Assuming these provide the correct base paths
use quote::{quote, ToTokens}; // Required for path generation in stubs

// Imports from the dsl module for pattern parsing
use crate::dsl::{parse_expr_generic, v3_path, PatternExpression, PatternParseStrategy}; // Renamed v3_path to avoid conflict

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
use std::sync::atomic::{AtomicUsize, Ordering};

static UNIQUE_COUNTER: AtomicUsize = AtomicUsize::new(0);

// Helper function to generate a unique number
fn generate_unique_number() -> usize {
    UNIQUE_COUNTER.fetch_add(1, Ordering::SeqCst)
}

struct GeneratedMatchArm {
    bound_var: Vec<(Ident, TokenStream2)>,
    match_bind_or_return: TokenStream2,
}

// Helper function to generate matching conditions and bindings
fn generate_match_conditions_and_bindings(
    target_path: &TokenStream2, // Path to the current part of the target expression being matched
    pattern: &PatternExpression,
    v3_path: &TokenStream2,
) -> Result<Option<GeneratedMatchArm>> {
    match pattern {
        PatternExpression::Wildcard => Ok(None), // nothing to generate
        PatternExpression::Constant(pattern_lit) => {
            let match_bind_or_return = quote! {
                let #v3_path::lir::Expression::Constant(__matched_val) = #target_path else {
                    return None
                };
                if *__matched_val != #pattern_lit {
                    return None
                }
            };
            Ok(Some(GeneratedMatchArm {
                bound_var: vec![],
                match_bind_or_return,
            }))
        }
        PatternExpression::Bind(var_bind) => {
            let bound_var = var_bind.ident.clone();
            match var_bind.bind_type {
                crate::dsl::PatternBindType::Expression => {
                    let match_bind_or_return = quote!(let #bound_var = &#target_path;);
                    Ok(Some(GeneratedMatchArm {
                        bound_var: vec![(
                            bound_var,
                            quote!(#v3_path::lir::Expression<#v3_path::ssa::types::SsaMemoryReference>),
                        )],
                        match_bind_or_return,
                    }))
                }
                crate::dsl::PatternBindType::Constant => {
                    let match_bind_or_return = quote! {
                        let #v3_path::lir::Expression::Constant(ref #bound_var) = #target_path else {
                            return None
                        };
                    };
                    Ok(Some(GeneratedMatchArm {
                        bound_var: vec![(bound_var, quote!(i128))],
                        match_bind_or_return,
                    }))
                }
                crate::dsl::PatternBindType::Addressable => {
                    let match_bind_or_return = quote! {
                        let #v3_path::lir::Expression::Addressable(ref #bound_var) = #target_path else {
                            return None
                        };
                    };
                    Ok(Some(GeneratedMatchArm {
                        bound_var: vec![(
                            bound_var,
                            quote!(#v3_path::ssa::types::SsaMemoryReference),
                        )],
                        match_bind_or_return,
                    }))
                }
            }
        }
        PatternExpression::Addressable(pattern_ssa_ref) => match pattern_ssa_ref {
            crate::dsl::PatternSsaMemoryReference::Versioned(pattern_ve) => {
                let pattern_offset_val: i128 = pattern_ve.offset.base10_parse().map_err(|e| {
                    syn::Error::new(
                        pattern_ve.offset.span(),
                        format!("Invalid pattern offset: {}", e),
                    )
                })?;
                let pattern_version_val: usize =
                    pattern_ve.version.base10_parse().map_err(|e| {
                        syn::Error::new(
                            pattern_ve.version.span(),
                            format!("Invalid pattern version: {}", e),
                        )
                    })?;
                let pattern_sign_val = pattern_ve.sign;
                let pattern_is_relative_val = pattern_ve.is_relative;
                let match_bind_or_return = if pattern_is_relative_val {
                    let offset = pattern_ve.sign * pattern_offset_val;
                    quote! {
                        if !matches!(#target_path, #v3_path::lir::Expression::Addressable(#v3_path::ssa::SsaMemoryReference::Versioned(#v3_path::ssa::types::VersionedMemoryReference {
                            kind: #v3_path::ssa::types::VersionableMemoryKind::RelativeMemory(#offset),
                            version: #pattern_version_val,
                            ..
                        }))) {
                            return None
                        }
                    }
                } else {
                    let pattern_offset_val = pattern_offset_val as usize;
                    quote! {
                        if !

                        matches!(#target_path, #v3_path::lir::Expression::Addressable(#v3_path::ssa::SsaMemoryReference::Versioned(#v3_path::ssa::types::VersionedMemoryReference {
                            kind: #v3_path::ssa::types::VersionableMemoryKind::Memory(#pattern_offset_val),
                            version: #pattern_version_val,
                            ..
                        }))) {
                            return None
                        }
                    }
                };
                Ok(Some(GeneratedMatchArm {
                    bound_var: vec![],
                    match_bind_or_return,
                }))
            }
            crate::dsl::PatternSsaMemoryReference::Deref(inner_pattern_expr) => {
                let lir_deref_inner_expr_ident = Ident::new(
                    &format!("__deref_inner_{}", generate_unique_number()),
                    Span::call_site(),
                );
                let inner = generate_match_conditions_and_bindings(
                    &quote!(#lir_deref_inner_expr_ident.as_ref()),
                    inner_pattern_expr.as_ref(),
                    v3_path,
                )?;
                let inner_code = inner.as_ref().map(|i| &i.match_bind_or_return);
                let match_bind_or_return = quote! {
                    let #v3_path::lir::Expression::Addressable(#v3_path::ssa::SsaMemoryReference::Deref(#lir_deref_inner_expr_ident)) = &#target_path else {
                        return None
                    };
                    #inner_code
                };
                Ok(Some(GeneratedMatchArm {
                    bound_var: inner
                        .as_ref()
                        .map(|i| i.bound_var.clone())
                        .unwrap_or_default(),
                    match_bind_or_return,
                }))
            }
        },
        PatternExpression::Unary {
            op: pattern_op,
            arg: pattern_arg,
        } => {
            let lir_op_token = match pattern_op {
                crate::dsl::PatternUnaryOperator::Not => quote!(#v3_path::lir::UnaryOperator::Not),
                crate::dsl::PatternUnaryOperator::Minus => {
                    quote!(#v3_path::lir::UnaryOperator::Minus)
                }
            };
            let lir_inner_expr_ident = Ident::new(
                &format!("__unary_inner_{}", generate_unique_number()),
                Span::call_site(),
            );
            let inner = generate_match_conditions_and_bindings(
                &quote!(#lir_inner_expr_ident.as_ref()),
                pattern_arg.as_ref(),
                v3_path,
            )?;
            let inner_code = inner.as_ref().map(|i| &i.match_bind_or_return);
            let match_bind_or_return = quote! {
                let #v3_path::lir::Expression::Unary { op: #lir_op_token, arg: ref #lir_inner_expr_ident } = &#target_path else {
                    return None
                };
                #inner_code
            };
            Ok(Some(GeneratedMatchArm {
                bound_var: inner.map(|i| i.bound_var).unwrap_or_default(),
                match_bind_or_return,
            }))
        }
        PatternExpression::Binary {
            op: pattern_op,
            lhs: pattern_lhs,
            rhs: pattern_rhs,
        } => {
            let lir_op_token = match pattern_op {
                crate::dsl::PatternBinaryOperator::Add => {
                    quote!(#v3_path::lir::BinaryOperator::Add)
                }
                crate::dsl::PatternBinaryOperator::Sub => {
                    quote!(#v3_path::lir::BinaryOperator::Sub)
                }
                crate::dsl::PatternBinaryOperator::Mul => {
                    quote!(#v3_path::lir::BinaryOperator::Mul)
                }
                crate::dsl::PatternBinaryOperator::LessThan => {
                    quote!(#v3_path::BinaryOperator::LessThan)
                }
                crate::dsl::PatternBinaryOperator::LessThanOrEqual => {
                    quote!(#v3_path::BinaryOperator::LessThanOrEqual)
                }
                crate::dsl::PatternBinaryOperator::GreaterThan => {
                    quote!(#v3_path::BinaryOperator::GreaterThan)
                }
                crate::dsl::PatternBinaryOperator::GreaterThanOrEqual => {
                    quote!(#v3_path::BinaryOperator::GreaterThanOrEqual)
                }
                crate::dsl::PatternBinaryOperator::Equals => {
                    quote!(#v3_path::BinaryOperator::Equals)
                }
                crate::dsl::PatternBinaryOperator::NotEquals => {
                    quote!(#v3_path::BinaryOperator::NotEquals)
                }
            };

            let lir_lhs_ident = Ident::new("__binary_lir_lhs", Span::call_site());
            let lir_rhs_ident = Ident::new("__binary_lir_rhs", Span::call_site());

            // Recursively generate conditions for lhs and rhs
            let lhs_generated = generate_match_conditions_and_bindings(
                &quote!(#lir_lhs_ident.as_ref()),
                &*pattern_lhs, // Dereference Box and take reference
                v3_path,
            )?;
            let rhs_generated = generate_match_conditions_and_bindings(
                &quote!(#lir_rhs_ident.as_ref()),
                &*pattern_rhs, // Dereference Box and take reference
                v3_path,
            )?;

            let lhs_code = lhs_generated.as_ref().map(|i| &i.match_bind_or_return);
            let rhs_code = rhs_generated.as_ref().map(|i| &i.match_bind_or_return);

            let match_bind_or_return = quote! {
                let #v3_path::lir::Expression::Binary { op: #lir_op_token, lhs: ref #lir_lhs_ident, rhs: ref #lir_rhs_ident } = &#target_path else {
                    return None
                };
                #lhs_code
                #rhs_code
            };
            let mut bound_vars = lhs_generated.map(|i| i.bound_var).unwrap_or_default();
            bound_vars.extend(rhs_generated.map(|i| i.bound_var).unwrap_or_default());

            Ok(Some(GeneratedMatchArm {
                bound_var: bound_vars,
                match_bind_or_return,
            }))
        }
    }
}

impl MatchDslInput {
    pub fn expanded(&self) -> TokenStream2 {
        let target_expr_to_match = &self.target_expr;
        let match_target_ident = Ident::new("__match_dsl_target", Span::call_site());

        let v3_path = v3_path();

        let mut generated_functions = Vec::new();
        let mut arm_results = Vec::new();

        for arm in &self.arms {
            let func_name = Ident::new(
                &format!("__dsl_match_{}", generate_unique_number()),
                Span::call_site(),
            );
            let arm_body_expr = &arm.body;

            match generate_match_conditions_and_bindings(&quote!(expr), &arm.pattern, &v3_path) {
                Ok(Some(GeneratedMatchArm {
                    bound_var,
                    match_bind_or_return,
                })) => {
                    let types: Vec<_> = bound_var.iter().map(|(_, ty)| ty).collect();
                    let vars: Vec<_> = bound_var.iter().map(|(var, _)| var).collect();

                    let guard_condition = if let Some(guard_expr) = &arm.guard {
                        quote! { #guard_expr }
                    } else {
                        quote! { true } // No guard, so always true
                    };

                    // Create the matching function for this arm.
                    generated_functions.push(quote! {
                        fn #func_name(expr: &#v3_path::lir::Expression<#v3_path::ssa::types::SsaMemoryReference>) -> Option<(#(&#types),*)> {
                            #match_bind_or_return
                            if #guard_condition {
                                Some((#(#vars),*))
                            } else {
                                None
                            }
                        }
                    });

                    arm_results.push(quote! {
                        if let Some((#(#vars),*)) = #func_name(&#match_target_ident) {
                            #arm_body_expr
                        }
                    });
                }
                Ok(None) => {
                    // Wildcard pattern, always matches.
                    let guard_condition = if let Some(guard_expr) = &arm.guard {
                        quote! { #guard_expr }
                    } else {
                        quote! { true } // No guard, so always true
                    };
                    arm_results.push(quote! {
                        if #guard_condition {
                            #arm_body_expr
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
            let mut chained_code = quote! {};
            let mut first_arm = true;
            for arm_result in arm_results {
                if first_arm {
                    chained_code = quote! {
                        #arm_result
                    };
                    first_arm = false;
                } else {
                    chained_code = quote! {
                        #chained_code
                        else #arm_result
                    };
                }
            }
            eprintln!("CHAINED CODE: {}", chained_code);
            chained_code = quote! {
                #chained_code
                else { panic!("match_dsl! patterns not exhaustive on target: {:?}", #match_target_ident) }
            };

            chained_code
        };

        let expanded_code = quote! {
            {
                #(#generated_functions)* // Define the matching functions.
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
