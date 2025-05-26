// disasm/model_macros/macro/src/match_dsl_parser.rs
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use syn::parse::{Parse, ParseStream};
use syn::{spanned::Spanned, Expr, Result, Token};

// Assuming these provide the correct base paths
use quote::quote; // Required for path generation in stubs

// Imports from the dsl module for pattern parsing
use crate::dsl::{
    parse_expr_generic, v3_path, PatternBindVariable, PatternExpression, PatternParseStrategy,
    VersionedElement,
}; // Renamed v3_path to avoid conflict

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
// Start of refactored section: Helper functions for generate_match_conditions_and_bindings

// --- Path Helpers ---
#[inline]
fn _path_lir_expr(v3_path: &TokenStream2) -> TokenStream2 {
    quote!(#v3_path::lir::Expression)
}
#[inline]
fn _path_lir_expr_constant(v3_path: &TokenStream2) -> TokenStream2 {
    let lir_expr = _path_lir_expr(v3_path);
    quote!(#lir_expr::Constant)
}
#[inline]
fn _path_lir_expr_addressable(v3_path: &TokenStream2) -> TokenStream2 {
    let lir_expr = _path_lir_expr(v3_path);
    quote!(#lir_expr::Addressable)
}
#[inline]
fn _path_ssa_mem_ref(v3_path: &TokenStream2) -> TokenStream2 {
    quote!(#v3_path::ssa::SsaMemoryReference)
}
#[inline]
fn _path_ssa_mem_ref_versioned(v3_path: &TokenStream2) -> TokenStream2 {
    let ssa_mem_ref = _path_ssa_mem_ref(v3_path);
    quote!(#ssa_mem_ref::Versioned)
}
#[inline]
fn _path_ssa_mem_ref_deref(v3_path: &TokenStream2) -> TokenStream2 {
    let ssa_mem_ref = _path_ssa_mem_ref(v3_path);
    quote!(#ssa_mem_ref::Deref)
}
#[inline]
fn _path_ssa_types_versioned_mem_ref(v3_path: &TokenStream2) -> TokenStream2 {
    quote!(#v3_path::ssa::types::VersionedMemoryReference)
}
#[inline]
fn _path_ssa_types_versionable_mem_kind(v3_path: &TokenStream2) -> TokenStream2 {
    quote!(#v3_path::ssa::types::VersionableMemoryKind)
}
#[inline]
fn _path_lir_unary_op(v3_path: &TokenStream2) -> TokenStream2 {
    quote!(#v3_path::lir::UnaryOperator)
}
#[inline]
fn _path_lir_binary_op(v3_path: &TokenStream2) -> TokenStream2 {
    quote!(#v3_path::lir::BinaryOperator) // Note: Original had #v3_path::BinaryOperator for some, correcting to #v3_path::lir::BinaryOperator
}
#[inline]
fn _path_ssa_types_ssa_memory_reference(v3_path: &TokenStream2) -> TokenStream2 {
    quote!(#v3_path::ssa::types::SsaMemoryReference)
}
#[inline]
fn _path_lir_expr_unary(v3_path: &TokenStream2) -> TokenStream2 {
    let lir_expr = _path_lir_expr(v3_path);
    quote!(#lir_expr::Unary)
}
#[inline]
fn _path_lir_expr_binary(v3_path: &TokenStream2) -> TokenStream2 {
    let lir_expr = _path_lir_expr(v3_path);
    quote!(#lir_expr::Binary)
}

// --- Quote Block Helpers ---
fn _quote_constant_match_code(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    pattern_lit: &syn::LitInt,
) -> TokenStream2 {
    let lir_expr_constant_path = _path_lir_expr_constant(v3_path);
    quote! {
        let #lir_expr_constant_path(__matched_val) = #target_path else {
            return None
        };
        if *__matched_val != #pattern_lit {
            return None
        }
    }
}

fn _quote_bind_expression_code(bound_var: &Ident, target_path: &TokenStream2) -> TokenStream2 {
    quote!(let #bound_var = #target_path;)
}

fn _quote_bind_constant_code(
    bound_var: &Ident,
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
) -> TokenStream2 {
    let lir_expr_constant_path = _path_lir_expr_constant(v3_path);
    quote! {
        let #lir_expr_constant_path(ref #bound_var) = #target_path else {
            return None
        };
    }
}

fn _quote_bind_addressable_code(
    bound_var: &Ident,
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
) -> TokenStream2 {
    let lir_expr_addressable_path = _path_lir_expr_addressable(v3_path);
    quote! {
        let #lir_expr_addressable_path(ref #bound_var) = #target_path else {
            return None
        };
    }
}

fn _quote_versioned_match_code(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    pattern_ve: &VersionedElement,
    pattern_offset_val: i128,
    pattern_version_val: usize,
) -> TokenStream2 {
    let lir_expr_addressable_path = _path_lir_expr_addressable(v3_path);
    let ssa_mem_ref_versioned_path = _path_ssa_mem_ref_versioned(v3_path);
    let ssa_types_versioned_mem_ref_path = _path_ssa_types_versioned_mem_ref(v3_path);
    let versionable_mem_kind_path = _path_ssa_types_versionable_mem_kind(v3_path);

    match &pattern_ve.kind {
        crate::dsl::VersionedElementKind::Relative { sign, .. } => {
            let offset = sign * pattern_offset_val;
            quote! {
                if !matches!(#target_path, #lir_expr_addressable_path(#ssa_mem_ref_versioned_path(#ssa_types_versioned_mem_ref_path {
                    kind: #versionable_mem_kind_path::RelativeMemory(#offset),
                    version: #pattern_version_val,
                    ..
                }))) {
                    return None
                }
            }
        }
        crate::dsl::VersionedElementKind::Absolute(_) => {
            let pattern_offset_val = pattern_offset_val as usize; // Shadow to usize for Memory kind
            quote! {
                if !matches!(#target_path, #lir_expr_addressable_path(#ssa_mem_ref_versioned_path(#ssa_types_versioned_mem_ref_path {
                    kind: #versionable_mem_kind_path::Memory(#pattern_offset_val),
                    version: #pattern_version_val,
                    ..
                }))) {
                    return None
                }
            }
        }
        crate::dsl::VersionedElementKind::Pointer(_) => {
            let pattern_offset_val = pattern_offset_val as usize; // Shadow to usize for PointerId
            quote! {
                if !matches!(#target_path, #lir_expr_addressable_path(#ssa_mem_ref_versioned_path(#ssa_types_versioned_mem_ref_path {
                    kind: #versionable_mem_kind_path::Pointer(#v3_path::PointerId::new(#pattern_offset_val)),
                    version: #pattern_version_val,
                    ..
                }))) {
                    return None
                }
            }
        }
    }
}

fn _quote_deref_match_code(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    lir_deref_inner_expr_ident: &Ident,
    inner_code: Option<&TokenStream2>,
) -> TokenStream2 {
    let lir_expr_addressable_path = _path_lir_expr_addressable(v3_path);
    let ssa_mem_ref_deref_path = _path_ssa_mem_ref_deref(v3_path);
    quote! {
        let #lir_expr_addressable_path(#ssa_mem_ref_deref_path(#lir_deref_inner_expr_ident)) = #target_path else {
            return None
        };
        #inner_code
    }
}

fn _quote_unary_match_code(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    lir_op_token: &TokenStream2,
    lir_inner_expr_ident: &Ident,
    inner_code: Option<&TokenStream2>,
) -> TokenStream2 {
    let lir_expr_unary_path = _path_lir_expr_unary(v3_path);
    quote! {
        let #lir_expr_unary_path { op: #lir_op_token, arg: ref #lir_inner_expr_ident } = #target_path else {
            return None
        };
        #inner_code
    }
}

fn _quote_binary_match_code(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    lir_op_token: &TokenStream2,
    lir_lhs_ident: &Ident,
    lir_rhs_ident: &Ident,
    lhs_code: Option<&TokenStream2>,
    rhs_code: Option<&TokenStream2>,
) -> TokenStream2 {
    let lir_expr_binary_path = _path_lir_expr_binary(v3_path);
    quote! {
        let #lir_expr_binary_path { op: #lir_op_token, lhs: ref #lir_lhs_ident, rhs: ref #lir_rhs_ident } = #target_path else {
            return None
        };
        #lhs_code
        #rhs_code
    }
}

// --- Arm Handler Helpers ---
fn _handle_constant_pattern(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    pattern_lit: &syn::LitInt,
) -> Result<Option<GeneratedMatchArm>> {
    let match_bind_or_return = _quote_constant_match_code(target_path, v3_path, pattern_lit);
    Ok(Some(GeneratedMatchArm {
        bound_var: vec![],
        match_bind_or_return,
    }))
}

fn _handle_bind_pattern(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    var_bind: &PatternBindVariable,
) -> Result<Option<GeneratedMatchArm>> {
    let bound_var_ident = var_bind.ident.clone();
    let (bound_var_type_code, match_bind_or_return) = match var_bind.bind_type {
        crate::dsl::PatternBindType::Expression => {
            let lir_expr_path = _path_lir_expr(v3_path);
            let ssa_types_ssa_mem_ref_path = _path_ssa_types_ssa_memory_reference(v3_path);
            (
                quote!(#lir_expr_path<#ssa_types_ssa_mem_ref_path>),
                _quote_bind_expression_code(&bound_var_ident, target_path),
            )
        }
        crate::dsl::PatternBindType::Constant => (
            quote!(i128),
            _quote_bind_constant_code(&bound_var_ident, target_path, v3_path),
        ),
        crate::dsl::PatternBindType::Addressable => {
            let ssa_types_ssa_mem_ref_path = _path_ssa_types_ssa_memory_reference(v3_path);
            (
                quote!(#ssa_types_ssa_mem_ref_path),
                _quote_bind_addressable_code(&bound_var_ident, target_path, v3_path),
            )
        }
    };

    Ok(Some(GeneratedMatchArm {
        bound_var: vec![(bound_var_ident, bound_var_type_code)],
        match_bind_or_return,
    }))
}

fn _handle_addressable_versioned_pattern(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    pattern_ve: &VersionedElement,
) -> Result<Option<GeneratedMatchArm>> {
    // Extract the offset value based on the kind
    let pattern_offset_val: i128 = match &pattern_ve.kind {
        crate::dsl::VersionedElementKind::Absolute(offset) => {
            offset.base10_parse().map_err(|e| {
                syn::Error::new(offset.span(), format!("Invalid pattern offset: {}", e))
            })?
        }
        crate::dsl::VersionedElementKind::Relative { offset, .. } => {
            offset.base10_parse().map_err(|e| {
                syn::Error::new(offset.span(), format!("Invalid pattern offset: {}", e))
            })?
        }
        crate::dsl::VersionedElementKind::Pointer(id) => id
            .base10_parse()
            .map_err(|e| syn::Error::new(id.span(), format!("Invalid pointer ID: {}", e)))?,
    };

    let pattern_version_val: usize = pattern_ve.version.base10_parse().map_err(|e| {
        syn::Error::new(
            pattern_ve.version.span(),
            format!("Invalid pattern version: {}", e),
        )
    })?;

    let match_bind_or_return = _quote_versioned_match_code(
        target_path,
        v3_path,
        pattern_ve,
        pattern_offset_val,
        pattern_version_val,
    );
    Ok(Some(GeneratedMatchArm {
        bound_var: vec![],
        match_bind_or_return,
    }))
}

fn _handle_addressable_deref_pattern(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    inner_pattern_expr: &Box<PatternExpression>,
) -> Result<Option<GeneratedMatchArm>> {
    let lir_deref_inner_expr_ident = Ident::new(
        &format!("__deref_inner_{}", generate_unique_number()),
        Span::call_site(),
    );
    let inner_generated_arm = generate_match_conditions_and_bindings(
        // Note: Recursive call to the main function
        &quote!(#lir_deref_inner_expr_ident.as_ref()),
        inner_pattern_expr.as_ref(),
        v3_path,
    )?;

    let inner_code = inner_generated_arm
        .as_ref()
        .map(|i| &i.match_bind_or_return);
    let match_bind_or_return = _quote_deref_match_code(
        target_path,
        v3_path,
        &lir_deref_inner_expr_ident,
        inner_code,
    );

    Ok(Some(GeneratedMatchArm {
        bound_var: inner_generated_arm
            .as_ref()
            .map(|i| i.bound_var.clone())
            .unwrap_or_default(),
        match_bind_or_return,
    }))
}

fn _handle_addressable_pattern(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    pattern_ssa_ref: &crate::dsl::PatternSsaMemoryReference,
) -> Result<Option<GeneratedMatchArm>> {
    match pattern_ssa_ref {
        crate::dsl::PatternSsaMemoryReference::Versioned(pattern_ve) => {
            _handle_addressable_versioned_pattern(target_path, v3_path, pattern_ve)
        }
        crate::dsl::PatternSsaMemoryReference::Deref(inner_pattern_expr) => {
            _handle_addressable_deref_pattern(target_path, v3_path, inner_pattern_expr)
        }
    }
}

fn _handle_unary_pattern(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    pattern_op: &crate::dsl::PatternUnaryOperator,
    pattern_arg: &Box<PatternExpression>,
) -> Result<Option<GeneratedMatchArm>> {
    let lir_unary_op_path = _path_lir_unary_op(v3_path);
    let lir_op_token = match pattern_op {
        crate::dsl::PatternUnaryOperator::Not => quote!(#lir_unary_op_path::Not),
        crate::dsl::PatternUnaryOperator::Minus => quote!(#lir_unary_op_path::Minus),
    };

    let lir_inner_expr_ident = Ident::new(
        &format!("__unary_inner_{}", generate_unique_number()),
        Span::call_site(),
    );
    let inner_generated_arm = generate_match_conditions_and_bindings(
        // Note: Recursive call
        &quote!(#lir_inner_expr_ident.as_ref()),
        pattern_arg.as_ref(),
        v3_path,
    )?;

    let inner_code = inner_generated_arm
        .as_ref()
        .map(|i| &i.match_bind_or_return);
    let match_bind_or_return = _quote_unary_match_code(
        target_path,
        v3_path,
        &lir_op_token,
        &lir_inner_expr_ident,
        inner_code,
    );

    Ok(Some(GeneratedMatchArm {
        bound_var: inner_generated_arm.map(|i| i.bound_var).unwrap_or_default(),
        match_bind_or_return,
    }))
}

fn _handle_binary_pattern(
    target_path: &TokenStream2,
    v3_path: &TokenStream2,
    pattern_op: &crate::dsl::PatternBinaryOperator,
    pattern_lhs: &Box<PatternExpression>,
    pattern_rhs: &Box<PatternExpression>,
) -> Result<Option<GeneratedMatchArm>> {
    let lir_binary_op_path = _path_lir_binary_op(v3_path);
    let lir_op_token = match pattern_op {
        crate::dsl::PatternBinaryOperator::Add => quote!(#lir_binary_op_path::Add),
        crate::dsl::PatternBinaryOperator::Sub => quote!(#lir_binary_op_path::Sub),
        crate::dsl::PatternBinaryOperator::Mul => quote!(#lir_binary_op_path::Mul),
        crate::dsl::PatternBinaryOperator::LessThan => quote!(#lir_binary_op_path::LessThan),
        crate::dsl::PatternBinaryOperator::LessThanOrEqual => {
            quote!(#lir_binary_op_path::LessThanOrEqual)
        }
        crate::dsl::PatternBinaryOperator::GreaterThan => quote!(#lir_binary_op_path::GreaterThan),
        crate::dsl::PatternBinaryOperator::GreaterThanOrEqual => {
            quote!(#lir_binary_op_path::GreaterThanOrEqual)
        }
        crate::dsl::PatternBinaryOperator::Equals => quote!(#lir_binary_op_path::Equals),
        crate::dsl::PatternBinaryOperator::NotEquals => quote!(#lir_binary_op_path::NotEquals),
    };

    let lir_lhs_ident = Ident::new(
        &format!("__binary_lir_lhs_{}", generate_unique_number()),
        Span::call_site(),
    );
    let lir_rhs_ident = Ident::new(
        &format!("__binary_lir_rhs_{}", generate_unique_number()),
        Span::call_site(),
    );

    let lhs_generated = generate_match_conditions_and_bindings(
        // Note: Recursive call
        &quote!(#lir_lhs_ident.as_ref()),
        pattern_lhs,
        v3_path,
    )?;
    let rhs_generated = generate_match_conditions_and_bindings(
        // Note: Recursive call
        &quote!(#lir_rhs_ident.as_ref()),
        pattern_rhs,
        v3_path,
    )?;

    let lhs_code = lhs_generated.as_ref().map(|i| &i.match_bind_or_return);
    let rhs_code = rhs_generated.as_ref().map(|i| &i.match_bind_or_return);

    let match_bind_or_return = _quote_binary_match_code(
        target_path,
        v3_path,
        &lir_op_token,
        &lir_lhs_ident,
        &lir_rhs_ident,
        lhs_code,
        rhs_code,
    );

    let mut bound_vars = lhs_generated.map(|i| i.bound_var).unwrap_or_default();
    bound_vars.extend(rhs_generated.map(|i| i.bound_var).unwrap_or_default());

    Ok(Some(GeneratedMatchArm {
        bound_var: bound_vars,
        match_bind_or_return,
    }))
}

fn generate_match_conditions_and_bindings(
    target_path: &TokenStream2, // Path to the current part of the target expression being matched
    pattern: &PatternExpression,
    v3_path: &TokenStream2,
) -> Result<Option<GeneratedMatchArm>> {
    match pattern {
        PatternExpression::Wildcard => Ok(None), // nothing to generate
        PatternExpression::Constant(pattern_lit) => {
            _handle_constant_pattern(target_path, v3_path, pattern_lit)
        }
        PatternExpression::Bind(var_bind) => _handle_bind_pattern(target_path, v3_path, var_bind),
        PatternExpression::Addressable(pattern_ssa_ref) => {
            _handle_addressable_pattern(target_path, v3_path, pattern_ssa_ref)
        }
        PatternExpression::Unary { op, arg } => {
            _handle_unary_pattern(target_path, v3_path, op, arg)
        }
        PatternExpression::Binary { op, lhs, rhs } => {
            _handle_binary_pattern(target_path, v3_path, op, lhs, rhs)
        }
    }
}

impl MatchDslInput {
    // Helper to create the arm-specific matching function (fn __dsl_match_XXX(...) -> Option<...>)
    // This function is generated for each arm that is not a simple wildcard.
    fn _create_arm_logic_fn(
        fn_ident_for_arm: &Ident,
        v3_path_token_stream: &TokenStream2,
        generated_arm_details: &GeneratedMatchArm,
        arm_input: &MatchArmInput, // Used for accessing the guard expression
    ) -> TokenStream2 {
        let GeneratedMatchArm {
            bound_var,
            match_bind_or_return,
        } = generated_arm_details;

        let types: Vec<_> = bound_var.iter().map(|(_, ty)| ty).collect();
        let vars: Vec<_> = bound_var.iter().map(|(var, _)| var).collect();

        let guard_condition = if let Some(guard_expr) = &arm_input.guard {
            quote! { #guard_expr }
        } else {
            quote! { true } // Default to true if no guard is present
        };

        // Use existing path helpers to construct type paths
        let ssa_mem_ref_type_path = _path_ssa_types_ssa_memory_reference(v3_path_token_stream);
        let lir_expr_path = _path_lir_expr(v3_path_token_stream);

        quote! {
            // Allow too_many_arguments because the number of bound variables (`vars`)
            // can be large, leading to a function signature with many tuple elements.
            #[allow(clippy::too_many_arguments)]
            fn #fn_ident_for_arm(expr: &#lir_expr_path<#ssa_mem_ref_type_path>) -> Option<(#(&#types),*)> {
                #match_bind_or_return // Code to match the pattern and bind initial variables
                if #guard_condition { // Then, check the guard
                    Some((#(#vars),*)) // If guard passes, return bound variables
                } else {
                    None // Guard failed
                }
            }
        }
    }

    // Helper to create the code that calls an arm-specific function and executes its body
    // e.g., if let Some((vars,...)) = __dsl_match_arm_fn_XXX(&__match_dsl_target) { /* arm body */ }
    fn _create_arm_fn_call_and_body(
        fn_ident_for_arm: &Ident,
        match_target_ident: &Ident, // The identifier for the expression being matched (e.g., `__match_dsl_target`)
        generated_arm_details: &GeneratedMatchArm,
        arm_input: &MatchArmInput, // Used for accessing the arm body expression
    ) -> TokenStream2 {
        let GeneratedMatchArm { bound_var, .. } = generated_arm_details;
        let vars: Vec<_> = bound_var.iter().map(|(var, _)| var).collect();
        let arm_body_expr = &arm_input.body;

        quote! {
            if let Some((#(#vars),*)) = #fn_ident_for_arm(#match_target_ident) {
                #arm_body_expr
            }
        }
    }

    // Helper for wildcard arms (those with a `_` pattern)
    // e.g., if guard_condition { /* arm body */ }
    fn _create_wildcard_arm_logic(arm_input: &MatchArmInput) -> TokenStream2 {
        let guard_condition = if let Some(guard_expr) = &arm_input.guard {
            quote! { #guard_expr }
        } else {
            quote! { true } // Default to true if no guard
        };
        let arm_body_expr = &arm_input.body;
        quote! {
            if #guard_condition { // Only check guard, as pattern is wildcard
                #arm_body_expr
            }
        }
    }

    // Helper to build the final if/else if/.../else { panic } chain
    fn _build_final_match_structure(
        arm_call_blocks: Vec<TokenStream2>, // Each block is an `if let ...` or `if guard ...`
        match_target_ident: &Ident,
    ) -> TokenStream2 {
        if arm_call_blocks.is_empty() {
            // This check is defensive. The parser should ensure at least one arm.
            return syn::Error::new(
                Span::call_site(),
                "match_dsl! macro (internal check): requires at least one arm.",
            )
            .to_compile_error();
        }

        let mut chained_code = quote! {};
        let mut is_first_arm_block = true;
        for arm_call_block in arm_call_blocks {
            if is_first_arm_block {
                chained_code = quote! { #arm_call_block };
                is_first_arm_block = false;
            } else {
                chained_code = quote! { #chained_code else #arm_call_block };
            }
        }

        // Append the final `else { panic! }` for non-exhaustive matches.
        quote! {
            #chained_code
            else {
                panic!("match_dsl! patterns not exhaustive for target: {:?}", #match_target_ident);
            }
        }
    }

    pub fn expanded(&self) -> TokenStream2 {
        let target_expr_to_match = &self.target_expr;
        // This identifier will hold the expression being matched against.
        let match_target_ident = Ident::new("__match_dsl_target", Span::call_site());

        // `v3_path()` is assumed to be a function in scope that returns the TokenStream2
        // for the root path of LIR/SSA types (e.g., `crate::lir_paths_v3`).
        let v3_path_token_stream = v3_path();

        let mut arm_helper_fns: Vec<TokenStream2> = Vec::new(); // Stores generated fn __dsl_match_arm_fn_XXX
        let mut arm_call_blocks: Vec<TokenStream2> = Vec::new(); // Stores `if let ...` blocks

        // The identifier `expr` is used as the parameter name within the generated helper functions
        // (e.g., `fn __dsl_match_arm_fn_XXX(expr: &LirExpr) -> ...`).
        let expr_param_in_helper_fn = quote!(expr);

        for arm_input in &self.arms {
            match generate_match_conditions_and_bindings(
                &expr_param_in_helper_fn, // Pass `expr` as the target for conditions inside helper
                &arm_input.pattern,
                &v3_path_token_stream,
            ) {
                Ok(Some(generated_arm_details)) => {
                    // This arm has a non-wildcard pattern that requires a helper function.
                    let fn_ident_for_arm = Ident::new(
                        &format!("__dsl_match_arm_fn_{}", generate_unique_number()),
                        Span::call_site(),
                    );

                    let helper_fn_code = Self::_create_arm_logic_fn(
                        &fn_ident_for_arm,
                        &v3_path_token_stream,
                        &generated_arm_details,
                        arm_input,
                    );
                    arm_helper_fns.push(helper_fn_code);

                    let arm_call_code = Self::_create_arm_fn_call_and_body(
                        &fn_ident_for_arm,
                        &match_target_ident, // Call helper with the actual expression being matched
                        &generated_arm_details,
                        arm_input,
                    );
                    arm_call_blocks.push(arm_call_code);
                }
                Ok(None) => {
                    // This arm is a wildcard `_ => ...`. No helper function needed, just guard + body.
                    let wildcard_logic = Self::_create_wildcard_arm_logic(arm_input);
                    arm_call_blocks.push(wildcard_logic);
                }
                Err(e) => {
                    // Propagate errors from arm generation as compile errors.
                    return e.to_compile_error();
                }
            }
        }

        let final_match_logic =
            Self::_build_final_match_structure(arm_call_blocks, &match_target_ident);

        // Assemble the final token stream.
        quote! {
            { // Outer block to scope the helper functions and `match_target_ident`.
                #(#arm_helper_fns)* // Define all arm-specific helper functions.

                // Assign the expression to be matched to our stable identifier.
                let #match_target_ident = &#target_expr_to_match;

                // The chain of if/else if calls to the helper functions.
                #final_match_logic
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module (match_dsl_parser)
    use crate::dsl::{PatternBinaryOperator, PatternUnaryOperator}; // DSL specific operators
    use crate::dsl::{
        PatternBindType, PatternBindVariable, PatternExpression, PatternSsaMemoryReference,
    };

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
                // Can check ve.kind and ve.version if LitInt had an easy way to get value
                // For now, this structural match is good.
                match &ve.kind {
                    crate::dsl::VersionedElementKind::Relative { offset, sign } => {
                        assert_eq!(offset.base10_digits(), "123");
                        assert_eq!(*sign, 1);
                    }
                    _ => panic!("Expected Relative kind, got {:?}", ve.kind),
                }
                assert_eq!(ve.version.base10_digits(), "45");
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
        let input_str = "my_var, _ => {println!(\"wildcard\");}";
        let parsed_dsl: MatchDslInput = syn::parse_str(input_str).unwrap();
        let generated_ts = parsed_dsl.expanded();
        assert!(!generated_ts.to_string().is_empty());
    }

    #[test]
    fn test_generated_code_constant() {
        let input_str = "another_var, 123 => {println!(\"constant_123\");}";
        let parsed_dsl: MatchDslInput = syn::parse_str(input_str).unwrap();
        let generated_ts = parsed_dsl.expanded();
        assert!(!generated_ts.to_string().is_empty());
    }
}
