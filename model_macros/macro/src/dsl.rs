extern crate proc_macro;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, token, Expr, Ident, LitInt, Token,
}; // Use TokenStream2 from proc-macro2 for quote

// Helper to get the crate path for generated code, assuming your types are in the root
// or a known module of the calling crate. For robust macros, this path might need
// to be configurable or discovered.
fn lir_path() -> TokenStream2 {
    // If your types (Expression, VersionedVar, RelativeVar, R) are in the crate root:
    quote!(crate::v3::lir)
    // If they are in a module `my_types`: quote!(crate::my_types)
    // For a generic macro, you might use ::my_crate_name if types are re-exported.
}

fn ssa_path() -> TokenStream2 {
    // If your types (Expression, VersionedVar, RelativeVar, R) are in the crate root:
    quote!(crate::disasm::v3::ssa)
    // If they are in a module `my_types`: quote!(crate::my_types)
    // For a generic macro, you might use ::my_crate_name if types are re-exported.
}

// --- Parser for individual versioned elements: `[base_expr]_version_num` ---
pub struct VersionedRelativeMemory {
    sign: i128,
    offset: LitInt,
    version: LitInt,
}

impl Parse for VersionedRelativeMemory {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        syn::bracketed!(content in input);
        let r: Ident = content.parse()?;
        if r != "R" {
            return Err(content.error("Expected `R` as the base memory"));
        }
        let sign: i128 = content
            .parse::<token::Plus>()
            .map(|_| 1)
            .or_else(|_| content.parse::<token::Minus>().map(|_| -1))
            .map_err(|_| content.error("Expected `+` or `-` sign"))?;
        let offset = content.parse::<LitInt>()?;
        let _dot: token::Dot = input.parse()?;
        let version: LitInt = input.parse()?;
        Ok(VersionedRelativeMemory {
            sign,
            offset,
            version,
        })
    }
}

impl VersionedRelativeMemory {
    pub fn to_expr_tokens(&self) -> TokenStream2 {
        let offset = &self.offset;
        let ver = &self.version;
        let sign = &self.sign;
        let ssa = ssa_path(); // Path to where Expression, VersionedVar etc. are defined
        println!("ssa: {}", ssa);

        // This assumes that `base` (e.g., `R-5`) when evaluated will result in a `RelativeVar`.
        // And that `VersionedVar` and `Expression::VersionedThing` are accessible via `cp`.
        quote! {
            #ssa::SsaMemoryReference::Versioned(#ssa::VersionedMemoryReference::new(
                VersionableMemoryKind::RelativeMemory(#offset * #sign),
                FunctionId::new(0),
                #ver,
            ))
        }
    }
}

// --- Recursive Descent Parser for Expressions ---

/*
// Parses atoms: `[expr]_version`, `(expr)`, or potentially other literals/variables later
fn parse_atom(input: ParseStream) -> Result<TokenStream2> {
    if input.peek(token::Bracket) {
        // Check for `[`
        let version_atom: VersionAtomInput = input.parse()?;
        Ok(version_atom.to_expr_tokens())
    } else if input.peek(token::Paren) {
        // Check for `(`
        let content;
        syn::parenthesized!(content in input);
        parse_addition_subtraction(&content) // Recursively parse expression inside parens
    } else {
        Err(input.error(
            "Expected a versioned element like '[expr]_version' or a parenthesized expression",
        ))
    }
}

// Parses multiplicative expressions: atom (`*` atom)*
fn parse_multiplication(input: ParseStream) -> Result<TokenStream2> {
    let mut lhs = parse_atom(input)?;
    let cp = lir_path();

    while input.peek(Token![*]) {
        let _op: Token![*] = input.parse()?;
        let rhs = parse_atom(input)?;
        lhs = quote! { #cp::Expression::Mul(Box::new(#lhs), Box::new(#rhs)) };
    }
    Ok(lhs)
}

// Parses additive/subtractive expressions: term (`+` term | `-` term)*
fn parse_addition_subtraction(input: ParseStream) -> Result<TokenStream2> {
    let mut lhs = parse_multiplication(input)?; // Higher precedence
    let cp = lir_path();

    while input.peek(Token![+]) || input.peek(Token![-]) {
        if input.peek(Token![+]) {
            let _op: Token![+] = input.parse()?;
            let rhs = parse_multiplication(input)?;
            lhs = quote! { #cp::Expression::Add(Box::new(#lhs), Box::new(#rhs)) };
        } else if input.peek(Token![-]) {
            let _op: Token![-] = input.parse()?;
            let rhs = parse_multiplication(input)?;
            lhs = quote! { #cp::Expression::Sub(Box::new(#lhs), Box::new(#rhs)) };
        }
    }
    Ok(lhs)
}
*/

// Top-level parser for the macro input
/*
struct FullExpressionParser;

impl Parse for FullExpressionParser {
    fn parse(input: ParseStream) -> Result<FullExpressionParser> {
        let result = parse_addition_subtraction(input)?;
        if !input.is_empty() {
            return Err(input.error("Unexpected tokens after expression"));
        }
        Ok(result)
    }
}
*/
