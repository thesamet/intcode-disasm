extern crate proc_macro;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, token, Expr, Ident, LitInt, Result, Token,
}; // Use TokenStream2 from proc-macro2 for quote

// Helper to get the crate path for generated code, assuming your types are in the root
// or a known module of the calling crate. For robust macros, this path might need
// to be configurable or discovered.
fn lir_path() -> TokenStream2 {
    // If your types (Expression, VersionedVar, RelativeVar, R) are in the crate root:
    quote!(crate::disasm::v3::lir)
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
pub struct VersionedElement {
    sign: i128,
    offset: LitInt,
    version: LitInt,
    is_relative: bool,
}

impl Parse for VersionedElement {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        syn::bracketed!(content in input);

        // Attempt to parse as an identifier first
        let first_ident_result = content.parse::<Ident>();

        let (sign, offset, is_relative) = match first_ident_result {
            Ok(first) if first == "R" => {
                let sign: i128 = content
                    .parse::<token::Plus>()
                    .map(|_| 1)
                    .or_else(|_| content.parse::<token::Minus>().map(|_| -1))
                    .map_err(|_| content.error("Expected `+` or `-` sign"))?;
                let offset = content.parse::<LitInt>()?;
                (sign, offset, true)
            }
            _ => {
                // If not an identifier or not "R", try parsing as a literal integer
                let offset_result = content.parse::<LitInt>();
                match offset_result {
                    Ok(offset) => (1, offset, false),
                    Err(_) => {
                        // If parsing as LitInt fails, attempt to parse as identifier and convert to i128
                        let first = first_ident_result?;
                        let offset = first
                            .to_string()
                            .parse::<i128>()
                            .map_err(|_| content.error("Expected `R` or a number"))?;
                        let offset =
                            LitInt::new(&offset.to_string(), proc_macro2::Span::call_site());
                        (1, offset, false)
                    }
                }
            }
        };

        let _dot: token::Dot = input.parse()?;
        let version: LitInt = input.parse()?;

        Ok(VersionedElement {
            sign,
            offset,
            version,
            is_relative,
        })
    }
}

impl VersionedElement {
    pub fn to_expr_tokens(&self) -> TokenStream2 {
        let offset = &self.offset;
        let ver = &self.version;
        let sign = &self.sign;
        let ssa = ssa_path(); // Path to where Expression, VersionedVar etc. are defined

        // This assumes that `base` (e.g., `R-5`) when evaluated will result in a `RelativeVar`.
        // And that `VersionedVar` and `Expression::VersionedThing` are accessible via `cp`.
        let kind = if self.is_relative {
            quote!(#ssa::types::VersionableMemoryKind::RelativeMemory(#offset * #sign))
        } else {
            quote!(#ssa::types::VersionableMemoryKind::Memory(#offset))
        };
        quote! {
            #ssa::SsaMemoryReference::Versioned(#ssa::VersionedMemoryReference::new(
                #kind,
                FunctionId::new(0),
                #ver,
            ))
        }
    }
}

// Parses additive/subtractive expressions: term (`+` term | `-` term)*
fn parse_addition_subtraction(input: ParseStream) -> Result<TokenStream2> {
    let mut lhs = parse_multiplication(input)?; // Higher precedence
    let cp = lir_path();

    while input.peek(Token![+]) || input.peek(Token![-]) {
        if input.peek(Token![+]) {
            let _op: Token![+] = input.parse()?;
            let rhs = parse_multiplication(input)?;
            lhs = quote! { #cp::Expression::Binary {
            op: #cp::BinaryOperator::Add,
            lhs: Box::new(#lhs.into()),
            rhs: Box::new(#rhs.into()) }};
        } else if input.peek(Token![-]) {
            let _op: Token![-] = input.parse()?;
            let rhs = parse_multiplication(input)?;
            lhs = quote! { #cp::Expression::Binary { op: #cp::BinaryOperator::Sub, lhs: Box::new(#lhs.into()), rhs: Box::new(#rhs.into()) }};
        }
    }
    Ok(lhs)
}

fn parse_multiplication(input: ParseStream) -> Result<TokenStream2> {
    let mut lhs = parse_atom(input)?;
    let cp = lir_path();

    while input.peek(Token![*]) {
        let _op: Token![*] = input.parse()?;
        let rhs = parse_atom(input)?;
        lhs = quote! { #cp::Expression::Binary { op: #cp::BinaryOperator::Mul, lhs: Box::new(#lhs.into()), rhs: Box::new(#rhs.into()) }};
    }
    Ok(lhs)
}

fn parse_atom(input: ParseStream) -> Result<TokenStream2> {
    if input.peek(token::Bracket) {
        // Check for `[`
        let version_atom: VersionedElement = input.parse()?;
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

pub struct FullExpr(pub TokenStream2);

impl Parse for FullExpr {
    fn parse(input: ParseStream) -> Result<Self> {
        let result = parse_addition_subtraction(input)?;
        if !input.is_empty() {
            return Err(input.error("Unexpected tokens after expression"));
        }
        Ok(FullExpr(result))
    }
}

// --- Recursive Descent Parser for Expressions ---

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
