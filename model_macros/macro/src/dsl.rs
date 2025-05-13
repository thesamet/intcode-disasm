extern crate proc_macro;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, token, Ident, LitInt, Result, Token,
}; // Use TokenStream2 from proc-macro2 for quote

fn lir_path() -> TokenStream2 {
    quote!(crate::disasm::v3::lir)
}

fn ssa_path() -> TokenStream2 {
    quote!(crate::disasm::v3::ssa)
}

// --- Parser for individual versioned elements: `[base_expr]_version_num` ---
// (VersionedElement struct and its impls remain unchanged)
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

enum ParsedAtom {
    MemoryRef(TokenStream2),     // Contains tokens for SsaMemoryReference
    SubExpression(TokenStream2), // Contains tokens for a parsed Expression
    Constant(TokenStream2),      // Contains tokens for a literal (e.g., LitInt)
}

fn parse_atom_internal(input: ParseStream) -> Result<ParsedAtom> {
    // Peek to see if it's a pattern that parse_ssa_memory_reference can handle
    if (input.peek(Token![*]) && input.peek2(token::Paren)) || input.peek(token::Bracket) {
        // Delegate to parse_ssa_memory_reference for *(expr) or [...]
        let ssa_mem_ref_tokens = parse_ssa_memory_reference(input)?;
        Ok(ParsedAtom::MemoryRef(ssa_mem_ref_tokens))
    } else if input.peek(token::Paren) {
        // Parenthesized Sub-Expression: (...)
        let content;
        syn::parenthesized!(content in input);
        let sub_expr_tokens = parse_addition_subtraction(&content)?; // Recursively parse, returns Expression
        Ok(ParsedAtom::SubExpression(sub_expr_tokens))
    } else if input.peek(LitInt) {
        // Constant Literal
        let lit: LitInt = input.parse()?;
        Ok(ParsedAtom::Constant(quote! { #lit }))
    } else {
        Err(input.error(
            "Expected an assignable memory location ('[base].version' or '*(expression)'), a parenthesized expression, or a constant literal",
        ))
    }
}

// --- NEW: Public atom parser, calls internal and wraps into Expression ---
fn parse_atom(input: ParseStream) -> Result<TokenStream2> {
    let cp = lir_path();
    match parse_atom_internal(input)? {
        ParsedAtom::MemoryRef(tokens) => Ok(quote! { #cp::Expression::Addressable(#tokens) }),
        ParsedAtom::SubExpression(tokens) => Ok(tokens),
        ParsedAtom::Constant(tokens) => Ok(quote! { #cp::Expression::Constant(#tokens) }),
    }
}

fn parse_addition_subtraction(input: ParseStream) -> Result<TokenStream2> {
    let mut lhs = parse_multiplication(input)?; // Higher precedence, calls new parse_atom -> returns Expression
    let cp = lir_path();

    while input.peek(Token![+]) || input.peek(Token![-]) {
        if input.peek(Token![+]) {
            let _op: Token![+] = input.parse()?;
            let rhs = parse_multiplication(input)?; // Returns Expression
                                                    // Construct Binary, operands are already Expressions, remove .into()
            lhs = quote! { #cp::Expression::Binary {
                op: #cp::BinaryOperator::Add,
                lhs: Box::new(#lhs),
                rhs: Box::new(#rhs)
            }};
        } else if input.peek(Token![-]) {
            let _op: Token![-] = input.parse()?;
            let rhs = parse_multiplication(input)?; // Returns Expression
                                                    // Construct Binary, operands are already Expressions, remove .into()
            lhs = quote! { #cp::Expression::Binary {
                op: #cp::BinaryOperator::Sub,
                lhs: Box::new(#lhs),
                rhs: Box::new(#rhs)
            }};
        }
    }
    Ok(lhs)
}

fn parse_multiplication(input: ParseStream) -> Result<TokenStream2> {
    let mut lhs = parse_atom(input)?; // Calls NEW parse_atom -> returns Expression
    let cp = lir_path();

    while input.peek(Token![*]) {
        let _op: Token![*] = input.parse()?;
        let rhs = parse_atom(input)?;
        lhs = quote! { #cp::Expression::Binary {
            op: #cp::BinaryOperator::Mul,
            lhs: Box::new(#lhs),
            rhs: Box::new(#rhs)
        }};
    }
    Ok(lhs)
}

// --- Full Expression Parser ---
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

// --- NEW: Parser for SsaMemoryReference (LHS of assignment) ---
// This parses specifically what can be an LHS: a VersionedElement or a Deref.
// It does NOT produce a full Expression, but rather the tokens for an SsaMemoryReference.
fn parse_ssa_memory_reference(input: ParseStream) -> Result<TokenStream2> {
    let ssa = ssa_path();

    if input.peek(Token![*]) && input.peek2(token::Paren) {
        // Dereference: *(expr)
        let _star: Token![*] = input.parse()?;
        let content;
        syn::parenthesized!(content in input);
        let inner_expr_tokens = parse_addition_subtraction(&content)?; // Inner part is a full expression
        Ok(quote! {
            #ssa::SsaMemoryReference::Deref(Box::new(#inner_expr_tokens))
        })
    } else if input.peek(token::Bracket) {
        // Versioned Memory Reference: [...]
        let version_atom: VersionedElement = input.parse()?;
        Ok(version_atom.to_expr_tokens()) // to_expr_tokens() returns SsaMemoryReference::Versioned(...)
    } else {
        Err(input
            .error("Expected an assignable memory location: '[base].version' or '*(expression)'"))
    }
}

// --- NEW: Struct to parse the Assign instruction ---
pub struct DslInstruction(pub TokenStream2);

impl Parse for DslInstruction {
    fn parse(input: ParseStream) -> Result<Self> {
        // 1. Parse LHS (SsaMemoryReference)
        let lhs_tokens = parse_ssa_memory_reference(input)?;

        // 2. Parse '='
        let _eq_token: Token![=] = input.parse()?;

        let rhs_tokens = parse_addition_subtraction(input)?;

        if !input.is_empty() {
            return Err(input.error("Unexpected tokens after assignment expression"));
        }
        let lir = lir_path();

        let instr = quote! {
            #lir::Instruction::Assign {
                target: #lhs_tokens,
                src: #rhs_tokens,
                target_debug_marker: None, // Defaulting to None for now
            }
        };
        let instr_node = quote! {
            #lir::InstructionNode {
                id: crate::disasm::v3::InstructionId::new(0),
                kind: #instr,
            }
        };

        Ok(DslInstruction(instr_node))
    }
}
