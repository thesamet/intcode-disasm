extern crate proc_macro;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    token, Ident, LitInt, Result, Token,
};

pub fn lir_path() -> TokenStream2 {
    quote!(crate::disasm::v3::lir)
}

pub fn ssa_path() -> TokenStream2 {
    quote!(crate::disasm::v3::ssa)
}

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
                let offset_result = content.parse::<LitInt>();
                match offset_result {
                    Ok(offset) => (1, offset, false),
                    Err(_) => {
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
        let ssa = ssa_path();
        let kind = if self.is_relative {
            quote!(#ssa::types::VersionableMemoryKind::RelativeMemory(#offset * #sign))
        } else {
            quote!(#ssa::types::VersionableMemoryKind::Memory(#offset))
        };
        quote! {
            #ssa::SsaMemoryReference::Versioned(#ssa::VersionedMemoryReference::new(
                #kind,
                crate::disasm::v3::FunctionId::new(0),
                #ver,
            ))
        }
    }
}

enum ParsedAtom {
    MemoryRef(TokenStream2),
    SubExpression(TokenStream2),
    Constant(TokenStream2),
    ExternalVar(Ident), // NEW: For #var
}

fn parse_atom_internal(input: ParseStream) -> Result<ParsedAtom> {
    if input.peek(Token![#]) {
        // Check for '#'
        let _hash_token: Token![#] = input.parse()?; // Consume '#'
        let var_ident: Ident = input.parse()?; // Parse the identifier
        Ok(ParsedAtom::ExternalVar(var_ident))
    } else if (input.peek(Token![*]) && input.peek2(token::Paren)) || input.peek(token::Bracket) {
        // Delegate to parse_ssa_memory_reference for *(expr) or [...]
        let ssa_mem_ref_tokens = parse_ssa_memory_reference(input)?;
        Ok(ParsedAtom::MemoryRef(ssa_mem_ref_tokens))
    } else if input.peek(token::Paren) {
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
            "Expected #var, assignable memory location ('[base].version' or '*(expression)'), a parenthesized expression, or a constant literal",
        ))
    }
}

fn parse_atom(input: ParseStream) -> Result<TokenStream2> {
    let cp = lir_path(); // cp stands for crate_path, used for Expression variants
    match parse_atom_internal(input)? {
        ParsedAtom::MemoryRef(tokens) => {
            // Wrap SsaMemoryReference in Expression::Addressable
            Ok(quote! { #cp::Expression::Addressable(#tokens) })
        }
        ParsedAtom::SubExpression(tokens) => {
            // Already an Expression (came from parenthesized expression), return as is
            Ok(tokens)
        }
        ParsedAtom::Constant(tokens) => {
            // Wrap literal in Expression::Constant
            Ok(quote! { #cp::Expression::Constant(#tokens) })
        }
        ParsedAtom::ExternalVar(ident) => {
            // The ident is the Rust variable name. It's assumed to be in scope
            // and of a type compatible with Expression<SsaMemoryReference>.
            // If 'ident' is already an Expression, this will directly interpolate it.
            Ok(quote! { #ident })
        }
    }
}

// --- NEW: Parser for Unary Operations ---
// Handles expressions like -term, !term
fn parse_unary(input: ParseStream) -> Result<TokenStream2> {
    let cp = lir_path();
    if input.peek(Token![-]) {
        // Check for negation
        let _op: Token![-] = input.parse()?; // Consume '-'
        let arg = parse_unary(input)?; // Recursively parse the operand (allows --x or -!(y))
        Ok(quote! {
            #cp::Expression::Unary {
                op: #cp::UnaryOperator::Minus,
                arg: Box::new(#arg)
            }
        })
    } else if input.peek(Token![!]) {
        // Check for logical NOT
        let _op: Token![!] = input.parse()?; // Consume '!'
        let arg = parse_unary(input)?; // Recursively parse the operand
        Ok(quote! {
            #cp::Expression::Unary {
                op: #cp::UnaryOperator::Not,
                arg: Box::new(#arg)
            }
        })
    } else {
        // If no unary operator, parse an atom (which includes parenthesized expressions, literals, #vars, memory refs)
        parse_atom(input)
    }
}

fn parse_addition_subtraction(input: ParseStream) -> Result<TokenStream2> {
    let mut lhs = parse_multiplication(input)?;
    let cp = lir_path();
    while input.peek(Token![+]) || input.peek(Token![-]) {
        if input.peek(Token![+]) {
            let _op: Token![+] = input.parse()?;
            let rhs = parse_multiplication(input)?;
            lhs = quote! { #cp::Expression::Binary {
                op: #cp::BinaryOperator::Add,
                lhs: Box::new(#lhs),
                rhs: Box::new(#rhs)
            }};
        } else if input.peek(Token![-]) {
            // This '-' is for binary subtraction. Unary minus is handled by parse_unary.
            let _op: Token![-] = input.parse()?;
            let rhs = parse_multiplication(input)?; // This call chain now includes unary
            lhs = quote! { #cp::Expression::Binary {
                op: #cp::BinaryOperator::Sub,
                lhs: Box::new(#lhs),
                rhs: Box::new(#rhs)
            }};
        }
    }
    Ok(lhs)
}

// --- MODIFIED: parse_multiplication ---
// Now calls parse_unary instead of parse_atom for its operands
fn parse_multiplication(input: ParseStream) -> Result<TokenStream2> {
    let mut lhs = parse_unary(input)?; // MODIFIED: Call parse_unary for higher precedence
    let cp = lir_path();
    while input.peek(Token![*]) {
        let _op: Token![*] = input.parse()?;
        let rhs = parse_unary(input)?; // MODIFIED: Call parse_unary for higher precedence
        lhs = quote! { #cp::Expression::Binary {
            op: #cp::BinaryOperator::Mul,
            lhs: Box::new(#lhs),
            rhs: Box::new(#rhs)
        }};
    }
    Ok(lhs)
}

// --- Full Expression Parser (for build_expr!) ---

pub struct FullExprParse(pub TokenStream2); // Renamed from FullExpr to avoid conflict if used elsewhere

impl Parse for FullExprParse {
    fn parse(input: ParseStream) -> Result<Self> {
        let result = parse_addition_subtraction(input)?;
        if !input.is_empty() {
            return Err(input.error("Unexpected tokens after expression"));
        }
        Ok(FullExprParse(result))
    }
}

// --- Parser for SsaMemoryReference (LHS of assignment) ---
fn parse_ssa_memory_reference(input: ParseStream) -> Result<TokenStream2> {
    let ssa = ssa_path();
    if input.peek(Token![*]) && input.peek2(token::Paren) {
        let _star: Token![*] = input.parse()?;
        let content;
        syn::parenthesized!(content in input);
        let inner_expr_tokens = parse_addition_subtraction(&content)?;
        Ok(quote! {
            #ssa::SsaMemoryReference::Deref(Box::new(#inner_expr_tokens))
        })
    } else if input.peek(token::Bracket) {
        let version_atom: VersionedElement = input.parse()?;
        Ok(version_atom.to_expr_tokens())
    } else {
        Err(input
            .error("Expected an assignable memory location: '[base].version' or '*(expression)'"))
    }
}

// --- Instruction Parsing Logic ---
pub enum DslInstructionKind {
    Assign {
        lhs_tokens: TokenStream2,
        rhs_tokens: TokenStream2,
    },
    Output {
        expr_tokens: TokenStream2,
    },
}

pub struct DslInstructionParse {
    kind: DslInstructionKind,
}

impl DslInstructionParse {
    pub fn to_tokens(&self) -> TokenStream2 {
        let lir = lir_path();

        let instruction_variant_tokens = match &self.kind {
            DslInstructionKind::Assign {
                lhs_tokens,
                rhs_tokens,
            } => {
                quote! {
                    #lir::Instruction::Assign {
                        target: #lhs_tokens,
                        src: #rhs_tokens,
                        target_debug_marker: None,
                    }
                }
            }
            DslInstructionKind::Output { expr_tokens } => {
                quote! {
                    #lir::Instruction::Output(#expr_tokens)
                }
            }
        };

        quote! {
            #lir::InstructionNode {
                id: crate::disasm::v3::InstructionId::new(0),
                kind: #instruction_variant_tokens,
            }
        }
    }
}

impl Parse for DslInstructionParse {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(Ident) {
            let keyword_ident: Ident = input.fork().parse()?;
            if keyword_ident == "output" {
                let _keyword: Ident = input.parse()?;
                let expr_tokens = parse_addition_subtraction(input)?;
                if !input.is_empty() {
                    return Err(input.error("Unexpected tokens after output expression"));
                }
                return Ok(DslInstructionParse {
                    kind: DslInstructionKind::Output { expr_tokens },
                });
            }
        }

        let lhs_tokens = parse_ssa_memory_reference(input)?;
        if input.peek(Token![=]) {
            let _eq_token: Token![=] = input.parse()?;
            let rhs_tokens = parse_addition_subtraction(input)?;
            if !input.is_empty() {
                return Err(input.error("Unexpected tokens after assignment expression"));
            }
            Ok(DslInstructionParse {
                kind: DslInstructionKind::Assign {
                    lhs_tokens,
                    rhs_tokens,
                },
            })
        } else {
            Err(input.error("Expected '=' for assignment, or a supported instruction keyword (e.g., 'output <expr>')"))
        }
    }
}
