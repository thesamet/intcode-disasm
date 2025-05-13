extern crate proc_macro;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    token, Ident, LitInt, Result, Token,
};

// Bring in LIR operators for use in Pattern AST

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum PatternBinaryOperator {
    /// Addition operation (+).
    Add,
    /// Multiplication operation (*).
    Mul,
    /// Subtraction operation (-).
    Sub,
    /// Less than comparison (<).
    LessThan,
    /// Less than or equal comparison (<=).
    LessThanOrEqual,
    /// Greater than comparison (>).
    GreaterThan,
    /// Greater than or equal comparison (>=).
    GreaterThanOrEqual,
    /// Equality comparison (==).
    Equals,
    /// Inequality comparison (!=).
    NotEquals,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PatternUnaryOperator {
    /// Logical negation operation (!).
    Not,
    /// Arithmetic negation operation (-).
    Minus,
}

pub fn lir_path() -> TokenStream2 {
    quote!(crate::disasm::v3::lir)
}

pub fn ssa_path() -> TokenStream2 {
    quote!(crate::disasm::v3::ssa)
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub enum PatternMatchingAtom {
    Wildcard(),         // Represents '_'
    Expression(Ident),  // Represents $e:expr, or just $e (expr is the default)
    Addressable(Ident), // Represents $a:addr,  binds as a memory reference
    Literal(Ident),     // Represents $a:const binds as a constant literal.
}

// AST for Pattern Matching

// Represents the type of binding for a pattern variable (e.g., $v:expr, $v:addr, $v:const)
#[derive(Debug, Clone, Copy)]
pub enum PatternBindType {
    Expression,  // Binds as Expression<SsaMemoryReference>
    Addressable, // Binds as SsaMemoryReference
    Constant,    // Binds as a literal value (e.g., i128)
}

// Represents a variable binding in a pattern, e.g., $v:const
#[derive(Debug, Clone)]
pub struct PatternBindVariable {
    pub ident: Ident,
    pub bind_type: PatternBindType,
}

// AST node for patterns involving SsaMemoryReference-like structures
#[derive(Debug, Clone)]
pub enum PatternSsaMemoryReference {
    // For patterns like [R-3].3, where the structure is literal.
    // Reuses VersionedElement as it parses concrete values.
    Versioned(VersionedElement),
    // For patterns like *($pattern_expr) or *(ConcretePattern)
    Deref(Box<PatternExpression>),
}

// AST for representing a parsed pattern expression
#[derive(Debug, Clone)]
pub enum PatternExpression {
    Wildcard,                               // _
    Bind(PatternBindVariable),              // $v, $v:const, $v:addr
    Constant(LitInt),                       // e.g., 123
    Addressable(PatternSsaMemoryReference), // e.g., [R-3].3, *($pattern)
    Unary {
        op: PatternUnaryOperator, // Reusing from crate::disasm::v3::lir
        arg: Box<PatternExpression>,
    },
    Binary {
        op: PatternBinaryOperator, // Reusing from crate::disasm::v3::lir
        lhs: Box<PatternExpression>,
        rhs: Box<PatternExpression>,
    },
    // Potentially others like Tuple, Struct, if matching more complex structures
}

// End of AST for Pattern Matching

enum ParsedAtom {
    MemoryRef(TokenStream2),
    SubExpression(TokenStream2),
    Constant(TokenStream2),
    ExternalVar(Ident), // NEW: For #var
    PatternMatchingAtom(PatternMatchingAtom),
}

fn parse_pattern_matching_atom(input: ParseStream) -> Result<PatternMatchingAtom> {
    if input.peek(Ident) {
        let ident: Ident = input.parse()?;
        if ident == "_" {
            return Ok(PatternMatchingAtom::Wildcard());
        }
        Ok(PatternMatchingAtom::Expression(ident))
    } else if input.peek(Token![$]) {
        let _dollar_token: Token![$] = input.parse()?; // Consume '$'
        let var_ident: Ident = input.parse()?; // Parse the identifier (e.g., 'e', 'a')

        // Check for optional type specifier (:expr, :addr, :const)
        if input.peek(Token![:]) {
            let _colon_token: Token![:] = input.parse()?; // Consume ':'
            let type_specifier: Ident = input.parse()?; // Parse the type specifier (e.g., 'expr', 'addr', 'const')

            if type_specifier == "expr" {
                Ok(PatternMatchingAtom::Expression(var_ident))
            } else if type_specifier == "addr" {
                Ok(PatternMatchingAtom::Addressable(var_ident))
            } else if type_specifier == "const" {
                // Note: PatternMatchingAtom::Literal is defined as Literal(LitInt),
                // but the syntax $a:const implies binding the identifier 'a'.
                // Based on the prompt and other variants, we assume the intent
                // is to store the identifier. This might require adjusting
                // PatternMatchingAtom::Literal's type elsewhere if Literal(LitInt)
                // was strictly intended for direct literal values.
                Ok(PatternMatchingAtom::Literal(var_ident))
            } else {
                Err(input.error(format!("Unknown pattern matching atom type specifier: `{}`. Expected `expr`, `addr`, or `const`", type_specifier)))
            }
        } else {
            // No type specifier, default is :expr
            Ok(PatternMatchingAtom::Expression(var_ident))
        }
    } else {
        Err(input.error(
            "Expected #var, assignable memory location ('[base].version' or '*(expression)'), a parenthesized expression, or a constant literal",
        ))
    }
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
        let sub_expr_tokens = parse_expr(&content)?; // Recursively parse, returns Expression
        Ok(ParsedAtom::SubExpression(sub_expr_tokens))
    } else if input.peek(LitInt) {
        // Constant Literal
        let lit: LitInt = input.parse()?;
        Ok(ParsedAtom::Constant(quote! { #lit }))
    } else if input.peek(Token![$]) {
        let pma = parse_pattern_matching_atom(input)?;
        Ok(ParsedAtom::PatternMatchingAtom(pma))
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
        ParsedAtom::PatternMatchingAtom(pattern_matching_atom) => todo!(),
    }
}

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

fn parse_expr(input: ParseStream) -> Result<TokenStream2> {
    parse_addition_subtraction(input)
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

pub struct FullExprParse(pub TokenStream2);

impl Parse for FullExprParse {
    fn parse(input: ParseStream) -> Result<Self> {
        let result = parse_expr(input)?;
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
        let inner_expr_tokens = parse_expr(&content)?;
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
                let expr_tokens = parse_expr(input)?;
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
            let rhs_tokens = parse_expr(input)?;
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
