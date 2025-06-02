extern crate proc_macro;
use proc_macro2::{Span, TokenStream as TokenStream2};
use proc_macro_crate::FoundCrate;
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

pub fn v3_path() -> TokenStream2 {
    match proc_macro_crate::crate_name("disasm").expect("Could not find disasm crate") {
        FoundCrate::Itself => quote!(crate::disasm::v3),
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            quote!(#ident::disasm::v3)
        }
    }
}

#[derive(Debug, Clone)]
pub enum VersionedElementKind {
    Absolute(LitInt),
    Relative { offset: LitInt },
    Pointer(LitInt),
}

#[derive(Debug, Clone)]
pub struct VersionedElement {
    pub kind: VersionedElementKind,
    pub version: LitInt,
}

impl Parse for VersionedElement {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        syn::bracketed!(content in input);
        let first_ident_result = content.parse::<Ident>();

        let kind = match first_ident_result {
            Ok(first) if first == "R" => {
                // Parse relative memory reference [R+/-offset]
                if content.peek(Token![+]) {
                    content.parse::<Token![+]>()?;
                }
                let offset = content.parse::<LitInt>()?;
                VersionedElementKind::Relative { offset }
            }
            Ok(first) if first == "P" => {
                // Parse pointer reference [P<id>]
                let id = content.parse::<LitInt>()?;
                VersionedElementKind::Pointer(id)
            }
            _ => {
                // Parse absolute memory reference [<addr>]
                let offset_result = content.parse::<LitInt>();
                match offset_result {
                    Ok(offset) => VersionedElementKind::Absolute(offset),
                    Err(_) => {
                        let first = first_ident_result?;
                        return Err(
                            content.error(format!("Expected `R`, `P`, or a number, got {}", first))
                        );
                    }
                }
            }
        };

        let _dot: token::Dot = input.parse()?;
        let version: LitInt = input.parse()?;

        Ok(VersionedElement { kind, version })
    }
}

impl VersionedElement {
    pub fn to_expr_tokens(&self) -> TokenStream2 {
        let ver = &self.version;
        let v3_path = v3_path();

        let kind = match &self.kind {
            VersionedElementKind::Absolute(offset) => {
                quote!(#v3_path::ssa::types::VersionableMemoryKind::Memory(#offset))
            }
            VersionedElementKind::Relative { offset } => {
                quote!(#v3_path::ssa::types::VersionableMemoryKind::RelativeMemory(#offset))
            }
            VersionedElementKind::Pointer(id) => {
                quote!(#v3_path::ssa::types::VersionableMemoryKind::Pointer(#v3_path::PointerId::new(#id)))
            }
        };

        quote! {
            #v3_path::ssa::SsaMemoryReference::Versioned(#v3_path::ssa::VersionedMemoryReference::new(
                #kind,
                #v3_path::FunctionId::new(0),
                #ver,
            ))
        }
    }
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

// Custom keywords for parsing $var:type syntax
mod kw {
    syn::custom_keyword!(expr);
    syn::custom_keyword!(addr);
}

// --- Generic Parsing Infrastructure ---

// Trait to define the behavior for a specific parsing strategy (LIR or Pattern)
pub trait ParseStrategy {
    // The output type of the parser for this strategy (e.g., TokenStream2 or PatternExpression)
    type Output;
    // The type for unary operators for this strategy (e.g., TokenStream2 for LIR, PatternUnaryOperator for patterns)
    type UnaryOpType;
    // The type for binary operators for this strategy (e.g., TokenStream2 for LIR, PatternBinaryOperator for patterns)
    type BinaryOpType;

    // Parses the most basic elements (atoms, literals, parenthesized expressions for this strategy)
    fn parse_atom(&self, input: ParseStream) -> Result<Self::Output>;

    // Constructs a unary expression node
    fn build_unary(&self, op: Self::UnaryOpType, arg: Self::Output) -> Result<Self::Output>;

    // Constructs a binary expression node
    fn build_binary(
        &self,
        op: Self::BinaryOpType,
        lhs: Self::Output,
        rhs: Self::Output,
    ) -> Result<Self::Output>;

    // Specific Unary Operators for this strategy
    fn get_unary_minus_op(&self) -> Self::UnaryOpType;
    fn get_unary_not_op(&self) -> Self::UnaryOpType;

    // Specific Binary Operators for this strategy
    fn get_binary_add_op(&self) -> Self::BinaryOpType;
    fn get_binary_sub_op(&self) -> Self::BinaryOpType;
    fn get_binary_mul_op(&self) -> Self::BinaryOpType;
    fn get_binary_less_than_op(&self) -> Self::BinaryOpType;
    fn get_binary_less_than_or_equal_op(&self) -> Self::BinaryOpType;
    fn get_binary_greater_than_op(&self) -> Self::BinaryOpType;
    fn get_binary_greater_than_or_equal_op(&self) -> Self::BinaryOpType;
    fn get_binary_equals_op(&self) -> Self::BinaryOpType;
    fn get_binary_not_equals_op(&self) -> Self::BinaryOpType;
}

pub struct LirParseStrategy;

impl ParseStrategy for LirParseStrategy {
    type Output = TokenStream2;
    type UnaryOpType = TokenStream2; // Will be quote!(crate::disasm::v3::lir::UnaryOperator::Minus), etc.
    type BinaryOpType = TokenStream2; // Will be quote!(crate::disasm::v3::lir::BinaryOperator::Add), etc.

    fn parse_atom(&self, input: ParseStream) -> Result<Self::Output> {
        // Calls the original `parse_atom` function that produces TokenStream2 for LIR expressions
        parse_atom(input)
    }

    fn build_unary(
        &self,
        op_variant: Self::UnaryOpType,
        arg: Self::Output,
    ) -> Result<Self::Output> {
        let cp = v3_path();
        Ok(quote! {
            #cp::lir::Expression::Unary {
                op: #op_variant,
                arg: Box::new(#arg)
            }
        })
    }

    fn build_binary(
        &self,
        op_variant: Self::BinaryOpType,
        lhs: Self::Output,
        rhs: Self::Output,
    ) -> Result<Self::Output> {
        let cp = v3_path();
        Ok(quote! { #cp::lir::Expression::Binary {
            op: #op_variant,
            lhs: Box::new(#lhs),
            rhs: Box::new(#rhs)
        }})
    }

    fn get_unary_minus_op(&self) -> Self::UnaryOpType {
        let cp = v3_path();
        quote!(#cp::lir::UnaryOperator::Minus)
    }
    fn get_unary_not_op(&self) -> Self::UnaryOpType {
        let cp = v3_path();
        quote!(#cp::lir::UnaryOperator::Not)
    }
    fn get_binary_add_op(&self) -> Self::BinaryOpType {
        let cp = v3_path();

        quote!(#cp::lir::BinaryOperator::Add)
    }
    fn get_binary_sub_op(&self) -> Self::BinaryOpType {
        let cp = v3_path();
        quote!(#cp::lir::BinaryOperator::Sub)
    }
    fn get_binary_mul_op(&self) -> Self::BinaryOpType {
        let cp = v3_path();
        quote!(#cp::lir::BinaryOperator::Mul)
    }
    fn get_binary_less_than_op(&self) -> Self::BinaryOpType {
        let cp = v3_path();
        quote!(#cp::lir::BinaryOperator::LessThan)
    }
    fn get_binary_less_than_or_equal_op(&self) -> Self::BinaryOpType {
        let cp = v3_path();
        quote!(#cp::lir::BinaryOperator::LessThanOrEqual)
    }
    fn get_binary_greater_than_op(&self) -> Self::BinaryOpType {
        let cp = v3_path();
        quote!(#cp::lir::BinaryOperator::GreaterThan)
    }
    fn get_binary_greater_than_or_equal_op(&self) -> Self::BinaryOpType {
        let cp = v3_path();
        quote!(#cp::lir::BinaryOperator::GreaterThanOrEqual)
    }
    fn get_binary_equals_op(&self) -> Self::BinaryOpType {
        let cp = v3_path();
        quote!(#cp::lir::BinaryOperator::Equals)
    }
    fn get_binary_not_equals_op(&self) -> Self::BinaryOpType {
        let cp = v3_path();
        quote!(#cp::lir::BinaryOperator::NotEquals)
    }
}

// --- End of Generic Parsing Infrastructure ---

// --- Pattern Parsing Specifics ---

// Parses specific SsaMemoryReference-like patterns: [R+X].Y or *(PatternExpression)
fn parse_pattern_ssa_memory_reference(input: ParseStream) -> Result<PatternSsaMemoryReference> {
    if input.peek(Token![*]) && input.peek2(token::Paren) {
        let _star: Token![*] = input.parse()?;
        let content;
        syn::parenthesized!(content in input);
        // Inside the parentheses, we expect another pattern expression.
        // We use the generic parser with the PatternParseStrategy.
        let inner_pattern_expr = parse_expr_generic(&content, &PatternParseStrategy)?;
        Ok(PatternSsaMemoryReference::Deref(Box::new(
            inner_pattern_expr,
        )))
    } else if input.peek(token::Bracket) {
        // Parses concrete [R+X].Y or [OFFSET].VER
        let ve: VersionedElement = input.parse()?;
        Ok(PatternSsaMemoryReference::Versioned(ve))
    } else {
        Err(input.error(
            "Expected pattern for memory location: '[base].version' or '*(pattern_expression)'",
        ))
    }
}

// Parses an \"atom\" for a pattern expression.
// This includes wildcards, bind variables, literals, memory patterns, and parenthesized patterns.
fn parse_pattern_atom_internal(input: ParseStream) -> Result<PatternExpression> {
    let lookahead = input.lookahead1();

    if lookahead.peek(Token![$]) {
        // This is $var, $var:type
        return parse_pattern_matching_atom(input);
    }

    // Check for wildcard '_' specifically *before* checking for general Ident.
    // Token![_] is a specific token, distinct from a generic Ident for parsing purposes here.
    if lookahead.peek(Token![_]) {
        input.parse::<Token![_]>()?; // Consume '_'
        return Ok(PatternExpression::Wildcard);
    }

    // If not '$' or '_', then check for other pattern atom forms.
    // Order matters: `[...]` and `*(...)` should be checked before `LitInt` or `Ident` if there's ambiguity.
    if (input.peek(Token![*]) && input.peek2(token::Paren)) || input.peek(token::Bracket) {
        // This is for [R+X].Y or *(PatternExpression)
        let pattern_mem_ref = parse_pattern_ssa_memory_reference(input)?;
        return Ok(PatternExpression::Addressable(pattern_mem_ref));
    }

    if input.peek(token::Paren) {
        let content;
        syn::parenthesized!(content in input);
        // Recursively parse the inner expression as a pattern
        let strategy = PatternParseStrategy;
        parse_expr_generic(&content, &strategy)
    } else if input.peek(LitInt) {
        let lit: LitInt = input.parse()?;
        Ok(PatternExpression::Constant(lit))
    } else {
        Err(input.error(
            "Expected a pattern atom: '$var', '_', memory location pattern, (pattern_expression), or constant literal",
        ))
    }
}

pub struct PatternParseStrategy;

impl ParseStrategy for PatternParseStrategy {
    type Output = PatternExpression;
    type UnaryOpType = PatternUnaryOperator; // Using the one defined in this file
    type BinaryOpType = PatternBinaryOperator; // Using the one defined in this file

    fn parse_atom(&self, input: ParseStream) -> Result<Self::Output> {
        parse_pattern_atom_internal(input)
    }

    fn build_unary(&self, op: Self::UnaryOpType, arg: Self::Output) -> Result<Self::Output> {
        Ok(PatternExpression::Unary {
            op, // op is already PatternUnaryOperator
            arg: Box::new(arg),
        })
    }

    fn build_binary(
        &self,
        op: Self::BinaryOpType,
        lhs: Self::Output,
        rhs: Self::Output,
    ) -> Result<Self::Output> {
        Ok(PatternExpression::Binary {
            op, // op is already PatternBinaryOperator
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        })
    }

    fn get_unary_minus_op(&self) -> Self::UnaryOpType {
        PatternUnaryOperator::Minus
    }
    fn get_unary_not_op(&self) -> Self::UnaryOpType {
        PatternUnaryOperator::Not
    }
    fn get_binary_add_op(&self) -> Self::BinaryOpType {
        PatternBinaryOperator::Add
    }
    fn get_binary_sub_op(&self) -> Self::BinaryOpType {
        PatternBinaryOperator::Sub
    }
    fn get_binary_mul_op(&self) -> Self::BinaryOpType {
        PatternBinaryOperator::Mul
    }
    fn get_binary_less_than_op(&self) -> Self::BinaryOpType {
        PatternBinaryOperator::LessThan
    }
    fn get_binary_less_than_or_equal_op(&self) -> Self::BinaryOpType {
        PatternBinaryOperator::LessThanOrEqual
    }
    fn get_binary_greater_than_op(&self) -> Self::BinaryOpType {
        PatternBinaryOperator::GreaterThan
    }
    fn get_binary_greater_than_or_equal_op(&self) -> Self::BinaryOpType {
        PatternBinaryOperator::GreaterThanOrEqual
    }
    fn get_binary_equals_op(&self) -> Self::BinaryOpType {
        PatternBinaryOperator::Equals
    }
    fn get_binary_not_equals_op(&self) -> Self::BinaryOpType {
        PatternBinaryOperator::NotEquals
    }
    // Note: PatternBinaryOperator has more variants (LessThan, Equals etc.)
    // If the generic parser needs to support them, corresponding get_binary_xxx_op methods would be needed.
    // For now, only Add, Sub, Mul are in the generic parsing logic.
}

// --- End of Pattern Parsing Specifics ---

enum ParsedAtom {
    MemoryRef(TokenStream2),
    SubExpression(TokenStream2),
    Constant(TokenStream2),
    ExternalVar(Ident), // NEW: For #var
}

// Parses a pattern variable binding e.g. $var, $var:expr, $var:addr, $var:const
// Assumes that `parse_pattern_atom_internal` has already peeked `Token![$]`
// and this function is called to consume and parse it.
// Returns `Result<PatternExpression>` directly.
fn parse_pattern_matching_atom(input: ParseStream) -> Result<PatternExpression> {
    let _dollar_token: Token![$] = input.parse()?; // Consume '$'
    let var_ident: Ident = input.parse()?; // Parse the identifier (e.g., 'e', 'a')

    // Check for optional type specifier (:expr, :addr, :const)
    let final_bind_type = if input.peek(Token![:]) {
        let _colon_token: Token![:] = input.parse()?; // Consume ':'

        // Parse the type specifier using custom keywords
        if input.peek(kw::expr) {
            input.parse::<kw::expr>()?; // Consume 'expr'
            PatternBindType::Expression
        } else if input.peek(kw::addr) {
            input.parse::<kw::addr>()?; // Consume 'addr'
            PatternBindType::Addressable
        } else if input.peek(Token![const]) {
            input.parse::<Token![const]>()?; // Consume 'const'
            PatternBindType::Constant
        } else {
            // Error if none of the expected keywords are found
            return Err(input.error("Expected type specifier `expr`, `addr`, or `const` after `:`"));
        }
    } else {
        // No type specifier, default is :expr
        PatternBindType::Expression
    };

    Ok(PatternExpression::Bind(PatternBindVariable {
        ident: var_ident,
        bind_type: final_bind_type,
    }))
}

fn parse_atom_internal(input: ParseStream) -> Result<ParsedAtom> {
    if input.peek(Token![#]) {
        // Check for '#'
        let _hash_token: Token![#] = input.parse()?; // Consume '#'
        let var_ident: Ident = input.parse()?; // Parse the identifier
        Ok(ParsedAtom::ExternalVar(var_ident))
    } else if (input.peek(Token![*]) && input.peek2(token::Paren)) || input.peek(token::Bracket) {
        // Delegate to parse_ssa_memory_reference for *(expr) or [...]
        let ssa_mem_ref_tokens = SsaMemoryReferenceParse::parse(input)?.0;
        Ok(ParsedAtom::MemoryRef(ssa_mem_ref_tokens))
    } else if input.peek(token::Paren) {
        let content;
        syn::parenthesized!(content in input);
        let sub_expr_tokens = parse_lir_expr(&content)?; // Recursively parse LIR expression
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
    let cp = v3_path(); // cp stands for crate_path, used for Expression variants
    match parse_atom_internal(input)? {
        ParsedAtom::MemoryRef(tokens) => {
            // Wrap SsaMemoryReference in Expression::Addressable
            Ok(quote! { #cp::lir::Expression::Addressable(#tokens) })
        }
        ParsedAtom::SubExpression(tokens) => {
            // Already an Expression (came from parenthesized expression), return as is
            Ok(tokens)
        }
        ParsedAtom::Constant(tokens) => {
            // Wrap literal in Expression::Constant
            Ok(quote! { #cp::lir::Expression::Constant(#tokens) })
        }
        ParsedAtom::ExternalVar(ident) => {
            // The ident is the Rust variable name. It's assumed to be in scope
            // and of a type compatible with Expression<SsaMemoryReference>.
            // If 'ident' is already an Expression, this will directly interpolate it.
            Ok(quote! { #ident })
        }
    }
}

// Generic Unary Parser
fn parse_unary_generic<S: ParseStrategy>(input: ParseStream, strategy: &S) -> Result<S::Output> {
    if input.peek(Token![-]) {
        let _op: Token![-] = input.parse()?;
        let arg = parse_unary_generic(input, strategy)?; // Recursive call
        strategy.build_unary(strategy.get_unary_minus_op(), arg)
    } else if input.peek(Token![!]) {
        let _op: Token![!] = input.parse()?;
        let arg = parse_unary_generic(input, strategy)?; // Recursive call
        strategy.build_unary(strategy.get_unary_not_op(), arg)
    } else {
        strategy.parse_atom(input)
    }
}

// Generic Multiplication Parser
fn parse_multiplication_generic<S: ParseStrategy>(
    input: ParseStream,
    strategy: &S,
) -> Result<S::Output> {
    let mut lhs = parse_unary_generic(input, strategy)?;
    // The check `!(input.peek2(token::Paren) && ...)` used in some designs to disambiguate
    // multiplication from dereference `*(...)` is complex.
    // We rely on `parse_atom` (called by `parse_unary_generic`) to correctly consume `*(expr)`
    // or `*(pattern)` if that's the intended syntax. If `parse_atom` does not consume it,
    // then a `*` token here is treated as binary multiplication.
    while input.peek(Token![*]) {
        let _op: Token![*] = input.parse()?;
        let rhs = parse_unary_generic(input, strategy)?;
        lhs = strategy.build_binary(strategy.get_binary_mul_op(), lhs, rhs)?;
    }
    Ok(lhs)
}

// Generic Addition/Subtraction Parser
fn parse_addition_subtraction_generic<S: ParseStrategy>(
    input: ParseStream,
    strategy: &S,
) -> Result<S::Output> {
    let mut lhs = parse_multiplication_generic(input, strategy)?;
    while input.peek(Token![+]) || input.peek(Token![-]) {
        if input.peek(Token![+]) {
            let _op: Token![+] = input.parse()?;
            let rhs = parse_multiplication_generic(input, strategy)?;
            lhs = strategy.build_binary(strategy.get_binary_add_op(), lhs, rhs)?;
        } else if input.peek(Token![-]) {
            let _op: Token![-] = input.parse()?;
            let rhs = parse_multiplication_generic(input, strategy)?;
            lhs = strategy.build_binary(strategy.get_binary_sub_op(), lhs, rhs)?;
        }
    }
    Ok(lhs)
}

// Generic Comparison Parser
fn parse_comparison_generic<S: ParseStrategy>(
    input: ParseStream,
    strategy: &S,
) -> Result<S::Output> {
    let mut lhs = parse_addition_subtraction_generic(input, strategy)?;
    while input.peek(Token![<])
        || input.peek(Token![<=])
        || input.peek(Token![>])
        || input.peek(Token![>=])
    {
        if input.peek(Token![<=]) {
            let _op: Token![<=] = input.parse()?;
            let rhs = parse_addition_subtraction_generic(input, strategy)?;
            lhs = strategy.build_binary(strategy.get_binary_less_than_or_equal_op(), lhs, rhs)?;
        } else if input.peek(Token![<]) {
            let _op: Token![<] = input.parse()?;
            let rhs = parse_addition_subtraction_generic(input, strategy)?;
            lhs = strategy.build_binary(strategy.get_binary_less_than_op(), lhs, rhs)?;
        } else if input.peek(Token![>=]) {
            let _op: Token![>=] = input.parse()?;
            let rhs = parse_addition_subtraction_generic(input, strategy)?;
            lhs =
                strategy.build_binary(strategy.get_binary_greater_than_or_equal_op(), lhs, rhs)?;
        } else if input.peek(Token![>]) {
            let _op: Token![>] = input.parse()?;
            let rhs = parse_addition_subtraction_generic(input, strategy)?;
            lhs = strategy.build_binary(strategy.get_binary_greater_than_op(), lhs, rhs)?;
        }
    }
    Ok(lhs)
}

// Generic Equality Parser
fn parse_equality_generic<S: ParseStrategy>(input: ParseStream, strategy: &S) -> Result<S::Output> {
    let mut lhs = parse_comparison_generic(input, strategy)?;
    while input.peek(Token![==]) || input.peek(Token![!=]) {
        if input.peek(Token![==]) {
            let _op: Token![==] = input.parse()?;
            let rhs = parse_comparison_generic(input, strategy)?;
            lhs = strategy.build_binary(strategy.get_binary_equals_op(), lhs, rhs)?;
        } else if input.peek(Token![!=]) {
            let _op: Token![!=] = input.parse()?;
            let rhs = parse_comparison_generic(input, strategy)?;
            lhs = strategy.build_binary(strategy.get_binary_not_equals_op(), lhs, rhs)?;
        }
    }
    Ok(lhs)
}

// Generic Top-Level Expression Parser
pub fn parse_expr_generic<S: ParseStrategy>(input: ParseStream, strategy: &S) -> Result<S::Output> {
    parse_equality_generic(input, strategy)
}

// LIR Expression Parser (Specific instantiation of generic parser)
// This function is now a specific instance of using the generic parser for LIR.
// It's kept if direct LIR parsing is needed outside of FullExprParse, otherwise FullExprParse can call generic directly.
pub fn parse_lir_expr(input: ParseStream) -> Result<TokenStream2> {
    let strategy = LirParseStrategy;
    parse_expr_generic(input, &strategy)
}

pub struct FullExprParse(pub TokenStream2);

impl Parse for FullExprParse {
    fn parse(input: ParseStream) -> Result<Self> {
        let strategy = LirParseStrategy {};
        let result = parse_expr_generic(input, &strategy)?;
        if !input.is_empty() {
            return Err(input.error("Unexpected tokens after expression"));
        }
        Ok(FullExprParse(result))
    }
}

pub struct SsaMemoryReferenceParse(pub TokenStream2);

impl Parse for SsaMemoryReferenceParse {
    fn parse(input: ParseStream) -> Result<Self> {
        let v3_path = v3_path();
        if input.peek(Token![*]) && input.peek2(token::Paren) {
            let _star: Token![*] = input.parse()?;
            let content;
            syn::parenthesized!(content in input);
            let inner_expr_tokens = parse_lir_expr(&content)?; // Parse the inner expression as LIR
            Ok(SsaMemoryReferenceParse(quote! {
                #v3_path::ssa::SsaMemoryReference::Deref(Box::new(#inner_expr_tokens))
            }))
        } else if input.peek(token::Bracket) {
            let version_atom: VersionedElement = input.parse()?;
            Ok(SsaMemoryReferenceParse(version_atom.to_expr_tokens()))
        } else {
            Err(input.error(
                "Expected an assignable memory location: '[base].version' or '*(expression)'",
            ))
        }
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
        let v3_path = v3_path();

        let instruction_variant_tokens = match &self.kind {
            DslInstructionKind::Assign {
                lhs_tokens,
                rhs_tokens,
            } => {
                quote! {
                    #v3_path::lir::Instruction::Assign {
                        target: #lhs_tokens,
                        src: #rhs_tokens,
                        target_debug_marker: None,
                    }
                }
            }
            DslInstructionKind::Output { expr_tokens } => {
                quote! {
                    #v3_path::lir::Instruction::Output(#expr_tokens)
                }
            }
        };

        quote! {
            #v3_path::lir::InstructionNode {
                id: #v3_path::lir::InstructionId::new(0),
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
                let expr_tokens = parse_lir_expr(input)?; // Parse the output expression as LIR
                if !input.is_empty() {
                    return Err(input.error("Unexpected tokens after output expression"));
                }
                return Ok(DslInstructionParse {
                    kind: DslInstructionKind::Output { expr_tokens },
                });
            }
        }

        let lhs_tokens = SsaMemoryReferenceParse::parse(input)?.0;
        if input.peek(Token![=]) {
            let _eq_token: Token![=] = input.parse()?;
            let rhs_tokens = parse_lir_expr(input)?; // Parse the RHS as LIR
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
