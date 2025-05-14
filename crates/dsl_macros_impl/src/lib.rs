//! Macros for defining DSL expressions and match-like structures.

mod dsl;
mod match_dsl_parser;

use proc_macro::TokenStream;
use syn::parse_macro_input;

use dsl::{DslInstructionParse, FullExprParse};
use match_dsl_parser::MatchDslInput; // Corrected import

#[proc_macro]
pub fn match_dsl(input: TokenStream) -> TokenStream {
    let parsed_input = parse_macro_input!(input as MatchDslInput); // Use corrected MatchDslInput
    let code = parsed_input.expanded().into();
    code
}

#[proc_macro]
pub fn build_expr(input: TokenStream) -> TokenStream {
    let input_parsed = parse_macro_input!(input as FullExprParse);
    input_parsed.0.into()
}

#[proc_macro]
pub fn build_instruction(input: TokenStream) -> TokenStream {
    let parsed_instruction_wrapper = parse_macro_input!(input as DslInstructionParse);
    parsed_instruction_wrapper.to_tokens().into()
}
