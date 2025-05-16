//! Macros for defining DSL expressions and match-like structures.

mod dsl;
mod match_dsl_parser;

use proc_macro::TokenStream;
use syn::parse_macro_input;

use dsl::{DslInstructionParse, FullExprParse, SsaMemoryReferenceParse};
use match_dsl_parser::MatchDslInput; // Corrected import

/// # `build_expr!` Macro Documentation
///
/// The `build_expr!` macro provides a DSL (Domain Specific Language) for constructing
/// `Expression<SsaMemoryReference>` instances with a more natural, arithmetic-like syntax.
/// This is primarily used for testing and creating illustrative examples of LIR (Low-level IR) expressions.
///
/// ## Basic Usage
///
/// The macro takes a single expression block as input and produces an `Expression<SsaMemoryReference>`.
///
/// ```rust
/// // let expr: Expression<SsaMemoryReference> = build_expr! { 123 + [R+1].5 };
/// ```
///
/// ## Supported Features
///
/// ### 1. Literals
/// Integer literals can be used directly.
///
/// ```rust
/// // let const_expr = build_expr! { 123 };
/// // assert_eq!(const_expr.nocolor(), "123");
/// ```
///
/// ### 2. Memory References
/// Memory references are specified using a bracketed notation with three possible forms:
///
/// - **Register-relative**: `[R+/-offset].version`
///   - `R` is the "relative memory" register (like a stack or frame pointer).
///   - `+offset` or `-offset` specifies the offset from this base.
///   - `.version` is a numerical version, often for SSA (Static Single Assignment) form.
///   ```rust
///   // let mem_ref_reg_rel_pos = build_expr! { [R+2].7 }; // Pretty prints to "[R+2]_7"
///   // let mem_ref_reg_rel_neg = build_expr! { [R-3].5 }; // Pretty prints to "[R-3]_5"
///   ```
///
/// - **Absolute Address**: `[address].version`
///   - `address` is a numerical constant representing a memory address.
///   - `.version` is the SSA version.
///   ```rust
///   // let mem_ref_abs = build_expr! { [155].7 }; // Pretty prints to "[155]_7"
///   ```
///
/// - **Pointer**: `[P id].version`
///   - `P` indicates this is a pointer reference.
///   - `id` is a numerical identifier for the pointer.
///   - `.version` is the SSA version.
///   ```rust
///   // let ptr_ref = build_expr! { [P 123].8 }; // Pretty prints to "[P123]_8"
///   ```
///
/// All three memory reference types can be used interchangeably in expressions and support
/// the same operations (arithmetic, comparison, dereferencing, etc.).
///
/// ### 3. Binary Operators
/// Standard arithmetic and comparison operators are supported.
/// - **Arithmetic**: `+` (addition), `-` (subtraction), `*` (multiplication).
///   ```rust
///   // let addition = build_expr! { [R+2].7 + [R-3].5 };
///   // let subtraction = build_expr! { [R+2].3 - [R+3].0 };
///   // let multiplication = build_expr! { [R+1].3 * [R-2].2 };
///   // let mixed_arithmetic = build_expr! { [R+1].3 + [354].7 * [R-2].7 };
///   ```
/// - **Comparison**: `==`, `!=`, `>`, `<`, `>=`, `<=`.
///   ```rust
///   // let equals_op = build_expr! { 33 == 45 };
///   // let not_equals_op = build_expr! { 33 != 45 };
///   // let greater_than_op = build_expr! { [R+1].3 + 5 > 10 };
///   ```
///
/// ### 4. Unary Operators
/// - **Negation**: `-`
///   ```rust
///   // let neg_const = build_expr! { -123 };
///   // let neg_mem = build_expr! { -[R+1].5 };
///   // let neg_expr = build_expr! { -(123 + [R+1].5) };
///   ```
/// - **Logical NOT**: `!`
///   ```rust
///   // let not_const = build_expr! { !123 };
///   // let not_mem = build_expr! { ![R+1].5 };
///   // let not_expr = build_expr! { !(123 + [R+1].5) };
///   ```
/// - **Chaining**: Unary operators can be chained.
///   ```rust
///   // let double_neg = build_expr! { --5 };
///   // let double_not = build_expr! { !!5 };
///   // let neg_not = build_expr! { -!5 };
///   ```
///
/// ### 5. Dereference Operator
/// The `*` operator is used for dereferencing memory locations. It can be applied to constants
/// (representing addresses), memory references, or more complex expressions that evaluate to an address.
///
/// ```rust
/// // let deref_const_addr = build_expr! { *(123) };
/// // let deref_mem_ref = build_expr! { *([R+5].1) };
/// // let deref_complex_expr = build_expr! { *([R+1].3 + 123) };
/// // // Dereference as part of a larger expression:
/// // let deref_in_expr = build_expr! { *([R+1].3) + 123 };
/// // let complex_deref_expr = build_expr! { 5 * *([R+1].3 + [R-2].2) };
/// ```
/// Note: When dereferencing a simple literal or a direct memory reference, parentheses `()`
/// around the operand are often required by the macro's parser, e.g., `*(123)` or `*([R+5].1)`.
/// For more complex sub-expressions, parentheses are naturally part of the sub-expression structure,
/// e.g., `*([R+1].3 + 123)`.
///
/// ### 6. Parentheses for Grouping
/// Parentheses `()` can be used to explicitly control the order of operations, as in standard arithmetic.
///
/// ```rust
/// // let grouped_expr1 = build_expr! { ([R+1].3 + [R+1].5) * [R-2].7 };
/// // let grouped_expr2 = build_expr! { [R+1].3 * (123 + [R-2].7) };
/// ```
///
/// ### 7. External Expression Injection
/// Previously constructed `Expression<SsaMemoryReference>` instances can be injected into a new
/// `build_expr!` invocation using the `#` prefix followed by the variable name holding the expression.
///
/// ```rust
/// // let sub_expr: Expression<SsaMemoryReference> = build_expr! { [R+1].3 + 123 };
/// // // Inject sub_expr into a new expression:
/// // let combined_expr = build_expr! { (3 + #sub_expr) * [R-1].7 };
/// // // combined_expr.nocolor() would typically result in something like "(3 + [R+1]_3 + 123) * [R-1]_7"
/// ```
///
/// ## Return Type
///
/// The `build_expr!` macro evaluates to an `Expression<SsaMemoryReference>`.
///
/// ## Typical Use in Tests
///
/// In test scenarios, `build_expr!` is often used in conjunction with `.nocolor()` (a method provided
/// by a trait like `ContextualPrettyPrint`) to get a string representation for assertions.
///
/// ```rust
/// // assert_eq!(build_expr! { [R-3].5 }.nocolor(), "[R-3]_5");
/// // assert_eq!(
/// //     build_expr! { ([R+1].3 * ([R+1].5 + [R-2].7) - [123].1) * [R+4].9 }.nocolor(),
/// //     "([R+1]_3 * ([R+1]_5 + [R-2]_7) - [123]_1) * [R+4]_9"
/// // );
/// // assert_eq!(build_expr! { *([R+1].0 + [R+2].0) }.nocolor(), "*([R+1]_0 + [R+2]_0)");
/// ```
#[proc_macro]
pub fn build_expr(input: TokenStream) -> TokenStream {
    let input_parsed = parse_macro_input!(input as FullExprParse);
    input_parsed.0.into()
}

#[proc_macro]
pub fn memref(input: TokenStream) -> TokenStream {
    let input_parsed = parse_macro_input!(input as SsaMemoryReferenceParse);
    input_parsed.0.into()
}

/// # `match_dsl!` Macro Documentation
///
/// The `match_dsl!` macro provides a DSL for pattern matching on `Expression<SsaMemoryReference>`
/// instances, similar to Rust's `match` expression but tailored for the structure of LIR expressions.
/// It allows deconstructing expressions and binding parts of them to variables.
/// This is primarily used for testing and creating illustrative examples.
///
/// ## Basic Usage
///
/// The macro takes an expression to match (as a reference) and a series of pattern arms.
/// Each arm consists of a pattern and an expression to evaluate if the pattern matches.
///
/// ```rust
/// // // Assume build_expr! and Expression types are in scope
/// // let expr_to_match: Expression<SsaMemoryReference> = build_expr! { 10 + 20 };
/// // let result = match_dsl!(&expr_to_match,
/// //     $a:const + $b:const => {
/// //         // a is &i128, b is &i128
/// //         *a + *b // Dereference to get i128 values
/// //     },
/// //     _ => 0 // Default arm if no other pattern matches
/// // );
/// // assert_eq!(result, 30);
/// ```
///
/// ## Supported Patterns
///
/// ### 1. Literals
/// Match against exact literal values, including integers, memory references, and dereferenced forms.
/// The syntax for memory references (`[R+offset].version`, `[address].version`) and dereferences (`*`)
/// is the same as in `build_expr!`.
///
/// ```rust
/// // let num_expr = build_expr! { 12376 };
/// // assert_eq!(match_dsl!(&num_expr, 12376 => 99, _ => 0), 99);
///
/// // let mem_ref_expr = build_expr! { [R-3].5 };
/// // assert_eq!(match_dsl!(&mem_ref_expr, [R-3].5 => 1, _ => 0), 1);
///
/// // let deref_expr = build_expr! { *([R+7].0) };
/// // assert_eq!(match_dsl!(&deref_expr, *([R+7].0) => 2, _ => 0), 2);
/// ```
///
/// Note: While literal patterns work for integers and simple memory references, for pointer patterns
/// it's recommended to use binding patterns (described below) for more reliable matching.
///
/// ### 2. Bindings
/// Bind parts of the matched expression to variables. These variables are then available in the arm's expression.
/// - `$name:const`: Binds an integer constant. `name` will be of type `&i128`.
///   ```rust
///   // let const_expr = build_expr! { 35549 };
///   // match_dsl!(&const_expr, $a:const => assert_eq!(*a, 35549), _ => panic!());
///   ```
/// - `$name:addr`: Binds a memory reference. `name` will be of type `SsaMemoryReference`.
///   This works for all memory reference types (relative, absolute, and pointer).
///   ```rust
///   // let addr_expr = build_expr! { [R+5].10 };
///   // match_dsl!(&addr_expr, $b:addr => assert_eq!(b.nocolor(), "[R+5]_10"), _ => panic!());
///   //
///   // // Binding pointer references
///   // let ptr_expr = build_expr! { [P 123].8 };
///   // match_dsl!(&ptr_expr, $p:addr => assert_eq!(p.nocolor(), "[P123]_8"), _ => panic!());
///   ```
/// - `$name:expr` or simply `$name`: Binds a sub-expression. `name` will be of type `Expression<SsaMemoryReference>`.
///   ```rust
///   // let generic_expr = build_expr! { 123 + 456 };
///   // match_dsl!(&generic_expr, $c:expr => assert_eq!(c.nocolor(), "123 + 456"), _ => panic!());
///   // // Shorthand $c (without :expr) also works for binding expressions:
///   // match_dsl!(&generic_expr, $c => assert_eq!(c.nocolor(), "123 + 456"), _ => panic!());
///   ```
/// - `_`: Wildcard. Matches any sub-expression without binding it. Useful for ignoring parts of a pattern.
///
/// ### 3. Operators in Patterns
/// Patterns can mirror the structure of expressions, including arithmetic, comparison, unary, and dereference operators.
///
/// - **Binary Operators (Arithmetic & Comparison)**:
///   Match expressions like `lhs + rhs`, `lhs == rhs`, etc.
///   ```rust
///   // let add_expr = build_expr! { 33 + 45 };
///   // let (val1, val2) = match_dsl!(&add_expr, $a:const + $b:const => (*a, *b), _ => panic!());
///   // assert_eq!((val1, val2), (33, 45));
///
///   // let eq_expr = build_expr! { [R+1].3 + 5 == 10 };
///   // let (lhs_str, rhs_val) = match_dsl!(&eq_expr, $lhs_expr == $rhs_const:const => (lhs_expr.nocolor(), *rhs_const), _ => panic!());
///   // assert_eq!(lhs_str, "[R+1]_3 + 5");
///   // assert_eq!(rhs_val, 10);
///   ```
///
/// - **Unary Operators (`-`, `!`)**:
///   Match negated or logically inverted expressions.
///   ```rust
///   // let neg_expr = build_expr! { -123 };
///   // let val = match_dsl!(&neg_expr, -$a:const => *a, _ => panic!());
///   // assert_eq!(val, 123);
///
///   // let not_expr = build_expr! { ![R+3].5 };
///   // let inner_str = match_dsl!(&not_expr, !$b_inner:expr => b_inner.nocolor(), _ => panic!());
///   // assert_eq!(inner_str, "[R+3]_5");
///   ```
///
/// - **Dereference Operator (`*`)**:
///   Match dereferenced expressions. Parentheses around the dereferenced sub-expression in the pattern are often needed.
///   ```rust
///   // let deref_op_expr = build_expr! { *([R+2].3 + 10) };
///   // let inner_expr_str = match_dsl!(&deref_op_expr, *($c_inner:expr) => c_inner.nocolor(), _ => panic!());
///   // assert_eq!(inner_expr_str, "[R+2]_3 + 10");
///
///   // // Binding within a dereferenced expression:
///   // let deref_bind_expr = build_expr! { *([R+3].8 + 20) };
///   // let const_val = match_dsl!(&deref_bind_expr, *([R+3].8 + $a_const:const) => *a_const, _ => panic!());
///   // assert_eq!(const_val, 20);
///   ```
///
/// ### 4. Parentheses for Grouping
/// Parentheses `()` in patterns clarify the structure and precedence, similar to their use in `build_expr!`.
///
/// ```rust
/// // let complex_expr = build_expr! { ([R+2].3 - [R+3].5) + [R+4].7 };
/// // let bound_d_str = match_dsl!(&complex_expr,
/// //     ([R+2].3 - $d_expr) + _ => d_expr.nocolor(), // Matches subtraction within parentheses
/// //     _ => panic!("no match")
/// // );
/// // assert_eq!(bound_d_str, "[R+3]_5");
/// ```
///
/// ### 5. Complex Nested Patterns
/// Combine literals, bindings, and operators to deconstruct deeply nested expression structures.
///
/// ```rust
/// // let nested_expr = build_expr! { *([R+2].3 + 123) * ![R+1].5 };
/// // let (a_str, b_str) = match_dsl!(&nested_expr,
/// //     *($a_expr + 123) * !$b_expr => (a_expr.nocolor(), b_expr.nocolor()),
/// //     _ => panic!("no match")
/// // );
/// // assert_eq!(a_str, "[R+2]_3");
/// // assert_eq!(b_str, "[R+1]_5");
/// ```
///
/// Pointer references can be used in complex patterns as well:
///
/// ```rust
/// // let ptr_expr = build_expr! { [P 123].8 * 5 + *([P 456].9) };
/// // let (ptr_id, deref_ptr) = match_dsl!(&ptr_expr,
/// //     $p:addr * 5 + *($d:addr) => (p.nocolor(), d.nocolor()),
/// //     _ => panic!("no match")
/// // );
/// // assert_eq!(ptr_id, "[P123]_8");
/// // assert_eq!(deref_ptr, "[P456]_9");
/// ```
///
/// ### 6. Multiple Arms and Fallthrough
/// `match_dsl!` evaluates arms sequentially, executing the code for the first pattern that matches.
/// A wildcard `_` arm acts as a default or catch-all if no preceding patterns match.
///
/// ```rust
/// // let expr_val = build_expr! { 10 + 20 };
/// // let result_code = match_dsl!(&expr_val,
/// //     [R+1].17 => 1,                // Arm 1: Doesn't match
/// //     $a:const + $b:const => *a + *b, // Arm 2: Matches!
/// //     *(_ + 5) => 3,                 // Arm 3: Not reached
/// //     _ => 4                         // Arm 4: Not reached
/// // );
/// // assert_eq!(result_code, 30);
/// ```
///
/// ## Return Value
///
/// The `match_dsl!` macro evaluates to the result of the expression in the executed arm.
/// Consequently, all arms must return values of compatible types.
///
/// ## Typical Use in Tests
///
/// `match_dsl!` is particularly useful in unit tests for:
/// - Verifying the specific structure of `Expression<SsaMemoryReference>` instances.
/// - Deconstructing expressions to assert properties of their components (e.g., values, types of sub-expressions).
///
/// ```rust
/// // let expr_to_test = build_expr! { [R+5].4 >= 45 * 3 };
/// // match_dsl!(&expr_to_test,
/// //     $a_lhs:expr >= $b_rhs:expr => {
/// //         assert_eq!(a_lhs.nocolor(), "[R+5]_4");
/// //         // Further match or assert on b_rhs if needed:
/// //         match_dsl!(&b_rhs, $val1:const * $val2:const => {
/// //            assert_eq!(*val1, 45);
/// //            assert_eq!(*val2, 3);
/// //         }, _ => panic!("RHS not as expected"));
/// //     },
/// //     _ => panic!("Pattern did not match")
/// // );
/// ```
#[proc_macro]
pub fn match_dsl(input: TokenStream) -> TokenStream {
    let parsed_input = parse_macro_input!(input as MatchDslInput); // Use corrected MatchDslInput
    let code = parsed_input.expanded().into();
    code
}

#[proc_macro]
pub fn build_instruction(input: TokenStream) -> TokenStream {
    let parsed_instruction_wrapper = parse_macro_input!(input as DslInstructionParse);
    parsed_instruction_wrapper.to_tokens().into()
}
