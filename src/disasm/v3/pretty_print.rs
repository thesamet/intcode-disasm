use std::fmt::Display;

use castaway::{cast, match_type};
use colored::Colorize;
use itertools::Itertools;

use crate::derive_display;
use crate::disasm::v3::lir::{MemoryReference, MemoryReferenceInfo};
use crate::disasm::v3::model::{
    FoldedSsaComplete, HasFoldedSsaResult, HasFunctionCallAnalysisResult, HasHlrProgram,
    HasTypeInferenceResult, HlrConstructionComplete, TypeInferenceComplete, VariableMergerComplete,
};
use crate::disasm::v3::ssa::converter::PhiFunction;
use crate::disasm::v3::type_inference::TypeVarId;
use crate::disasm::v3::{
    cfg::{BlockView, FunctionView},
    common::formatting::pretty_print_framework::PrettyPrintConfig,
    model::{
        FunctionCallAnalysisComplete, HasControlFlowGraphResult, HasSsaResult, Model, ModelState,
    },
    PredecessorKind,
};

// Import from V2/V3
use crate::disasm::v2::{
    instructions::{BinaryOperator, Expression, Instruction, InstructionNode, UnaryOperator},
    model::FunctionId,
};
use crate::disasm::v3::ssa::{SsaMemoryReference, VersionedMemoryReference};

use super::common::formatting::pretty_print_framework::GenericFormattingContext;
use super::common::formatting::{ContextualPrettyPrint, SemanticColor};

// --- Operator Precedence Helpers ---
fn binary_op_precedence(op: &BinaryOperator) -> u8 {
    match op {
        BinaryOperator::Mul => 5,
        BinaryOperator::Add | BinaryOperator::Sub => 4,
        BinaryOperator::LessThan
        | BinaryOperator::LessThanOrEqual
        | BinaryOperator::GreaterThan
        | BinaryOperator::GreaterThanOrEqual => 2,
        BinaryOperator::Equals | BinaryOperator::NotEquals => 1,
    }
}

type FormattingContext<'a> = GenericFormattingContext<'a, ()>;

impl<A: ContextualPrettyPrint<T = ()> + 'static> ContextualPrettyPrint for InstructionNode<A> {
    type T = ();

    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        match &self.kind {
            Instruction::Assign {
                ref target,
                ref src,
                target_debug_marker,
            } => {
                let debug_marker = match target_debug_marker {
                    Some(marker) => {
                        format!(
                            "{}{} ",
                            ctx.format("'", SemanticColor::LowPrio),
                            ctx.format(marker.to_string(), SemanticColor::LowPrio)
                        )
                    }
                    None => "".to_string(),
                };
                let target_type = ""; // castaway::match_type!(self.model, {});
                format!(
                    "{debug_marker}{}{} {} {}",
                    target.pretty_print_with_context(ctx),
                    target_type,
                    ctx.fmt_eq(),
                    src.pretty_print_with_context(ctx)
                )
            }
            Instruction::If {
                cond,
                then_addr,
                else_addr,
            } => {
                format!(
                    "{} {} {} {} {} {}",
                    ctx.format("if", SemanticColor::Keyword),
                    cond.pretty_print_with_context(ctx),
                    ctx.format("goto", SemanticColor::Keyword),
                    ctx.format(then_addr, SemanticColor::Constant),
                    ctx.format("else goto", SemanticColor::Keyword),
                    ctx.format(else_addr, SemanticColor::Constant)
                )
            }
            Instruction::Goto(addr) => {
                format!(
                    "{} {}",
                    ctx.format("goto", SemanticColor::Keyword),
                    ctx.format(addr, SemanticColor::Constant)
                )
            }
            Instruction::Call {
                addr,
                args,
                return_to,
            } => {
                format!(
                    "{} {}{}{}{} {} {}",
                    ctx.format("call", SemanticColor::Keyword),
                    addr.pretty_print_with_context(ctx),
                    ctx.fmt_open_paren(),
                    args.iter()
                        .map(|e| e.pretty_print_with_context(ctx))
                        .join(&ctx.fmt_comma().to_string()),
                    ctx.fmt_close_paren(),
                    ctx.format("return to", SemanticColor::Keyword),
                    ctx.format(return_to, SemanticColor::Constant)
                )
            }
            Instruction::Output(expr) => {
                format!(
                    "{} {}",
                    ctx.format("output", SemanticColor::Keyword),
                    expr.pretty_print_with_context(ctx)
                )
            }
            Instruction::Return => ctx.format("return", SemanticColor::Keyword).to_string(),
            Instruction::Halt => ctx.format("halt", SemanticColor::Keyword).to_string(),
        }
    }
}

impl<A> Display for InstructionNode<A>
where
    A: 'static + ContextualPrettyPrint<T = ()>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pretty_print())
    }
}

impl ContextualPrettyPrint for PhiFunction {
    type T = ();
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        let inputs_str = self
            .inputs
            .iter()
            .sorted_by_key(|(pred_kind, _)| pred_kind.source_block_id())
            .map(|(pred_kind, addressable)| {
                let source_id_str = pred_kind
                    .source_block_id()
                    .to_string()
                    .color(ctx.colors().unwrap().const_color);
                let call_marker_str =
                    if matches!(pred_kind, PredecessorKind::FunctionCallReturns(_)) {
                        "(call)".color(ctx.colors().unwrap().low_prio).to_string()
                    } else {
                        String::new()
                    };
                format!(
                    "{}{}: {}",
                    source_id_str,
                    call_marker_str,
                    addressable.pretty_print_with_context(ctx)
                )
            })
            .join(", ");

        format!(
            "{} {} {}({})",
            self.result.pretty_print_with_context(ctx),
            "=".color(ctx.colors().unwrap().op_color),
            "φ".color(ctx.colors().unwrap().function),
            inputs_str
        )
    }
}

derive_display!(PhiFunction);

fn unary_op_precedence(_op: &UnaryOperator) -> u8 {
    6 // Unary operators typically have high precedence
}

// --- Expression Formatting ---
fn line(s: &str, ctx: &FormattingContext) -> String {
    let clear_to_end_code = "\x1b[K";
    match ctx.colors() {
        Some(colors) => format!("{s}{clear_to_end_code}")
            .on_color(colors.bg_color)
            .to_string(),
        None => s.to_string(),
    }
}

impl<S: ModelState + 'static> ContextualPrettyPrint for Model<S>
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    type T = ();
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        let mut functions_sorted: Vec<_> = self.functions().map(|(_, f)| f).collect();
        functions_sorted.sort_by_key(|f| f.function_id());

        let clear_to_end_code = "\x1b[K";

        // Create a blank line with background color for separating functions
        let blank_line = clear_to_end_code
            .to_string()
            .on_color(ctx.colors().unwrap().bg_color)
            .to_string();

        functions_sorted
            .iter()
            .map(|f| f.pretty_print_with_context(ctx))
            .join(&format!("\n{blank_line}\n"))
    }
}

impl<S> Display for Model<S>
where
    S: ModelState + HasSsaResult + HasControlFlowGraphResult + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pretty_print())
    }
}

fn format_signature<S: ModelState + 'static>(
    function: &FunctionView<S>,
    ctx: &FormattingContext,
) -> String {
    fn format_signature<T, S: ModelState + 'static>(
        model: &Model<T>,
        function: &FunctionView<S>,
        ctx: &FormattingContext,
    ) -> String
    where
        T: HasFunctionCallAnalysisResult + ModelState + 'static,
    {
        format!(
            "{}{}{}",
            "(".color(ctx.colors().unwrap().low_prio),
            model
                .function_call_analysis_result()
                .functions
                .get(&function.function_id())
                .unwrap()
                .parameter_entry_vars
                .values()
                .sorted_by_key(|v| v.as_stack_relative().unwrap())
                .map(|v| v.pretty_print_with_context(ctx))
                .join(&", ".color(ctx.colors().unwrap().low_prio).to_string()),
            ") -> ?".color(ctx.colors().unwrap().low_prio)
        )
    }

    fn format_typed_signature<T, S>(
        model: &Model<T>,
        function: &FunctionView<S>,
        ctx: &FormattingContext,
    ) -> String
    where
        T: HasTypeInferenceResult + ModelState + HasFunctionCallAnalysisResult + 'static,
        S: ModelState + 'static,
    {
        let res = model.type_inference_result();
        let show_var_ids = ctx.config.show_types_var_ids;
        let var_id = |tv_id: &TypeVarId| -> String {
            if show_var_ids {
                format!("[{}] ", tv_id)
            } else {
                String::new()
            }
        };
        let args = model.type_inference_result().function_signatures[&function.function_id()]
            .args
            .iter()
            .map(|(v, t, tv_id)| {
                format!(
                    "{}{}: {}",
                    var_id(tv_id),
                    v.pretty_print_with_context(ctx),
                    t.display_with(res)
                )
            })
            .join(&", ".color(ctx.colors().unwrap().low_prio).to_string());
        let rets = model.type_inference_result().function_signatures[&function.function_id()]
            .returns
            .iter()
            .map(|(v, t, tv_id)| {
                format!(
                    "{}{}: {}",
                    var_id(tv_id),
                    v.pretty_print_with_context(ctx),
                    t.display_with(res)
                )
            })
            .join(&", ".color(ctx.colors().unwrap().low_prio).to_string());
        format!(
            "{}{}{}{}{}{}",
            "(".color(ctx.colors().unwrap().low_prio),
            args,
            ") -> ".color(ctx.colors().unwrap().low_prio),
            "(".color(ctx.colors().unwrap().low_prio),
            rets,
            ")".color(ctx.colors().unwrap().low_prio),
        )
    }

    match_type!(function.model, {
        &Model<FunctionCallAnalysisComplete> as m => format_signature(m, function, ctx),
        &Model<FoldedSsaComplete> as m => format_signature(m, function, ctx),
        &Model<TypeInferenceComplete> as m =>  format_typed_signature(m, function, ctx),
        &Model<VariableMergerComplete> as m => format_typed_signature(m,  function, ctx),
        &Model<HlrConstructionComplete> as m => format_typed_signature(m, function, ctx),
        _ => "".to_string(),
    })
}

impl<A: ContextualPrettyPrint<T = ()> + 'static> ContextualPrettyPrint for Expression<A> {
    type T = ();
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        match self {
            Expression::Constant(value) => value.pretty_print_with_context(ctx),
            Expression::Addressable(addr) => addr.pretty_print_with_context(ctx),
            Expression::Binary { op, lhs, rhs } => {
                let op_display_str = match op {
                    BinaryOperator::Add => " + ",
                    BinaryOperator::Sub => " - ",
                    BinaryOperator::Mul => " * ",
                    BinaryOperator::Equals => " == ",
                    BinaryOperator::NotEquals => " != ",
                    BinaryOperator::LessThan => " < ",
                    BinaryOperator::LessThanOrEqual => " <= ",
                    BinaryOperator::GreaterThan => " > ",
                    BinaryOperator::GreaterThanOrEqual => " >= ",
                };
                let op_str_formatted = ctx.format(op_display_str, SemanticColor::Operator);
                let op_prec = binary_op_precedence(op);

                let lhs_str = lhs.pretty_print_with_context(&ctx.with_precedence(op_prec));
                let rhs_str = rhs.pretty_print_with_context(&ctx.with_precedence(op_prec));

                let result = format!("{lhs_str}{op_str_formatted}{rhs_str}");

                if let Some(parent_prec) = ctx.parent_precedence {
                    if parent_prec > op_prec {
                        // Add parentheses if needed based on precedence
                        return format!(
                            "{}{}{}",
                            ctx.fmt_open_paren(),
                            result,
                            ctx.fmt_close_paren()
                        );
                    }
                }
                result
            }
            Expression::Unary { op, arg } => {
                let op_str_formatted = ctx.format(op.to_string(), SemanticColor::Operator);
                let op_prec = unary_op_precedence(op);
                let arg_str = arg.pretty_print_with_context(&ctx.with_precedence(op_prec));

                let result = format!("{op_str_formatted}{arg_str}");

                if let Some(parent_prec) = ctx.parent_precedence {
                    if parent_prec > op_prec {
                        return format!(
                            "{}{}{}",
                            ctx.fmt_open_paren(),
                            result,
                            ctx.fmt_close_paren()
                        );
                    }
                }
                result
            }
            Expression::Input() => format!("{}", ctx.format("input()", SemanticColor::Keyword)),
            Expression::DebugMarker(marker, expr) => {
                format!(
                    "{}{}{}{}{}{}",
                    ctx.format('\'', SemanticColor::LowPrio),
                    ctx.format(*marker, SemanticColor::LowPrio), // Color the marker itself low_prio as per original
                    ctx.format(" ", SemanticColor::LowPrio),     // Explicit space, also low_prio
                    ctx.fmt_open_paren(),                        // Helper for '('
                    expr.pretty_print_with_context(&ctx.indented()), // Use indented context for the expression
                    ctx.fmt_close_paren()                            // Helper for ')'
                )
            }
        }
    }
}

impl<A: ContextualPrettyPrint<T = ()> + 'static> Display for Expression<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pretty_print())
    }
}

fn right_instructions<'a, S>(
    block: &BlockView<'a, S>,
) -> &'a Vec<InstructionNode<SsaMemoryReference>>
where
    S: HasSsaResult + ModelState + 'static,
{
    castaway::match_type!(block.model, {
        &Model<TypeInferenceComplete> as m =>
            &m
                .function(&block.containing_function_id())
                .block(&block.block_id())
                .folded_ssa()
                .instructions,
        &Model<FoldedSsaComplete> as m =>
            &m
                .function(&block.containing_function_id())
                .block(&block.block_id())
                .folded_ssa()
                .instructions,
            _ => &block.ssa().instructions,
    })
}

impl<'a, S> ContextualPrettyPrint for BlockView<'a, S>
where
    S: ModelState + HasSsaResult + 'static,
{
    type T = ();
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        let mut lines = Vec::new();
        let indent_str = ctx.indent_str();
        let inner_indent_str = " ".repeat(ctx.config.indent_width());

        // Block header with line number
        let block_header = format!(
            "{}{}:",
            indent_str,
            self.block_id().index().to_string().color(
                ctx.colors()
                    .map(|c| c.get_color(SemanticColor::LowPrio))
                    .unwrap_or(colored::Color::White)
            )
        );
        lines.push(line(&block_header, ctx));

        // Phi functions
        if ctx.show_vars() {
            // Instructions
        } else {
            for phi in &self.ssa().phi_functions {
                let phi_line = format!("{indent_str}{inner_indent_str}",)
                    + &phi.pretty_print_with_context(ctx);
                lines.push(line(&phi_line, ctx));
            }

            if !self.ssa().phi_functions.is_empty() {
                let blank_line = format!("{indent_str}{inner_indent_str}");
                lines.push(line(&blank_line, ctx));
            }
        }

        // Instructions
        for instr in right_instructions(self) {
            let instr_str = instr.pretty_print_with_context(ctx);
            if !instr_str.is_empty() {
                let instruction_line = format!(
                    "{}{}{:<5}        {}",
                    indent_str,
                    inner_indent_str,
                    instr.id.to_string().color(
                        ctx.colors()
                            .map(|c| c.get_color(SemanticColor::LowPrio))
                            .unwrap_or(colored::Color::White)
                    ),
                    instr_str,
                );
                lines.push(line(&instruction_line, ctx));
            }
        }

        lines.join("\n")
    }
}

impl<'a, S> Display for BlockView<'a, S>
where
    S: ModelState + HasSsaResult + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pretty_print())
    }
}

impl ContextualPrettyPrint for SsaMemoryReference {
    type T = ();
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        match self {
            SsaMemoryReference::Versioned(a) => a.pretty_print_with_context(ctx),
            SsaMemoryReference::Deref(expr) => {
                format!(
                    "{}{}{}{}",
                    ctx.fmt_star(),
                    ctx.fmt_open_paren(),
                    expr.pretty_print_with_context(ctx),
                    ctx.fmt_close_paren()
                )
            }
        }
    }
}

derive_display!(SsaMemoryReference);

impl ContextualPrettyPrint for MemoryReference {
    type T = ();
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        match self {
            MemoryReference::StackRelative(offset) => {
                // Use context helpers for '[' and ']' and ctx.format for 'R' and offset
                let base = ctx.format("R", SemanticColor::Variable);
                let offset_str = match offset {
                    0 => {
                        // No offset needed for [R]
                        String::new()
                    }
                    offset if *offset > 0 => {
                        // Format positive offset like +offset
                        format!("{}{}", ctx.format("+", SemanticColor::Operator), offset)
                    }
                    _ => {
                        // Format negative offset directly like -offset
                        format!("{offset}")
                    }
                };

                format!(
                    "{}{}{}{}",
                    ctx.fmt_open_bracket(),  // Helper for '['
                    base,                    // Formatted 'R'
                    offset_str,              // Formatted offset string
                    ctx.fmt_close_bracket()  // Helper for ']'
                )
            }
            MemoryReference::Global(addr) => {
                // Use context helpers for '[' and ']' and ctx.format for the address
                format!(
                    "{}{}{}",
                    ctx.fmt_open_bracket(), // Helper for '['
                    ctx.format(addr, SemanticColor::Variable), // Format the address
                    ctx.fmt_close_bracket()  // Helper for ']'
                )
            }
            MemoryReference::Pointer(addr) => {
                // Format pointers as [P{addr}]
                format!(
                    "{}{}{}{}",
                    ctx.fmt_open_bracket(),                   // Helper for '['
                    ctx.format("P", SemanticColor::Variable), // Format 'P'
                    ctx.format(addr.index(), SemanticColor::Variable), // Format the address
                    ctx.fmt_close_bracket()                   // Helper for ']'
                )
            }
            MemoryReference::Deref(expr) => {
                // Use ctx.format for '*'
                format!(
                    "{}{}",
                    ctx.fmt_star(),                      // Helper for '*'
                    expr.pretty_print_with_context(ctx)  // Recursively print the inner expression
                )
            }
        }
    }
}

derive_display!(MemoryReference);

impl<'a, S> ContextualPrettyPrint for FunctionView<'a, S>
where
    S: ModelState + HasSsaResult + 'static,
{
    type T = ();
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        let model = self.model;
        let mut lines = Vec::new();
        let indent_str = ctx.indent_str();

        let callers_comment = format_callers_comment(model, self.function_id());

        // Format signature content
        let signature_content = format!(
            "{}{}{} {}", // Construct the content of the line *without* clear_to_end_code or outer coloring
            ctx.format("fn ", SemanticColor::Keyword), // Use ctx.format
            ctx.format(self.function_id().to_string(), SemanticColor::Function), // Use ctx.format
            format_signature(self, ctx), // Assuming format_signature handles its own coloring conditionally or returns plain string
            ctx.fmt_open_brace()         // Use helper for '{'
        );

        // Use the `line` helper for the signature line
        lines.push(line(&format!("{indent_str}{signature_content}"), ctx));

        // Use the `line` helper for callers_comment lines
        if !callers_comment.is_empty() {
            for comment_text in callers_comment.lines() {
                let comment_line_content = format!("{indent_str}{comment_text}");
                lines.push(line(&comment_line_content, ctx));
            }
        }

        // Format blocks
        let mut blocks_sorted: Vec<_> = self.blocks().map(|(_, b)| b).collect();
        blocks_sorted.sort_by_key(|b| b.block_id());

        for block in blocks_sorted {
            // Block pretty-printing is recursive. Split its output into lines
            // and apply the line formatting to each line.
            let block_lines = block.pretty_print_with_context(&ctx.indented());
            lines.extend(block_lines.lines().map(|l| line(l, ctx))); // Apply line formatting to each line
        }

        // Format closing brace line content
        let close_line_content = format!(
            "{}",
            ctx.fmt_close_brace() // Use helper for '}'
        );

        // Use the `line` helper for the closing brace line
        lines.push(line(&format!("{indent_str}{close_line_content}"), ctx));

        lines.join("\n")
    }
}

impl<'a, S> Display for FunctionView<'a, S>
where
    S: ModelState + HasSsaResult + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.pretty_print())
    }
}

fn format_callers_comment<S>(model: &Model<S>, function_id: FunctionId) -> String
where
    S: ModelState + 'static,
{
    if let Ok(m_fca) = cast!(model, &Model<FunctionCallAnalysisComplete>) {
        let fca_result = m_fca.function_call_analysis_result();

        let callers = fca_result
            .blocks
            .iter()
            .filter(|(_, cs)| cs.target_function_id == Some(function_id))
            .map(|(block_id, csi)| {
                format!(
                    "// at {}: {} -> {}",
                    block_id,
                    csi.argument_writes.values().sorted().join(","),
                    csi.return_reads.values().sorted().join(", ")
                )
            })
            .collect_vec();

        if !callers.is_empty() {
            return format!("{}\n", callers.join("\n"));
        }
    }
    "".to_string()
}

impl ContextualPrettyPrint for i128 {
    type T = ();
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        ctx.format(self, SemanticColor::Constant).to_string()
    }
}

impl ContextualPrettyPrint for VersionedMemoryReference {
    type T = ();
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String {
        // Add the version
        let mem_ref = self.to_memory_reference();
        format!(
            "{}_{}",
            mem_ref.pretty_print_with_context(ctx),
            ctx.format(self.version, SemanticColor::Type)
        )
    }
}

derive_display!(VersionedMemoryReference);

// --- Public API ---

pub fn pretty_print_ssa_with_config<S>(model: &Model<S>, config: PrettyPrintConfig) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult + ModelState + 'static,
{
    model.pretty_print_with_config(&config)
}

pub fn pretty_print_ssa<S>(model: &Model<S>) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult + ModelState + 'static,
{
    let config = PrettyPrintConfig::default()
        .with_show_types(false)
        .with_show_vars(false);
    pretty_print_ssa_with_config(model, config)
}

pub fn pretty_print_folded_ssa_with_config<S>(model: &Model<S>, config: PrettyPrintConfig) -> String
where
    S: HasFoldedSsaResult + HasControlFlowGraphResult + ModelState + 'static,
{
    model.pretty_print_with_config(&config)
}

pub fn pretty_print_folded_ssa<S>(model: &Model<S>) -> String
where
    S: HasFoldedSsaResult + HasControlFlowGraphResult + ModelState + 'static,
{
    let config = PrettyPrintConfig::default()
        .with_show_types(false)
        .with_show_vars(false);
    pretty_print_folded_ssa_with_config(model, config)
}

pub fn pretty_print_types<S>(model: &Model<S>) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult + ModelState + 'static,
{
    let config = PrettyPrintConfig::default()
        .with_show_vars(false)
        .with_show_types_var_ids(true);
    pretty_print_types_with_config(model, config)
}

pub fn pretty_print_types_with_config<S>(model: &Model<S>, config: PrettyPrintConfig) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult + ModelState + 'static,
{
    model.pretty_print_with_config(&config)
}

// --- Backward compatibility functions ---

pub fn pretty_print_ssa_stdout<S>(model: &Model<S>)
where
    S: HasSsaResult + HasControlFlowGraphResult + ModelState + 'static,
{
    println!("{}", pretty_print_ssa(model));
}

pub fn pretty_print_with_types_stdout<S>(model: &Model<S>)
where
    S: HasTypeInferenceResult + HasControlFlowGraphResult + ModelState + 'static,
{
    println!("{}", pretty_print_types(model));
}
