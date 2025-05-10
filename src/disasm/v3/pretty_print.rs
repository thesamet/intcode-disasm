use castaway::{cast, match_type};
use colored::Colorize;
use itertools::Itertools;

use crate::disasm::v3::lir::{MemoryReference, MemoryReferenceInfo};
use crate::disasm::v3::model::{FoldedSsaComplete, HasFunctionCallAnalysisResult};
use crate::disasm::v3::ssa::converter::PhiFunction;
use crate::disasm::v3::{
    common::formatting::{
        colors::Colors,
        pretty_print::{FormattingContext, PrettyPrintConfig},
    },
    control_flow::{BlockView, FunctionView},
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

fn unary_op_precedence(_op: &UnaryOperator) -> u8 {
    6 // Unary operators typically have high precedence
}

// --- Expression Formatting ---

pub fn format_program<S: ModelState + 'static>(
    model: &Model<S>,
    config: &PrettyPrintConfig,
) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    let ctx = FormattingContext::new(config);
    let mut functions_sorted: Vec<_> = model.functions().map(|(_, f)| f).collect();
    functions_sorted.sort_by_key(|f| f.function_id());

    let clear_to_end_code = "\x1b[K";

    // Create a blank line with background color for separating functions
    let blank_line = clear_to_end_code
        .to_string()
        .on_color(ctx.colors().bg_color)
        .to_string();

    functions_sorted
        .iter()
        .map(|f| format_function(model, f, &ctx))
        .join(&format!("\n{blank_line}\n"))
}

fn format_signature<S: ModelState + 'static>(
    function: &FunctionView<S>,
    ctx: &FormattingContext,
) -> String {
    fn format_signature<
        T: HasFunctionCallAnalysisResult + ModelState + 'static,
        S: ModelState + 'static,
    >(
        model: &Model<T>,
        function: &FunctionView<S>,
        ctx: &FormattingContext,
    ) -> String
    where
        T: HasFunctionCallAnalysisResult,
    {
        format!(
            "{}{}{}",
            "(".color(ctx.colors().low_prio),
            model
                .function_call_analysis_result()
                .functions
                .get(&function.function_id())
                .unwrap()
                .parameter_entry_vars
                .values()
                .sorted_by_key(|v| v.as_stack_relative().unwrap())
                .map(|v| format_versioned_reference(*v, ctx))
                .join(&", ".color(ctx.colors().low_prio).to_string()),
            ") -> ?".color(ctx.colors().low_prio)
        )
    }

    match_type!(function.model, {
        &Model<FunctionCallAnalysisComplete> as m => format_signature(m, function, ctx),
        &Model<FoldedSsaComplete> as m => format_signature(m, function, ctx),
        _ => "".to_string(),
    })
}

pub fn format_expression<S: 'static>(expr: &Expression<S>, ctx: &FormattingContext) -> String {
    match expr {
        Expression::Constant(value) => format_constant(*value, ctx),
        Expression::Addressable(addr) => format_any_memory_reference(addr, ctx),
        Expression::Binary { op, lhs, rhs } => {
            let op_str = op.to_string().color(ctx.colors().op_color).to_string();
            let op_prec = binary_op_precedence(op);

            let lhs_str = format_expression(lhs, &ctx.with_precedence(op_prec));
            let rhs_str = format_expression(rhs, &ctx.with_precedence(op_prec));

            let result = format!("{lhs_str} {op_str} {rhs_str}");

            if let Some(parent_prec) = ctx.parent_precedence {
                if parent_prec > op_prec {
                    // Add parentheses if needed based on precedence
                    return format!(
                        "{}{}{}",
                        "(".color(ctx.colors().low_prio),
                        result,
                        ")".color(ctx.colors().low_prio)
                    );
                }
            }
            result
        }
        Expression::Unary { op, arg } => {
            let op_str = op.to_string().color(ctx.colors().op_color).to_string();
            let op_prec = unary_op_precedence(op);
            let arg_str = format_expression(arg, &ctx.with_precedence(op_prec));

            let result = format!("{op_str}{arg_str}");

            if let Some(parent_prec) = ctx.parent_precedence {
                if parent_prec > op_prec {
                    return format!(
                        "{}{}{}",
                        "(".color(ctx.colors().low_prio),
                        result,
                        ")".color(ctx.colors().low_prio)
                    );
                }
            }
            result
        }
        Expression::Input() => "input()".color(ctx.colors().keyword).to_string(),
        Expression::DebugMarker(marker, expr) => {
            format!(
                "'{} ({})",
                marker.to_string().color(ctx.colors().low_prio),
                format_expression(expr, ctx)
            )
        }
    }
}

// --- Memory Reference Formatting ---

// --- Phi Functions ---

fn format_phi_function(phi: &PhiFunction, ctx: &FormattingContext) -> String {
    let inputs_str = phi
        .inputs
        .iter()
        .sorted_by_key(|(pred_kind, _)| pred_kind.source_block_id())
        .map(|(pred_kind, addressable)| {
            let source_id_str = pred_kind
                .source_block_id()
                .to_string()
                .color(ctx.colors().const_color);
            let call_marker_str = if matches!(pred_kind, PredecessorKind::FunctionCallReturns(_)) {
                "(call)".color(ctx.colors().low_prio).to_string()
            } else {
                String::new()
            };
            format!(
                "{}{}: {}",
                source_id_str,
                call_marker_str,
                format_versioned_reference(*addressable, ctx)
            )
        })
        .join(", ");

    format!(
        "{} {} {}({})",
        format_versioned_reference(phi.result, ctx),
        "=".color(ctx.colors().op_color),
        "φ".color(ctx.colors().function),
        inputs_str
    )
}

// --- Instructions ---

// --- Block Level Formatting ---
fn right_instructions<'a, S: ModelState + 'static>(
    block: BlockView<'a, S>,
) -> &'a Vec<InstructionNode<SsaMemoryReference>>
where
    S: HasSsaResult,
{
    castaway::match_type!(block.model, {
        &Model<FoldedSsaComplete> as m =>
            &m
                .function(&block.containing_function_id())
                .block(&block.block_id())
                .folded_ssa()
                .instructions,
            _ => &block.ssa().instructions,
    })
}

// --- Function Call Info ---

// --- Caller Comments ---

// --- Function Formatting ---

// --- Program Level Formatting ---

fn format_block<S: ModelState + 'static>(block: BlockView<S>, ctx: &FormattingContext) -> String
where
    S: HasSsaResult,
{
    let mut lines = Vec::new();
    let indent_str = ctx.indent_str();
    let inner_indent_str = " ".repeat(ctx.config.indent_width());
    let clear_to_end_code = "\x1b[K";

    // Block header with line number
    let block_header = format!(
        "{}{}:{}",
        indent_str,
        block
            .block_id()
            .index()
            .to_string()
            .color(ctx.colors().low_prio),
        clear_to_end_code
    )
    .on_color(ctx.colors().bg_color)
    .to_string();
    lines.push(block_header);

    // Phi functions
    if !ctx.show_vars() {
        for phi in &block.ssa().phi_functions {
            let phi_line = format!(
                "{}{}{}{}",
                indent_str,
                inner_indent_str,
                format_phi_function(phi, ctx),
                clear_to_end_code
            )
            .on_color(ctx.colors().bg_color)
            .to_string();
            lines.push(phi_line);
        }

        if !block.ssa().phi_functions.is_empty() {
            let blank_line = format!("{indent_str}{inner_indent_str}{clear_to_end_code}")
                .on_color(ctx.colors().bg_color)
                .to_string();
            lines.push(blank_line);
        }
    }

    // Instructions
    for instr in right_instructions(block) {
        let instr_str = format_instruction(instr, ctx);
        if !instr_str.is_empty() {
            let instruction_line = format!(
                "{}{}{:<5}        {}{}",
                indent_str,
                inner_indent_str,
                instr.id.to_string().color(ctx.colors().low_prio),
                instr_str,
                clear_to_end_code
            )
            .on_color(ctx.colors().bg_color)
            .to_string();
            lines.push(instruction_line);
        }
    }

    lines.join("\n")
}

pub fn format_instruction<A: 'static>(
    instr: &InstructionNode<A>,
    ctx: &FormattingContext,
) -> String {
    match &instr.kind {
        Instruction::Assign {
            ref target,
            ref src,
            target_debug_marker,
        } => {
            let debug_marker = match target_debug_marker {
                Some(marker) => format!("'{} ", marker.to_string().color(ctx.colors().low_prio)),
                None => "".to_string(),
            };
            format!(
                "{debug_marker}{} {} {}",
                format_any_memory_reference(target, ctx),
                "=".color(ctx.colors().op_color),
                format_expression(src, ctx)
            )
        }
        Instruction::If {
            cond,
            then_addr,
            else_addr,
        } => {
            format!(
                "{} {} {} {} {} {}",
                "if".color(ctx.colors().keyword),
                format_expression(cond, ctx),
                "goto".color(ctx.colors().keyword),
                then_addr.to_string().color(ctx.colors().const_color),
                "else goto".color(ctx.colors().keyword),
                else_addr.to_string().color(ctx.colors().const_color)
            )
        }
        Instruction::Goto(addr) => {
            format!(
                "{} {}",
                "goto".color(ctx.colors().keyword),
                addr.to_string().color(ctx.colors().const_color)
            )
        }
        Instruction::Call {
            addr,
            args,
            return_to,
        } => {
            format!(
                "{} {}{}{}{} {} {}",
                "call".color(ctx.colors().keyword),
                format_expression(addr, ctx),
                "(".color(ctx.colors().low_prio),
                args.iter()
                    .map(|e| format_expression(e, ctx))
                    .join(&", ".color(ctx.colors().low_prio).to_string()),
                ")".color(ctx.colors().low_prio),
                "return to".color(ctx.colors().keyword),
                return_to.to_string().color(ctx.colors().const_color)
            )
        }
        Instruction::Output(expr) => {
            format!(
                "{} {}",
                "output".color(ctx.colors().keyword),
                format_expression(expr, ctx)
            )
        }
        Instruction::Return => "return".color(ctx.colors().keyword).to_string(),
        Instruction::Halt => "halt".color(ctx.colors().keyword).to_string(),
    }
}

pub fn format_ssa_memory_reference(
    reference: &SsaMemoryReference,
    ctx: &FormattingContext,
) -> String {
    match reference {
        SsaMemoryReference::Versioned(a) => format_versioned_reference(*a, ctx),
        SsaMemoryReference::Deref(expr) => {
            format!("*{}", format_expression(expr, ctx))
        }
    }
}

pub fn format_any_memory_reference<S>(reference: &S, ctx: &FormattingContext) -> String {
    match_type!(reference, {
        &SsaMemoryReference as s => format_ssa_memory_reference(s, ctx),
        &MemoryReference as m => format_memory_reference(m, ctx),
        _ => unreachable!(),
    })
}

fn format_function<S: ModelState + 'static>(
    model: &Model<S>,
    function: &FunctionView<S>,
    ctx: &FormattingContext,
) -> String
where
    S: HasSsaResult,
{
    let mut lines = Vec::new();
    let indent_str = ctx.indent_str();
    let clear_to_end_code = "\x1b[K";

    let callers_comment = format_callers_comment(model, function.function_id());

    // Format signature
    let signature = format!(
        "{}{}{} {{{}",
        "fn ".color(ctx.colors().keyword),
        function
            .function_id()
            .to_string()
            .color(ctx.colors().function),
        format_signature(function, ctx),
        clear_to_end_code
    );

    // Apply background color to callers_comment lines if not empty
    if !callers_comment.is_empty() {
        for line in callers_comment.lines() {
            let comment_line = format!("{indent_str}{line}{clear_to_end_code}")
                .on_color(ctx.colors().bg_color)
                .to_string();
            lines.push(comment_line);
        }
    }

    // Add the signature with background color
    let sig_line = format!("{indent_str}{signature}")
        .on_color(ctx.colors().bg_color)
        .to_string();
    lines.push(sig_line);

    // Format blocks
    let mut blocks_sorted: Vec<_> = function.blocks().map(|(_, b)| b).collect();
    blocks_sorted.sort_by_key(|b| b.block_id());

    for block in blocks_sorted {
        lines.push(format_block(block, &ctx.indented()));
    }

    // Add closing brace
    let close_line = format!(
        "{}{}{}",
        indent_str,
        "}".color(ctx.colors().low_prio),
        clear_to_end_code
    )
    .on_color(ctx.colors().bg_color)
    .to_string();
    lines.push(close_line);

    lines.join("\n")
}

fn format_callers_comment<S: ModelState + 'static>(
    model: &Model<S>,
    function_id: FunctionId,
) -> String
where
    S: 'static,
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

fn format_constant(value: i128, ctx: &FormattingContext) -> String {
    value
        .to_string()
        .color(ctx.colors().const_color)
        .to_string()
}

pub fn format_memory_reference(mem_ref: &MemoryReference, ctx: &FormattingContext) -> String {
    match mem_ref {
        MemoryReference::StackRelative(offset) => {
            if *offset == 0 {
                "[R]".color(ctx.colors().variable).to_string()
            } else if *offset > -1 {
                format!("[R+{offset}]")
                    .color(ctx.colors().variable)
                    .to_string()
            } else {
                format!("[R{offset}]")
                    .color(ctx.colors().variable)
                    .to_string()
            }
        }
        MemoryReference::Global(addr) => {
            format!("[{addr}]").color(ctx.colors().variable).to_string()
        }
        MemoryReference::Pointer(addr) => {
            format!("p{addr}").color(ctx.colors().variable).to_string()
        }
        MemoryReference::Deref(expr) => format!("*{}", format_expression(expr.as_ref(), ctx)),
    }
}

pub fn format_versioned_reference(
    reference: VersionedMemoryReference,
    ctx: &FormattingContext,
) -> String {
    // Add the version
    let mem_ref = reference.to_memory_reference();
    format!(
        "{}_{}",
        format_memory_reference(&mem_ref, ctx),
        reference.version.to_string().color(ctx.colors().type_color)
    )
}

// --- Public API ---

pub fn pretty_print_ssa_with_config<S: ModelState + 'static>(
    model: &Model<S>,
    config: PrettyPrintConfig,
) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    format_program(model, &config)
}

pub fn pretty_print_ssa<S: ModelState + 'static>(model: &Model<S>) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    let config = PrettyPrintConfig {
        colors: Colors::default(),
        show_types: false,
        show_vars: false,
        indent_width: 4,
    };
    pretty_print_ssa_with_config(model, config)
}

pub fn pretty_print_folded_ssa_with_config<S: ModelState + 'static>(
    model: &Model<S>,
    config: PrettyPrintConfig,
) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    format_program(model, &config)
}

pub fn pretty_print_folded_ssa<S: ModelState + 'static>(model: &Model<S>) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    let config = PrettyPrintConfig {
        colors: Colors::default(),
        show_types: false,
        show_vars: false,
        indent_width: 4,
    };
    pretty_print_folded_ssa_with_config(model, config)
}

pub fn pretty_print_with_types<S: ModelState + 'static>(model: &Model<S>) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    let config = PrettyPrintConfig {
        colors: Colors::default(),
        show_types: true,
        show_vars: false,
        indent_width: 4,
    };
    pretty_print_ssa_with_config(model, config)
}

// --- Backward compatibility functions ---

pub fn pretty_print_ssa_stdout<S: ModelState + 'static>(model: &Model<S>)
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    println!("{}", pretty_print_ssa(model));
}

pub fn pretty_print_with_types_stdout<S: ModelState + 'static>(model: &Model<S>)
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    println!("{}", pretty_print_with_types(model));
}
