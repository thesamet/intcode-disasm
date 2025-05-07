use castaway::cast;
use colored::Colorize;
use itertools::Itertools;

use crate::disasm::v3::{
    common::formatting::{colors::Colors, pretty_print::{FormattingContext, PrettyPrintConfig}},
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
    ssa_form::{
        MemoryReferenceType, PhiFunction, SsaMemoryReference, SsaVar, SsaVarKind,
        VersionedMemoryReference,
    },
};

// --- Model Wrapper ---
// A wrapper that allows accessing the model during formatting
pub struct ModelPrinter<'a, S: ModelState + 'static> {
    model: &'a Model<S>,
    config: PrettyPrintConfig,
}

impl<'a, S: ModelState + 'static> ModelPrinter<'a, S> {
    pub fn new(model: &'a Model<S>) -> Self {
        Self { 
            model,
            config: PrettyPrintConfig::default(),
        }
    }
    
    pub fn with_config(model: &'a Model<S>, config: PrettyPrintConfig) -> Self {
        Self { model, config }
    }
}

// --- Operator Precedence Helpers ---
fn binary_op_precedence(op: &BinaryOperator) -> u8 {
    match op {
        BinaryOperator::Mul => 5,
        BinaryOperator::Add | BinaryOperator::Sub => 4,
        BinaryOperator::LessThan | BinaryOperator::LessThanOrEqual |
        BinaryOperator::GreaterThan | BinaryOperator::GreaterThanOrEqual => 2,
        BinaryOperator::Equals | BinaryOperator::NotEquals => 1,
    }
}

fn unary_op_precedence(_op: &UnaryOperator) -> u8 {
    6 // Unary operators typically have high precedence
}

// --- Expression Formatting ---
impl<'a, S: ModelState + 'static> ModelPrinter<'a, S> {
    fn format_expression(&self, expr: &Expression<SsaMemoryReference>, ctx: &FormattingContext) -> String {
        match expr {
            Expression::Constant(value) => {
                value.to_string().color(ctx.colors().const_color).to_string()
            }
            Expression::Addressable(addr) => self.format_memory_reference(addr, ctx),
            Expression::Binary { op, lhs, rhs } => {
                let op_str = op.to_string().color(ctx.colors().op_color).to_string();
                let op_prec = binary_op_precedence(op);

                let lhs_str = self.format_expression(lhs, &ctx.with_precedence(op_prec));
                let rhs_str = self.format_expression(rhs, &ctx.with_precedence(op_prec));

                let result = format!("{} {} {}", lhs_str, op_str, rhs_str);

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
                let arg_str = self.format_expression(arg, &ctx.with_precedence(op_prec));
                
                let result = format!("{}{}", op_str, arg_str);

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
                    self.format_expression(expr, ctx)
                )
            }
        }
    }
    
    // --- Memory Reference Formatting ---
    
    fn format_memory_reference(&self, reference: &SsaMemoryReference, ctx: &FormattingContext) -> String {
        match reference {
            SsaMemoryReference::Versioned(a) => self.format_versioned_reference(a, ctx),
            SsaMemoryReference::Deref(expr) => {
                format!(
                    "*{}",
                    self.format_expression(expr, ctx)
                )
            }
        }
    }
    
    fn format_versioned_reference(&self, reference: &VersionedMemoryReference, ctx: &FormattingContext) -> String {
        // Format the kind part
        let base = match reference.kind {
            MemoryReferenceType::RelativeMemory(offset) => {
                if offset == 0 {
                    "[R]".color(ctx.colors().variable).to_string()
                } else if offset > -1 {
                    format!("[R+{}]", offset).color(ctx.colors().variable).to_string()
                } else {
                    format!("[R{}]", offset).color(ctx.colors().variable).to_string()
                }
            },
            MemoryReferenceType::Memory(addr) => {
                format!("[{}]", addr).color(ctx.colors().variable).to_string()
            },
            MemoryReferenceType::Pointer(addr) => {
                format!("p{}", addr).color(ctx.colors().variable).to_string()
            },
        };
        
        // Add the version
        format!(
            "{}_{}",
            base, 
            reference.version.to_string().color(ctx.colors().low_prio)
        )
    }
    
    // --- SSA Variable Formatting ---
    
    fn format_ssa_var(&self, var: &SsaVar, ctx: &FormattingContext) -> String {
        let type_info_result = self.model.type_inference_result();
        let typ_str = if ctx.show_types() {
            type_info_result
                .and_then(|ti| ti.get_type_for_ssavar(var))
                .map_or_else(String::new, |t| {
                    format!(": {}", t.to_string().color(ctx.colors().type_color))
                })
        } else {
            String::new()
        };

        let debug_marker_str = var
            .origin_info
            .debug_marker
            .as_ref()
            .map(|m| format!("'{} ", m.to_string().color(ctx.colors().low_prio)))
            .unwrap_or_default();

        let var_version_str = format!("_{}", var.version)
            .color(ctx.colors().low_prio)
            .to_string();

        if !ctx.show_vars() {
            let base_name = match var.kind {
                SsaVarKind::RelativeMemory(offset) => {
                    if offset == 0 {
                        "[R]".color(ctx.colors().variable).to_string()
                    } else if offset > -1 {
                        format!("[R+{}]", offset).color(ctx.colors().variable).to_string()
                    } else {
                        format!("[R{}]", offset).color(ctx.colors().variable).to_string()
                    }
                }
                SsaVarKind::Memory(addr) => {
                    format!("[{}]", addr).color(ctx.colors().variable).to_string()
                }
                SsaVarKind::Pointer(addr) => {
                    format!("p{}", addr).color(ctx.colors().variable).to_string()
                }
            };
            format!("{}{}{}{}", debug_marker_str, base_name, var_version_str, typ_str)
        } else {
            // show_vars = true logic
            if var.kind.get_relative_memory() == Some(0) {
                format!("{}R{}{}", debug_marker_str, var_version_str, typ_str)
                    .color(ctx.colors().variable)
                    .to_string()
            } else if let Some(clusters) = self.model.variable_merger_result() {
                clusters
                    .variable_to_cluster
                    .get(var)
                    .and_then(|cluster_id| clusters.clusters.get(cluster_id))
                    .map_or_else(
                        || {
                            format!(
                                "{}{:?}{}{}", 
                                debug_marker_str, var.kind, var_version_str, typ_str
                            )
                            .color(ctx.colors().variable)
                            .to_string()
                        },
                        |cluster| {
                            format!("{}{}{}", debug_marker_str, cluster.cluster_name, typ_str)
                                .color(ctx.colors().variable)
                                .to_string()
                        },
                    )
            } else {
                format!(
                    "{}{:?}{}{}",
                    debug_marker_str, var.kind, var_version_str, typ_str
                )
                .color(ctx.colors().variable)
                .to_string()
            }
        }
    }
    
    // --- Phi Functions ---
    
    fn format_phi_function(&self, phi: &PhiFunction, ctx: &FormattingContext) -> String {
        let inputs_str = phi
            .inputs
            .iter()
            .sorted_by_key(|(pred_kind, _)| pred_kind.source_block_id())
            .map(|(pred_kind, addressable)| {
                let source_id_str = pred_kind.source_block_id().to_string();
                let call_marker_str =
                    if matches!(pred_kind, PredecessorKind::FunctionCallReturns(_)) {
                        "(call)".color(ctx.colors().low_prio).to_string()
                    } else {
                        String::new()
                    };
                format!(
                    "{}{}: {}",
                    source_id_str,
                    call_marker_str,
                    self.format_versioned_reference(addressable, ctx)
                )
            })
            .join(", ");

        format!(
            "{} {} φ({})",
            self.format_versioned_reference(&phi.result, ctx),
            "=".color(ctx.colors().op_color),
            inputs_str
        )
    }
    
    // --- Instructions ---
    
    fn format_instruction(&self, instr: &InstructionNode<SsaMemoryReference>, ctx: &FormattingContext) -> String {
        match &instr.kind {
            Instruction::Assign { target, src, .. } => {
                format!(
                    "{} {} {}",
                    self.format_memory_reference(target, ctx),
                    "=".color(ctx.colors().op_color),
                    self.format_expression(src, ctx)
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
                    self.format_expression(cond, ctx),
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
            Instruction::Call { addr, return_to } => {
                format!(
                    "{} {} {} {}",
                    "call".color(ctx.colors().keyword),
                    self.format_expression(addr, ctx),
                    "return to".color(ctx.colors().keyword),
                    return_to.to_string().color(ctx.colors().const_color)
                )
            }
            Instruction::Output(expr) => {
                format!(
                    "{} {}",
                    "output".color(ctx.colors().keyword),
                    self.format_expression(expr, ctx)
                )
            }
            Instruction::Return => "return".color(ctx.colors().keyword).to_string(),
            Instruction::Halt => "halt".color(ctx.colors().keyword).to_string(),
        }
    }
    
    // --- Block Level Formatting ---
    
    fn format_block(&self, block: &BlockView<S>, ctx: &FormattingContext) -> String 
    where 
        S: HasSsaResult 
    {
        let mut lines = Vec::new();
        let indent_str = ctx.indent_str();
        let inner_indent_str = " ".repeat(ctx.config.indent_width());
        let clear_to_end_code = "\x1b[K";

        // Block header with line number
        let block_header = format!(
            "{}{}:{}",
            indent_str,
            block.block_id().index().to_string().color(ctx.colors().low_prio),
            clear_to_end_code
        ).on_color(ctx.colors().bg_color).to_string();
        lines.push(block_header);

        // Phi functions
        if !ctx.show_vars() {
            for phi in &block.ssa().phi_functions {
                let phi_line = format!(
                    "{}{}{}{}",
                    indent_str,
                    inner_indent_str,
                    self.format_phi_function(phi, ctx),
                    clear_to_end_code
                ).on_color(ctx.colors().bg_color).to_string();
                lines.push(phi_line);
            }
            
            if !block.ssa().phi_functions.is_empty() {
                let blank_line = format!(
                    "{}{}{}",
                    indent_str,
                    inner_indent_str,
                    clear_to_end_code
                ).on_color(ctx.colors().bg_color).to_string();
                lines.push(blank_line);
            }
        }

        // Instructions
        for instr in &block.ssa().instructions {
            let instr_str = self.format_instruction(instr, ctx);
            if !instr_str.is_empty() {
                let instruction_line = format!(
                    "{}{}{:<5}        {}{}",
                    indent_str,
                    inner_indent_str,
                    instr.id.to_string().color(ctx.colors().low_prio),
                    instr_str,
                    clear_to_end_code
                ).on_color(ctx.colors().bg_color).to_string();
                lines.push(instruction_line);
            }
        }
        
        lines.join("\n")
    }
    
    // --- Function Call Info ---
    
    fn format_function_call_info(&self, _function: &FunctionView<S>, ctx: &FormattingContext) -> String {
        if !ctx.show_types() { return "".to_string(); }

        // This may need more implementation once we have access to the type info
        format!(
            "({}) -> ({})",
            "?".color(ctx.colors().low_prio),
            "?".color(ctx.colors().low_prio)
        )
    }
    
    // --- Caller Comments ---
    
    fn format_callers_comment(&self, function_id: FunctionId, _ctx: &FormattingContext) -> String
    where 
        S: 'static 
    {
        if let Ok(m_fca) = cast!(self.model, &Model<FunctionCallAnalysisComplete>) {
            let fca_result = m_fca.function_call_analysis_result();
            
            let callers = fca_result
                .blocks
                .iter()
                .filter(|(_, cs)| cs.target_function_id == Some(function_id))
                .map(|(block_id, csi)| {
                    format!(
                        "// at {}: {} -> {}",
                        block_id,
                        csi.argument_writes.values().sorted().join(", "),
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
    
    // --- Function Formatting ---
    
    fn format_function(&self, function: &FunctionView<S>, ctx: &FormattingContext) -> String
    where 
        S: HasSsaResult 
    {
        let mut lines = Vec::new();
        let indent_str = ctx.indent_str();
        let clear_to_end_code = "\x1b[K";

        let callers_comment = self.format_callers_comment(function.function_id(), ctx);

        // Format signature
        let signature = format!(
            "{}{}{} {{{}",
            "fn ".color(ctx.colors().keyword),
            function.function_id().to_string().color(ctx.colors().function),
            self.format_function_call_info(function, ctx),
            clear_to_end_code
        );
        
        // Apply background color to callers_comment lines if not empty
        if !callers_comment.is_empty() {
            for line in callers_comment.lines() {
                let comment_line = format!(
                    "{}{}{}",
                    indent_str,
                    line,
                    clear_to_end_code
                ).on_color(ctx.colors().bg_color).to_string();
                lines.push(comment_line);
            }
        }
        
        // Add the signature with background color
        let sig_line = format!("{}{}", indent_str, signature)
            .on_color(ctx.colors().bg_color)
            .to_string();
        lines.push(sig_line);

        // Format blocks
        let mut blocks_sorted: Vec<_> = function.blocks().map(|(_, b)| b).collect();
        blocks_sorted.sort_by_key(|b| b.block_id());

        for block in &blocks_sorted {
            lines.push(self.format_block(block, &ctx.indented()));
        }

        // Add closing brace
        let close_line = format!(
            "{}{}{}",
            indent_str,
            "}".color(ctx.colors().low_prio),
            clear_to_end_code
        ).on_color(ctx.colors().bg_color).to_string();
        lines.push(close_line);
        
        lines.join("\n")
    }
    
    // --- Program Level Formatting ---
    
    pub fn format_program(&self) -> String
    where 
        S: HasSsaResult + HasControlFlowGraphResult 
    {
        let ctx = FormattingContext::new(&self.config);
        let mut functions_sorted: Vec<_> = self.model.functions().map(|(_, f)| f).collect();
        functions_sorted.sort_by_key(|f| f.function_id());
        
        let clear_to_end_code = "\x1b[K";
        
        // Create a blank line with background color for separating functions
        let blank_line = format!("{}", clear_to_end_code)
            .on_color(ctx.colors().bg_color)
            .to_string();

        functions_sorted
            .iter()
            .map(|f| self.format_function(f, &ctx))
            .collect::<Vec<_>>()
            .join(&format!("\n{}\n", blank_line))
    }
}

// --- Public API ---

pub fn pretty_print_ssa_with_config<S: ModelState + 'static>(
    model: &Model<S>,
    config: PrettyPrintConfig,
) -> String
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    let printer = ModelPrinter::with_config(model, config);
    printer.format_program()
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