use colored::*;
use itertools::Itertools;

use crate::disasm::v3::{
    control_flow::{BlockView, FunctionView},
    model::{
        HasControlFlowGraphResult,
        HasSsaResult, Model, ModelState,
    }, PredecessorKind,
};

use super::{
    instructions::{Expression, Instruction, InstructionNode},
    ssa_form::{
        PhiFunction, SsaMemoryReference, SsaOperandKind, SsaVarKind,
        VersionedMemoryReference,
    },
};

struct PrettyPrinter<'a, S: ModelState> {
    model: &'a Model<S>,
    show_types: bool,
    show_vars: bool,
}

impl<'a, S: ModelState> PrettyPrinter<'a, S> {
    fn format_expression(&self, expr: &Expression<SsaMemoryReference>) -> String {
        match expr {
            Expression::Constant(value) => format!("{}", value).green().to_string(),
            Expression::Addressable(addr) => self.format_addressable(addr),
            Expression::Binary { op, lhs, rhs } => format!(
                "({} {} {})",
                self.format_expression(lhs),
                op,
                self.format_expression(rhs)
            ),
            Expression::Unary { op, arg } => {
                format!("{}({})", op, self.format_expression(arg))
            }
            Expression::Input() => "input()".to_string(),
            Expression::DebugMarker(marker, expr) => {
                format!(
                    "'{} ({})",
                    marker.to_string().yellow(),
                    self.format_expression(expr)
                )
            }
        }
    }

    fn format_addressable(&self, addressable: &SsaMemoryReference) -> String {
        match addressable {
            SsaMemoryReference::Versioned(a) => self.format_versioned_addressable(a),
            SsaMemoryReference::Deref(expr) => format!("*({})", self.format_expression(expr)),
        }
    }

    fn format_versioned_addressable(&self, addressable: &VersionedMemoryReference) -> String {
        format!("{}_{}", addressable.kind, addressable.version)
    }

    fn format_ssa_addressable_kind(&self, op_kind: &SsaOperandKind) -> String {
        match op_kind {
            SsaOperandKind::Constant(val) => format!("{}", val).green().to_string(),
            SsaOperandKind::Deref(ptr) => format!(
                "*{}",
                self.format_ssa_addressable_kind(&SsaOperandKind::Variable(*ptr))
            ),
            SsaOperandKind::Variable(ref var) => {
                // Formatting logic for SsaVar
                let typ = if let Some(type_info) = self.model.type_inference_result() {
                    if self.show_types {
                        type_info.get_type_for_ssavar(var) // Type info is per-variable
                    } else {
                        None
                    }
                } else {
                    None
                };

                let typ_str = match typ {
                    Some(typ) => format!(": {}", typ),
                    None => "".to_string(),
                };

                let debug_marker = var
                    .origin_info
                    .debug_marker
                    .as_ref()
                    .map(|m| format!("'{} ", m).yellow())
                    .unwrap_or_default();

                if !self.show_vars {
                    match var.kind {
                        SsaVarKind::RelativeMemory(offset) => {
                            if offset == 0 {
                                "[R]".cyan().to_string() // Version not shown for [R]_0 usually
                            } else if offset > -1 {
                                format!("{}[R+{}]_{}{}", debug_marker, offset, var.version, typ_str)
                                    .cyan()
                                    .to_string()
                            } else {
                                format!("{}[R{}]_{}{}", debug_marker, offset, var.version, typ_str)
                                    .blue()
                                    .to_string()
                            }
                        }
                        SsaVarKind::Memory(addr) => {
                            format!("{}[{}]_{}{}", debug_marker, addr, var.version, typ_str)
                                .purple()
                                .to_string()
                        }
                        SsaVarKind::Pointer(addr) => {
                            format!("{}p{}_{}{}", debug_marker, addr, var.version, typ_str)
                                .purple()
                                .to_string()
                        }
                        .bright_red()
                        .to_string(),
                    }
                } else if var.kind.get_relative_memory() == Some(0) {
                    "R".to_string().cyan().to_string()
                } else {
                    let clusters = &self.model.variable_merger_result().unwrap();
                    let cluster_id = clusters
                        .variable_to_cluster
                        .get(var)
                        .unwrap_or_else(|| panic!("No entry found for key {}", var));
                    let name = &clusters
                        .clusters
                        .get(cluster_id)
                        .unwrap_or_else(|| {
                            panic!("Missing cluster id {} for key {}", cluster_id, var)
                        })
                        .cluster_name;
                    format!("{}{}", name, typ_str)
                }
            }
        }
    }

    fn format_phi_function(&self, phi: &PhiFunction) -> String {
        let inputs = phi
            .inputs
            .iter()
            .sorted_by_key(|(pred_kind, _)| pred_kind.source_block_id())
            .map(|(pred_kind, addressable)| {
                // Now iterates over SsaOperand
                let source_id = pred_kind.source_block_id();
                let call_marker = if matches!(pred_kind, PredecessorKind::FunctionCallReturns(_)) {
                    "(call)"
                } else {
                    ""
                };

                format!(
                    "{}{}: {}",
                    source_id,
                    call_marker,
                    self.format_versioned_addressable(addressable)
                )
            })
            .join(", ");
        // Phi result is always an SsaVar, wrap it for formatting
        format!(
            "{} = φ({})",
            self.format_versioned_addressable(&phi.result),
            inputs
        )
    }

    // Update to take GenericInstruction<SsaOperand>
    fn format_instruction(&self, instr: &InstructionNode<SsaMemoryReference>) -> String {
        // Use format_ssa_operand for all operands
        match &instr.kind {
            Instruction::Assign { target, src, .. } => {
                format!(
                    "{} = {}",
                    self.format_addressable(target),
                    self.format_expression(src)
                )
            }
            Instruction::If {
                cond,
                then_addr,
                else_addr,
            } => {
                format!(
                    "if {} goto {} else goto {}",
                    self.format_expression(cond),
                    then_addr,
                    else_addr
                )
            }
            Instruction::Goto(addr) => {
                format!("goto {}", addr)
            }
            Instruction::Call { addr, return_to } => {
                format!(
                    "call {} return to {}",
                    self.format_expression(addr),
                    return_to
                )
            }
            Instruction::Output(expr) => {
                format!("output {}", self.format_expression(expr))
            }
            Instruction::Return => "return".to_string(),
            Instruction::Halt => "halt".to_string(),
        }
    }

    fn format_block(&self, block: &BlockView<S>) -> String
    where
        S: HasSsaResult,
    {
        let mut lines = Vec::new();

        // Block header with line number in gray
        lines.push(format!(
            "{}:",
            format!("{}", block.block_id().index()).blue()
        ));

        // Phi functions
        if !self.show_vars {
            for phi in &block.ssa().phi_functions {
                lines.push(format!("{:<8}{}", "", self.format_phi_function(phi)));
            }
        }

        // Instructions
        for instr in &block.ssa().instructions {
            if self.show_vars {
                match &instr.kind {
                    Instruction::Assign {
                        target: _, // Renamed from target_operand
                        src: _,    // Renamed from source_operand
                        target_debug_marker: _,
                    } => {
                        // panic!("Migration uncomment") // Commented out as per migration guidelines
                        // skip a == b where a and b are the same variable
                        /* Migration: Requires VariableMergerResult and SsaMemoryReference details
                        if let (Some(target), Some(src)) = (target.as_variable(), .as_variable()) {
                            let var_to_cluster = &self
                                .model
                                .get_variable_merger_result()
                                .unwrap()
                                .variable_to_cluster;
                            let ca = var_to_cluster.get(a).unwrap();
                            let cb = var_to_cluster.get(b).unwrap();
                            if ca == cb {
                                continue;
                            }
                        }
                        */
                    }
                    _ => {}
                }
            }
            lines.push(format!("{:<8}{}", "", self.format_instruction(instr)));
        }

        lines.join("\n")
    }

    fn format_function(&self, function: &FunctionView<S>) -> String
    where
        S: HasSsaResult,
    {
        let mut blocks: Vec<_> = function.blocks().map(|b| b.1).collect();
        blocks.sort_by_key(|b| b.block_id());

        blocks.iter().map(|b| self.format_block(b)).join("\n\n")
    }

    pub fn format_call_info(&self, function: &FunctionView<S>) -> String {
        // return "".to_string(); // Removed unreachable return
        let args_rets: Option<String> = self
            .model
            .type_inference_result()
            // .and_then(|m| m.get_function_signature(&function.original_id));
            .and_then(|_m| panic!("Migration uncomment")); // Use _m to avoid unused variable warning

        // Return empty string during migration
        "".to_string()
        /* Migration: Commented out unreachable code block
        let sig = if let Some((args, rets)) = args_rets {
            let mut args = args.iter().map(|(_, v, _)| {
                self.format_addressable(&SsaOperand {
                    kind: SsaOperandKind::Variable(*v),
                    origin_info: v.origin_info,
                })
                .to_string()
            });
            let mut rets = rets.iter().map(|(_, v, _)| {
                self.format_addressable(&SsaOperand {
                    kind: SsaOperandKind::Variable(*v),
                    origin_info: v.origin_info,
                })
                .to_string()
            });
            format!(
                "({}) -> {}",
                args.join(", "),
                match rets.len() {
                    0 => "void".to_string(),
                    1 => rets.exactly_one().unwrap().to_string(),
                    _ => format!("({})", rets.join(", ")),
                }
            )
        } else {
            "(unknown) -> (unknown)".to_string()
        };
        sig
        */
    }

    pub fn format_callers_comment(&self, function: &FunctionView<S>) -> String
    where
        S: HasControlFlowGraphResult + HasSsaResult,
    {
        return "NO CALLERS FOR NOW MIGRATION".to_string();
        /*
        let callers = self
            .model
            .function_call_analysis_result()
            .blocks
            .iter()
            .filter(|(_, cs)| cs.target_function_id == Some(function.function_id()))
            .collect_vec();

        let mut out = vec![];
        for (block_id, csi) in &callers {
            out.push(format!(
                "// at {}: {} -> {}\n",
                block_id,
                csi.argument_writes.values().sorted().join(", "),
                csi.return_reads.values().sorted().join(", ")
            ));
        }

        out.join("")
        */
    }

    fn print_ssa(&self)
    where
        S: HasSsaResult + HasControlFlowGraphResult,
    {
        let mut functions: Vec<_> = self.model.functions().map(|(_, f)| f).collect();
        functions.sort_by_key(|f| f.function_id());

        let s = functions
            .iter()
            .map(|f| -> String {
                format!(
                    "{}fn {}{} {{\n{}\n}}",
                    self.format_callers_comment(f),
                    f.function_id(),
                    self.format_call_info(f),
                    self.format_function(f)
                        .lines()
                        .map(|l| format!("    {}", l))
                        .join("\n")
                )
            })
            .join("\n\n");
        println!("{}", s);
    }
}
pub fn pretty_print_ssa<S: ModelState>(model: &Model<S>)
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    let printer = PrettyPrinter {
        model,
        show_types: false,
        show_vars: false,
    };
    printer.print_ssa();
}

pub fn pretty_print_with_types<S: ModelState>(model: &Model<S>)
where
    S: HasSsaResult + HasControlFlowGraphResult,
{
    let printer = PrettyPrinter {
        model,
        show_types: true,
        show_vars: false,
    };
    printer.print_ssa();
}
