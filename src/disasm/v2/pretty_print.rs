use colored::*;
use itertools::Itertools;

use super::{
    control_flow::PredecessorKind,
    instructions::{GenericInstruction, InstructionKind},
    model::ProgramModel,
    // Import SsaOperand and related types
    ssa_form::{PhiFunction, SsaBlock, SsaFunction, SsaOperand, SsaOperandKind, SsaVarKind},
};

struct PrettyPrinter<'a> {
    model: &'a ProgramModel,
    show_types: bool,
}

impl<'a> PrettyPrinter<'a> {
    // Format SsaOperand which now has kind and origin_info
    fn format_ssa_operand(&self, ssa_op: &SsaOperand) -> String {
        match ssa_op.kind {
            SsaOperandKind::Constant(val) => format!("{}", val).green().to_string(),
            SsaOperandKind::Variable(ref var) => {
                // Formatting logic for SsaVar
                let typ = if let Some(type_info) = self.model.get_type_inference_result() {
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

                // Debug marker is now in origin_info
                let debug_marker = var
                    .origin_info
                    .debug_marker
                    .as_ref()
                    .map(|m| format!("'{} ", m).yellow())
                    .unwrap_or_default();

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
                    SsaVarKind::Deref {
                        address,
                        address_version,
                    } => format!(
                        "{}*[{}_{}]_{}{}",
                        debug_marker, address, address_version, var.version, typ_str
                    )
                    .bright_red()
                    .to_string(),
                }
            }
        }
    }

    fn format_phi_function(&self, phi: &PhiFunction) -> String {
        let inputs = phi
            .inputs
            .iter()
            .sorted_by_key(|(pred_kind, _)| pred_kind.source_block_id())
            .map(|(pred_kind, ssa_op)| {
                // Now iterates over SsaOperand
                let source_id = pred_kind.source_block_id();
                let call_marker = if matches!(pred_kind, PredecessorKind::FunctionCallReturns(_)) {
                    "(call)"
                } else {
                    ""
                };
                // Create a new SsaOperand with the SSA var
                let ssa_operand = SsaOperand {
                    kind: SsaOperandKind::Variable(*ssa_op),
                    origin_info: ssa_op.origin_info,
                };
                
                format!(
                    "{}{}: {}",
                    source_id,
                    call_marker,
                    self.format_ssa_operand(&ssa_operand)
                )
            })
            .join(", ");
        // Phi result is always an SsaVar, wrap it for formatting
        format!(
            "{} = φ({})",
            self.format_ssa_operand(&SsaOperand {
                kind: SsaOperandKind::Variable(phi.result),
                origin_info: phi.result.origin_info,
            }),
            inputs
        )
    }

    // Update to take GenericInstruction<SsaOperand>
    fn format_instruction(&self, instr: &GenericInstruction<SsaOperand>) -> String {
        // Use format_ssa_operand for all operands
        match &instr.kind {
            InstructionKind::Add(a, b, c) => {
                format!(
                    "{} = {} + {}",
                    self.format_ssa_operand(c),
                    self.format_ssa_operand(a),
                    self.format_ssa_operand(b)
                )
            }
            InstructionKind::Mul(a, b, c) => {
                format!(
                    "{} = {} * {}",
                    self.format_ssa_operand(c),
                    self.format_ssa_operand(a),
                    self.format_ssa_operand(b)
                )
            }
            InstructionKind::Input(a) => {
                format!("{} = input()", self.format_ssa_operand(a))
            }
            InstructionKind::Output(a) => {
                format!("output({})", self.format_ssa_operand(a))
            }
            InstructionKind::JumpIfTrue(cond, target) => {
                format!(
                    "if {} goto {}",
                    self.format_ssa_operand(cond),
                    self.format_ssa_operand(target)
                )
            }
            InstructionKind::JumpIfFalse(cond, target) => {
                format!(
                    "if !{} goto {}",
                    self.format_ssa_operand(cond),
                    self.format_ssa_operand(target)
                )
            }
            InstructionKind::LessThan(a, b, c) => {
                format!(
                    "{} = {} < {}",
                    self.format_ssa_operand(c),
                    self.format_ssa_operand(a),
                    self.format_ssa_operand(b)
                )
            }
            InstructionKind::Equals(a, b, c) => {
                format!(
                    "{} = {} == {}",
                    self.format_ssa_operand(c),
                    self.format_ssa_operand(a),
                    self.format_ssa_operand(b)
                )
            }
            InstructionKind::AdjustRelativeBase(a) => {
                format!("R += {}", self.format_ssa_operand(a))
            }
            InstructionKind::Halt => "halt".red().to_string(),
            InstructionKind::Data(values) => {
                format!(
                    "DATA {}",
                    values.iter().map(|v| v.to_string().green()).join(", ")
                )
            }
            InstructionKind::Goto(target) => {
                format!("goto {}", self.format_ssa_operand(target))
            }
            InstructionKind::Assign(target, source) => {
                format!(
                    "{} = {}",
                    self.format_ssa_operand(target),
                    self.format_ssa_operand(source)
                )
            }
        }
    }

    fn format_block(&self, block: &SsaBlock) -> String {
        let mut lines = Vec::new();

        // Block header with line number in gray
        lines.push(format!(
            "{}:",
            format!("{}", block.original_id.index()).blue()
        ));

        // Phi functions
        for phi in &block.phi_functions {
            lines.push(format!("{:<8}{}", "", self.format_phi_function(phi)));
        }

        // Instructions
        for instr in &block.instructions {
            lines.push(format!("{:<8}{}", "", self.format_instruction(instr)));
        }

        lines.join("\n")
    }

    fn format_function(&self, function: &SsaFunction) -> String {
        let mut blocks: Vec<_> = function.blocks.values().collect();
        blocks.sort_by_key(|b| b.original_id);

        blocks.iter().map(|b| self.format_block(b)).join("\n\n")
    }

    pub fn format_call_info(&self, function: &SsaFunction) -> String {
        let ca = self
            .model
            .get_function_call_analysis()
            .and_then(|m| m.callee_info.get(&function.original_id));

        if let Some(ca) = ca {
            let return_values = self
                .model
                .get_function_call_analysis()
                .and_then(|m| m.get_effective_return_values(function.original_id));
            let rets = match return_values {
                Some(return_values) if return_values.len() > 1 => {
                    format!(
                        "({})",
                        return_values
                            .iter()
                            // Return values are SsaVar, wrap for formatting
                            .map(|v| self.format_ssa_operand(&SsaOperand {
                                kind: SsaOperandKind::Variable(*v),
                                origin_info: v.origin_info,
                            }))
                            .join(", "),
                    )
                }
                Some(return_values) if return_values.len() == 1 => return_values
                    .iter()
                    // Return values are SsaVar, wrap for formatting
                    .map(|v| self.format_ssa_operand(&SsaOperand {
                        kind: SsaOperandKind::Variable(*v),
                        origin_info: v.origin_info,
                    }))
                    .join(", ")
                    .to_string(),
                Some(_) => "void".to_string().red().to_string(), // Empty return_values vec
                None => "unknown".to_string(),
            };
            format!(
                "({}) -> {}",
                ca.parameter_entry_vars
                    .values()
                    .sorted()
                    // Parameter entry vars are SsaVar, wrap for formatting
                    .map(|v| self.format_ssa_operand(&SsaOperand {
                        kind: SsaOperandKind::Variable(*v),
                        origin_info: v.origin_info,
                    }))
                    .join(", "),
                rets // Already formatted string
            )
        } else {
            "".to_string()
        }
    }

    pub fn format_callers_comment(&self, function: &SsaFunction) -> String {
        let callers = self
            .model
            .get_function_call_analysis()
            .map(|m| {
                m.call_site_info
                    .iter()
                    .filter(|(_, cs)| cs.target_function_id == Some(function.original_id))
                    .collect_vec()
            })
            .unwrap_or_default();

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
    }

    fn print_ssa(&self) {
        let ssa = self
            .model
            .get_ssa_result()
            .expect("No SSA result available");

        let mut functions: Vec<_> = ssa.functions.values().collect();
        functions.sort_by_key(|f| f.original_id);

        let s = functions
            .iter()
            .map(|f| -> String {
                format!(
                    "{}fn {}{} {{\n{}\n}}",
                    self.format_callers_comment(f),
                    f.original_id,
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
pub fn pretty_print_ssa(model: &ProgramModel) {
    let printer = PrettyPrinter {
        model,
        show_types: false,
    };
    printer.print_ssa();
}

pub fn pretty_print_with_types(model: &ProgramModel) {
    let printer = PrettyPrinter {
        model,
        show_types: true,
    };
    printer.print_ssa();
}
