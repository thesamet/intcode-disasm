use colored::*;
use itertools::Itertools;

use super::{
    instructions::{GenericInstruction, InstructionKind},
    model::ProgramModel,
    ssa_form::{PhiFunction, SsaBlock, SsaFunction, SsaVar},
};

struct PrettyPrinter<'a> {
    model: &'a ProgramModel,
    show_type_vars: bool,
}

impl<'a> PrettyPrinter<'a> {
    fn format_ssa_var(&self, var: &SsaVar) -> String {
        let typ = if let Some(type_info) = self.model.get_type_inference_result() {
            if self.show_type_vars {
                type_info.get_type_for_ssavar(var)
            } else {
                type_info.get_type_for_ssavar(var)
            }
        } else {
            None
        };

        let typ = match typ {
            Some(typ) => format!(": {}", typ),
            None => "".to_string(),
        };
        let debug_marker = var
            .operand
            .debug_marker
            .as_ref()
            .map(|m| format!("'{} ", m).yellow())
            .unwrap_or_default();
        match var.operand.kind {
            super::instructions::OperandKind::RelativeMemory(offset) => {
                if offset == 0 {
                    "[R]".cyan().to_string()
                } else if offset > -1 {
                    format!("{}[R+{}]_{}{}", debug_marker, offset, var.version, typ)
                        .cyan()
                        .to_string()
                } else {
                    format!("{}[R{}]_{}{}", debug_marker, offset, var.version, typ)
                        .blue()
                        .to_string()
                }
            }
            super::instructions::OperandKind::Memory(addr) => {
                format!("{}[{}]_{}{}", debug_marker, addr, var.version, typ)
                    .purple()
                    .to_string()
            }
            super::instructions::OperandKind::Immediate(val) => {
                format!("{}{}", debug_marker, val).green().to_string()
            }
            super::instructions::OperandKind::Deref(addr) => {
                format!("{}*{}{}", debug_marker, addr, typ)
                    .bright_red()
                    .to_string()
            }
        }
    }

    fn format_phi_function(&self, phi: &PhiFunction) -> String {
        let inputs = phi
            .inputs
            .iter()
            .sorted()
            .map(|(block_id, var)| format!("{}: {}", block_id, self.format_ssa_var(var)))
            .join(", ");
        format!("{} = φ({})", self.format_ssa_var(&phi.result), inputs)
    }

    fn format_instruction(&self, instr: &GenericInstruction<SsaVar>) -> String {
        match &instr.kind {
            InstructionKind::Add(a, b, c) => {
                format!(
                    "{} = {} + {}",
                    self.format_ssa_var(c),
                    self.format_ssa_var(a),
                    self.format_ssa_var(b)
                )
            }
            InstructionKind::Mul(a, b, c) => {
                format!(
                    "{} = {} * {}",
                    self.format_ssa_var(c),
                    self.format_ssa_var(a),
                    self.format_ssa_var(b)
                )
            }
            InstructionKind::Input(a) => {
                format!("{} = input()", self.format_ssa_var(a))
            }
            InstructionKind::Output(a) => {
                format!("output({})", self.format_ssa_var(a))
            }
            InstructionKind::JumpIfTrue(cond, target) => {
                format!(
                    "if {} goto {}",
                    self.format_ssa_var(cond),
                    self.format_ssa_var(target)
                )
            }
            InstructionKind::JumpIfFalse(cond, target) => {
                format!(
                    "if !{} goto {}",
                    self.format_ssa_var(cond),
                    self.format_ssa_var(target)
                )
            }
            InstructionKind::LessThan(a, b, c) => {
                format!(
                    "{} = {} < {}",
                    self.format_ssa_var(c),
                    self.format_ssa_var(a),
                    self.format_ssa_var(b)
                )
            }
            InstructionKind::Equals(a, b, c) => {
                format!(
                    "{} = {} == {}",
                    self.format_ssa_var(c),
                    self.format_ssa_var(a),
                    self.format_ssa_var(b)
                )
            }
            InstructionKind::AdjustRelativeBase(a) => {
                format!("R += {}", self.format_ssa_var(a))
            }
            InstructionKind::Halt => "halt".red().to_string(),
            InstructionKind::Data(values) => {
                format!(
                    "DATA {}",
                    values.iter().map(|v| v.to_string().green()).join(", ")
                )
            }
            InstructionKind::Goto(target) => {
                format!("goto {}", self.format_ssa_var(target))
            }
            InstructionKind::Assign(target, source) => {
                format!(
                    "{} = {}",
                    self.format_ssa_var(target),
                    self.format_ssa_var(source)
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
                            .map(|v| self.format_ssa_var(v))
                            .join(", "),
                    )
                }
                Some(return_values) if return_values.len() == 1 => {
                    format!(
                        "{}",
                        return_values
                            .iter()
                            .map(|v| self.format_ssa_var(v))
                            .join(", ")
                    )
                }
                Some(_) => format!("void").red().to_string(),
                None => format!("unknown"),
            };
            format!(
                "({}) -> {}",
                ca.parameter_entry_vars
                    .values()
                    .sorted()
                    .map(|v| self.format_ssa_var(v))
                    .join(", "),
                rets
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
        show_type_vars: false,
    };
    printer.print_ssa();
}

pub fn pretty_print_type_vars(model: &ProgramModel) {
    let printer = PrettyPrinter {
        model,
        show_type_vars: true,
    };
    printer.print_ssa();
}
