use itertools::Itertools;
use colored::*;

use super::{
    instructions::{GenericInstruction, InstructionKind},
    model::ProgramModel,
    ssa_form::{PhiFunction, SsaBlock, SsaFunction, SsaVar},
};

fn format_ssa_var(var: &SsaVar) -> String {
    match var.operand.kind {
        // Highlight relative memory accesses in cyan
        super::instructions::OperandKind::RelativeMemory(offset) => {
            if offset == 0 {
                "[R]".cyan().to_string()
            } else if offset > 0 {
                format!("[R+{}]", offset).cyan().to_string()
            } else {
                format!("[R{}]", offset).cyan().to_string()
            }
        }
        // Highlight memory accesses in yellow
        super::instructions::OperandKind::Memory(addr) => {
            format!("[{}]", addr).yellow().to_string()
        }
        // Highlight immediate values in green
        super::instructions::OperandKind::Immediate(val) => {
            format!("{}", val).green().to_string()
        }
        // Highlight dereferences in magenta
        super::instructions::OperandKind::Deref(addr) => {
            format!("*{}", addr).magenta().to_string()
        }
    }
}

fn format_phi_function(phi: &PhiFunction) -> String {
    let inputs = phi
        .inputs
        .iter()
        .map(|(block_id, var)| format!("{}: {}", block_id, format_ssa_var(var)))
        .join(", ");
    format!(
        "{} = φ({})",
        format_ssa_var(&phi.result),
        inputs
    )
}

fn format_instruction(instr: &GenericInstruction<SsaVar>) -> String {
    match &instr.kind {
        InstructionKind::Add(a, b, c) => {
            format!(
                "{} = {} + {}",
                format_ssa_var(c),
                format_ssa_var(a),
                format_ssa_var(b)
            )
        }
        InstructionKind::Mul(a, b, c) => {
            format!(
                "{} = {} * {}",
                format_ssa_var(c),
                format_ssa_var(a),
                format_ssa_var(b)
            )
        }
        InstructionKind::Input(a) => {
            format!("{} = input()", format_ssa_var(a))
        }
        InstructionKind::Output(a) => {
            format!("output({})", format_ssa_var(a))
        }
        InstructionKind::JumpIfTrue(cond, target) => {
            format!(
                "if {} goto {}",
                format_ssa_var(cond),
                format_ssa_var(target)
            )
        }
        InstructionKind::JumpIfFalse(cond, target) => {
            format!(
                "if !{} goto {}",
                format_ssa_var(cond),
                format_ssa_var(target)
            )
        }
        InstructionKind::LessThan(a, b, c) => {
            format!(
                "{} = {} < {}",
                format_ssa_var(c),
                format_ssa_var(a),
                format_ssa_var(b)
            )
        }
        InstructionKind::Equals(a, b, c) => {
            format!(
                "{} = {} == {}",
                format_ssa_var(c),
                format_ssa_var(a),
                format_ssa_var(b)
            )
        }
        InstructionKind::AdjustRelativeBase(a) => {
            format!("R += {}", format_ssa_var(a))
        }
        InstructionKind::Halt => "halt".red().to_string(),
        InstructionKind::Data(values) => {
            format!("DATA {}", values.iter().map(|v| v.to_string().green()).join(", "))
        }
        InstructionKind::Goto(target) => {
            format!("goto {}", format_ssa_var(target))
        }
        InstructionKind::Assign(target, source) => {
            format!(
                "{} = {}",
                format_ssa_var(target),
                format_ssa_var(source)
            )
        }
    }
}

fn format_block(block: &SsaBlock) -> String {
    let mut lines = Vec::new();

    // Block header with line number in gray
    lines.push(format!(
        "{}:",
        format!("{}", block.original_id.index()).blue()
    ));

    // Phi functions
    for phi in &block.phi_functions {
        lines.push(format!("{:<8}{}", "", format_phi_function(phi)));
    }

    // Instructions
    for instr in &block.instructions {
        lines.push(format!("{:<8}{}", "", format_instruction(instr)));
    }

    lines.join("\n")
}

fn format_function(function: &SsaFunction) -> String {
    let mut blocks: Vec<_> = function.blocks.values().collect();
    blocks.sort_by_key(|b| b.original_id);

    blocks.iter().map(|b| format_block(b)).join("\n\n")
}

pub fn pretty_print_ssa(model: &ProgramModel) -> String {
    let ssa = model.get_ssa_result().expect("No SSA result available");

    let mut functions: Vec<_> = ssa.functions.values().collect();
    functions.sort_by_key(|f| f.original_id);

    functions
        .iter()
        .map(|f| {
            format!(
                "function_{} {{\n{}\n}}",
                f.original_id,
                format_function(f)
                    .lines()
                    .map(|l| format!("    {}", l))
                    .join("\n")
            )
        })
        .join("\n\n")
}
