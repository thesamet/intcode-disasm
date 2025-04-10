use crate::disasm::code_printer::{self, CodePrinter};
use code_printer::CodeWriter as _;
use itertools::Itertools;

use super::{
    instructions::{GenericInstruction, InstructionKind, OperandKind},
    model::{BlockId, ProgramModel},
    ssa_form::SsaVar,
};

pub fn pretty_print_ssa(model: &ProgramModel) -> String {
    let mut printer = CodePrinter::new();

    for (function_id, function) in model
        .get_ssa_result()
        .unwrap()
        .functions
        .iter()
        .sorted_by_key(|(id, _)| id.index())
    {
        // Print function header
        printer.line(&format!("Function @{}:", function_id));

        let callee_info = model
            .get_function_call_analysis()
            .and_then(|fa| fa.callee_info.get(&function_id));
        if let Some(callee_info) = callee_info {
            printer.line(&format!(
                "parameters: ({}) returns: {}",
                callee_info.parameter_entry_vars.values().join(", "),
                callee_info.return_writes.values().join(", ")
            ));
        }

        // Sort blocks by address
        let mut block_ids: Vec<&BlockId> = function.blocks.keys().collect();
        block_ids.sort_by_key(|id| id.index());

        // Process each block
        for &block_id in &block_ids {
            let block = &function.blocks[block_id];

            // Print block header with a separator
            printer.line(&format!("Block {}: ", block_id.index()));

            // Print phi functions at the beginning of the block
            let mut indented = printer.indented();

            if !block.phi_functions.is_empty() {
                indented.line("# Phi functions:");
                for phi in &block.phi_functions {
                    let mut sources = Vec::new();
                    for (&pred_id, var) in &phi.inputs {
                        sources.push(format!("{}: {}", pred_id, var));
                    }

                    let sources_str = if sources.is_empty() {
                        "<empty>".to_string()
                    } else {
                        sources.join(", ")
                    };

                    indented.line(&format!("{} = φ({})", phi.result, sources_str));
                }
                indented.line(""); // Extra space after phi functions
            }

            // Print instructions
            if !block.instructions.is_empty() {
                indented.line("# Instructions:");
                for instr in &block.instructions {
                    let instruction_str = format!(
                        "{:<8}  {}",
                        format!("{}", instr.id.index()),
                        format!("{}", instr)
                    );
                    indented.line(&instruction_str);
                }
                indented.line(""); // Extra space after instructions
            }

            // Blank line between blocks
            printer.line("");
        }

        // Extra blank line between functions
        printer.line("");
    }

    printer.result()
}
