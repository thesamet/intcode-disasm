use std::str::FromStr;

use clap::{Parser, Subcommand};
use colored::Colorize;
use itertools::Itertools;
use rustyline::DefaultEditor;
use tabled::settings::{object::Columns, Span, Style, Width};

use crate::disasm::v3::{
    common::formatting::ContextualPrettyPrint, type_inference::TypeVarState, FunctionId,
};

use super::v3::{
    control_flow::FunctionView,
    model::{Model, TypeInferenceComplete},
    type_inference::Type,
};

#[derive(Subcommand, Debug, Clone)]
enum Command {
    #[clap(alias = "l")]
    List { function: Option<FunctionId> },
    #[clap(alias = "f")]
    Functions,
    #[clap(alias = "tvs")]
    TypeVars { function: FunctionId },
}

impl FromStr for FunctionId {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        s.parse::<usize>()
            .map(FunctionId::new)
            .map_err(|e| format!("Failed to parse FunctionId: {}", e))
    }
}

#[derive(Parser, Clone, Debug)]
struct ReplLine {
    #[clap(subcommand)]
    command: Command,
}

pub fn repl(model: Model<TypeInferenceComplete>) {
    let mut editor = DefaultEditor::new().expect("Failed to create editor");
    let history_path = "history.txt";

    if editor.load_history(history_path).is_err() {
        println!("No previous history found.");
    }

    loop {
        let readline = editor.readline(">> ");
        match readline {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                editor.add_history_entry(line.as_str()).unwrap();
                match ReplLine::try_parse_from(std::iter::once(">>").chain(line.split_whitespace()))
                {
                    Ok(cmd) => match run_command(cmd, &model) {
                        Ok(_) => {}
                        Err(err) => {
                            println!("{}", err.red())
                        }
                    },
                    Err(err) => {
                        println!("{}", err)
                    }
                }
                // Here you would parse and evaluate the line against the model
            }
            Err(rustyline::error::ReadlineError::Interrupted) => {
                break;
            }
            Err(rustyline::error::ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    editor
        .save_history(history_path)
        .expect("Failed to save history");
}

fn get_function<'a>(
    model: &'a Model<TypeInferenceComplete>,
    function_id: &FunctionId,
) -> Result<FunctionView<'a, TypeInferenceComplete>, String> {
    model
        .get_function(function_id)
        .ok_or_else(|| format!("Function {} does not exist", function_id))
}

fn format_bounds<'a, I>(v: I) -> String
where
    I: IntoIterator<Item = &'a Type>,
{
    let v = v.into_iter().sorted().collect_vec();
    let out = format!("{}", v.iter().join(", "));
    if out.len() > 30 {
        format!("{}", v.iter().join(",\n"))
    } else {
        out
    }
}

fn run_command(cmd: ReplLine, model: &Model<TypeInferenceComplete>) -> Result<(), String> {
    match cmd.command {
        Command::List { function } => match function {
            Some(function_id) => {
                let fu = get_function(model, &function_id)?;
                println!("{}", fu.pretty_print());
            }
            None => {
                println!("{}", model.pretty_print());
            }
        },
        Command::Functions => {
            for (id, _) in model.functions().sorted_by_key(|f| f.0) {
                println!("{}", id);
            }
        }
        Command::TypeVars { function } => {
            let _ = get_function(model, &function)?;
            let ti = model.type_inference_result();
            use tabled::{Table, Tabled};

            #[derive(Tabled)]
            struct TypeVarRow {
                id: String,
                function: String,
                inst: String,
                kind: String,
                lower: String,
                upper: String,
            }

            let mut data = Vec::new();
            let mut converged_rows = Vec::new();
            for (row, (tv, tv_node)) in ti
                .type_var_nodes
                .iter()
                .filter(|(_, n)| n.function_id == function)
                .sorted_by_key(|(id, _)| *id)
                .enumerate()
            {
                let state = ti.type_var_states.get(tv).unwrap();

                data.push(TypeVarRow {
                    id: format!("{}", tv),
                    function: format!("{}", tv_node.function_id),
                    inst: format!("{}", tv_node.instruction_id),
                    kind: format!("{}", tv_node.kind),
                    lower: match state {
                        TypeVarState::Bounds { lower_bounds, .. } => format_bounds(lower_bounds),
                        TypeVarState::Converged(ty) => {
                            converged_rows.push(row);
                            format!("{}", ty).green().to_string()
                        }
                    },
                    upper: match state {
                        TypeVarState::Bounds { upper_bounds, .. } => format_bounds(upper_bounds),
                        _ => "".to_string(),
                    },
                });
            }
            let mut table = Table::new(data);
            table
                .with(Style::modern())
                .modify(Columns::new(4..6), Width::wrap(30))
                .modify(Columns::single(3), Width::wrap(15));

            for row in converged_rows {
                table.modify((row + 1, 4), Span::column(2));
                table.modify((row + 1, 4), Width::wrap(50));
            }

            println!("{}", table.to_string());
        }
    }
    Ok(())
}
