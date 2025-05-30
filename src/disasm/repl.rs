use clap::{arg, Parser, Subcommand};
use colored::Colorize;
use itertools::Itertools;
use rustyline::DefaultEditor;
use tabled::settings::{object::Columns, Span, Style, Width};

use crate::disasm::v3::{
    common::formatting::ContextualPrettyPrint,
    type_inference::{
        constraints::ConstraintSource,
        type_bounds_map::{BoundChangeReason, ChangeLogKind, TypeVarRegistry},
        Constraint, TypeInferenceResult, TypeVarState,
    },
    FunctionId,
};

use super::v3::{
    control_flow::FunctionView,
    lir::Expression,
    model::{Model, TypeInferenceComplete},
    ssa::SsaMemoryReference,
    type_inference::{constraints::ConstraintId, Type, TypeVarId, TypeVarPath},
};

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Print function details or full model overview
    #[clap(alias = "p")]
    Print { function: Option<FunctionId> },
    /// List all available functions
    #[clap(alias = "lf")]
    Functions,
    /// Display type variables for a function
    #[clap(alias = "v")]
    Variables {
        id: Option<TypeVarId>,
        #[arg(short, long)]
        function: Option<FunctionId>,
    },
    /// Show change history for a type variable
    #[clap(alias = "h")]
    History {
        tv_id: Option<TypeVarId>,
        #[arg(short, long)]
        resolve: bool,
    },
    /// Display constraints
    #[clap(alias = "cs")]
    Constraints {
        id: Option<ConstraintId>,
        #[arg(short, long)]
        function: Option<FunctionId>,
    },
}

#[derive(Parser, Clone, Debug)]
struct ReplLine {
    #[clap(subcommand)]
    command: Command,
}

pub fn repl(model: &Model<TypeInferenceComplete>) {
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
        Command::Print { function } => match function {
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
        Command::Variables { id, function } => list_variables(model, id, function)?,
        Command::History { tv_id, resolve } => changelog(model, tv_id, resolve)?,
        Command::Constraints { id, function } => constraint(model, id, function)?,
    }
    Ok(())
}

fn format_path<'a>(
    model: &'a Model<TypeInferenceComplete>,
    path: &TypeVarPath,
) -> (String, Option<&'a Expression<SsaMemoryReference>>) {
    let expr = path.expression_from_model(model);
    let role = match path {
        TypeVarPath::AssignmentTargetVersioned { vmr, .. } => format!("Assign to {}", vmr),
        TypeVarPath::AssignmentTargetDeref { .. } => format!("Assign to deref"),
        TypeVarPath::FunctionDefArg { index, .. } => format!("DefArg[{}]", index),
        TypeVarPath::FunctionDefArgTuple { .. } => "FunctionDefArgTuple".to_string(),
        TypeVarPath::FunctionDefRet { index, .. } => format!("DefRet[{}]", index),
        TypeVarPath::FunctionDefRetTuple { .. } => "FunctionDefRetTuple".to_string(),
        TypeVarPath::AssignmentSrc {
            expression_path: _, ..
        } => format!("AssignmentSrc"),
        TypeVarPath::IfCond {
            expression_path: _, ..
        } => format!("IfCond"),
        TypeVarPath::Output {
            expression_path: _, ..
        } => format!("Output"),
        TypeVarPath::CallAddress {
            expression_path: _, ..
        } => format!("CallAddress"),
        TypeVarPath::CallArgTuple { .. } => "CallArgTuple".to_string(),
        TypeVarPath::CallArg {
            index,
            expression_path: _,
            ..
        } => format!("CallArg[{}]", index),
        TypeVarPath::CallRetTuple { .. } => "CallRetTuple".to_string(),
        TypeVarPath::CallRet { index, vmr, .. } => format!("CallRet[{}] {}", index, vmr),
        TypeVarPath::PhiAssignment { .. } => "PhiAssignment".to_string(),
        TypeVarPath::PhiAssignmentArg { index, .. } => {
            format!("PhiAssignmentArg: {}", index)
        }
        TypeVarPath::FunctionArgsRefinement {
            original_type_var_id,
            ..
        } => format!("FunctionArgsRefinement for {}", original_type_var_id),
        TypeVarPath::FunctionRetsRefinement {
            original_type_var_id,
            ..
        } => format!("FunctionRetsRefinement for {}", original_type_var_id),
        TypeVarPath::TupleRefinement {
            index,
            original_type_var_id,
            ..
        } => format!("TupleRefinement[{}] for {}", index, original_type_var_id),
        TypeVarPath::PointerRefinement {
            original_type_var_id,
            ..
        } => format!("PointerRefinement for {}", original_type_var_id),
    };
    (role, expr)
}

fn list_variables(
    model: &Model<TypeInferenceComplete>,
    id: Option<TypeVarId>,
    function: Option<FunctionId>,
) -> Result<(), String> {
    let ti = model.type_inference_result();
    use tabled::{Table, Tabled};
    #[derive(Tabled)]
    struct TypeVarRow {
        id: String,
        function: String,
        inst: String,
        role: String,
        expr: String,
        lower: String,
        upper: String,
    }
    let mut data = Vec::new();
    let mut converged_rows = Vec::new();
    for (row, (tv, tv_node)) in ti
        .type_var_nodes
        .iter()
        .filter(|(tv_id, n)| {
            id.is_none_or(|id| id == **tv_id) && function.is_none_or(|f| f == n.path.function_id())
        })
        .sorted_by_key(|(id, _)| *id)
        .enumerate()
    {
        let state = ti.type_var_states.get(tv).unwrap();
        let (role, expr) = format_path(model, &tv_node.path);

        data.push(TypeVarRow {
            id: format!("{}", tv),
            function: format!("{}", tv_node.path.function_id()),
            inst: format!(
                "{}",
                tv_node
                    .path
                    .instruction_id()
                    .map(|c| c.to_string())
                    .unwrap_or_default()
            ),
            role,
            expr: expr.map(|e| e.to_string()).unwrap_or_default(),
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
        .modify(Columns::new(5..7), Width::wrap(30))
        .modify(Columns::single(4), Width::wrap(15));
    for row in converged_rows {
        table.modify((row + 1, 5), Span::column(2));
        table.modify((row + 1, 5), Width::wrap(50));
    }
    println!("{}", table.to_string());
    Ok(())
}

fn format_change_log(tir: &TypeInferenceResult, clk: &ChangeLogKind, resolve: bool) -> String {
    match clk {
        ChangeLogKind::AddedBound {
            direction,
            new_bound,
            ..
        } => {
            let typ = if resolve {
                &tir.resolve_type(&new_bound)
            } else {
                new_bound
            };
            format!("Added {direction} {typ}")
        }
        ChangeLogKind::Converged {
            convergence_type,
            new_type,
        } => {
            format!("{convergence_type} into {new_type}")
        }
        ChangeLogKind::DependencyConverged {
            dependent_var_id,
            new_value,
        } => {
            format!("Dependency {dependent_var_id} converged to {new_value}")
        }
    }
}

fn changelog(
    model: &Model<TypeInferenceComplete>,
    tv_id: Option<TypeVarId>,
    resolve: bool,
) -> Result<(), String> {
    let ti: &TypeInferenceResult = model.type_inference_result();
    use tabled::{Table, Tabled};

    #[derive(Tabled)]
    struct ChangeRow {
        iter: usize,
        time: usize,
        tv_id: String,
        kind: String,
        reason: String,
    }

    let mut data = Vec::new();

    for (time, change) in ti
        .change_log
        .iter()
        .enumerate()
        .filter(|(_, c)| tv_id.is_none_or(|id| c.tv_id == id))
    {
        data.push(ChangeRow {
            iter: change.iteration,
            time,
            tv_id: format!("{}", change.tv_id),
            kind: format!("{}", format_change_log(ti, &change.kind, resolve)),
            reason: match &change.kind {
                ChangeLogKind::AddedBound { reason, .. } => {
                    let reason = match reason {
                        BoundChangeReason::Constraint(id) => {
                            let constraint = ti.constraint_store.get_constraint_by_id(*id).unwrap();
                            format!("{}: {:?}", id, constraint.reason)
                        }
                        __ => format!("{}", reason),
                    };
                    reason
                }
                ChangeLogKind::Converged {
                    convergence_type, ..
                } => format!("{}", convergence_type),
                ChangeLogKind::DependencyConverged { .. } => "Dependency".to_string(),
            },
        });
    }
    let mut table = Table::new(data);
    table.with(tabled::settings::Style::modern());
    println!("{}", table);

    Ok(())
}

fn constraint(
    model: &Model<TypeInferenceComplete>,
    id: Option<ConstraintId>,
    function: Option<FunctionId>,
) -> Result<(), String> {
    let ti: &TypeInferenceResult = model.type_inference_result();
    use tabled::{Table, Tabled};

    #[derive(Tabled)]
    struct ConstraintRow {
        id: String,
        function: String,
        instruction: String,
        sub_type: String,
        super_type: String,
        reason: String,
        parent: String,
    }

    let mut data = Vec::new();
    let mut found = false;

    let get_parent = |constraint_id: &ConstraintId| {
        ti.constraint_store
            .get_constraint_source(*constraint_id)
            .and_then(|s| match s {
                ConstraintSource::Derived {
                    from_constraint, ..
                } => Some(from_constraint),
                _ => None,
            })
    };

    let mut add_constraint = |constraint_id: &ConstraintId, constraint: &Constraint| {
        let source = match get_parent(constraint_id) {
            Some(from_constraint) => format!("{}", from_constraint),
            None => "".to_string(),
        };

        data.push(ConstraintRow {
            id: format!("{}", constraint_id),
            function: format!("{}", constraint.origin_function_id),
            instruction: format!("{}", constraint.origin_instruction_id),
            sub_type: format!("{}", constraint.sub_type), // .display_with(ti)),
            super_type: format!("{}", constraint.super_type), // .display_with(ti)),
            reason: format!("{:?}", constraint.reason),
            parent: source,
        });
    };

    if let Some(id_filter) = id {
        let mut current_id = id_filter;
        while let Some(constraint) = ti.constraint_store.get_constraint_by_id(current_id) {
            add_constraint(&current_id, constraint);
            found = true;
            match get_parent(&current_id) {
                Some(parent_id) => current_id = *parent_id,
                None => break,
            }
        }
    } else {
        for (constraint_id, constraint) in ti.constraint_store.iter().sorted_by_key(|c| c.0) {
            if let Some(function_filter) = function {
                if function_filter != constraint.origin_function_id {
                    continue;
                }
            }
            add_constraint(constraint_id, constraint);
            found = true;
        }
    }

    if !found {
        println!("No constraint found");
        return Ok(());
    }

    let mut table = Table::new(data);
    table.with(tabled::settings::Style::modern());
    println!("{}", table);

    Ok(())
}
