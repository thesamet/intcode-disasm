use std::marker::PhantomData;

use castaway::match_type;
use clap::{arg, Parser, Subcommand};
use colored::Colorize;
use itertools::Itertools;

use rustyline::DefaultEditor;
use serde::Serialize;
use std::collections::HashSet;
use tabled::{
    settings::{object::Columns, Span, Style, Width},
    Table, Tabled,
};

use crate::disasm::{
    vm::{FunctionCaller},
    v3::{
        common::formatting::{ContextualPrettyPrint, PrettyPrintConfig},
        lir::{MemoryReferenceInfo, TypeVarPath},
        type_inference::{
            type_bounds_map::{BoundChangeReason, ChangeLogKind, TypeVarRegistry},
            Constraint, TypeInferenceResult, TypeVarState,
        },
        FunctionId,
    },
};

pub struct ReplState {
    caller: FunctionCaller,
}

use super::v3::{
    cfg::FunctionView,
    lir::Expression,
    model::{HasTypeInferenceResult, HlrConstructionComplete, Model, ModelState},
    ssa::SsaMemoryReference,
    type_inference::{constraints::ConstraintId, Type, TypeVarId},
};

#[derive(Tabled, Serialize)]
pub struct TypeVarRow {
    id: String,
    function: String,
    inst: String,
    role: String,
    expr: String,
    lower: String,
    upper: String,
}

#[derive(Tabled, Serialize, rmcp::schemars::JsonSchema)]
pub struct ChangeRow {
    iter: usize,
    time: usize,
    tv_id: String,
    kind: String,
    reason: String,
    context: String,
}

#[derive(Tabled, Serialize)]
pub struct FunctionRow {
    name: String,
    address: String,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Print function details or full model overview
    #[clap(alias = "p")]
    Print {
        function: Option<FunctionId>,
        #[arg(long)]
        hlr: bool,
        #[arg(long)]
        type_vars: bool,
    },
    /// List all available functions
    #[clap(alias = "lf")]
    Functions,
    /// Display type variables for a function
    #[clap(alias = "v")]
    Variables {
        id: Option<TypeVarId>,
        #[arg(short, long)]
        function: Option<FunctionId>,
        #[arg(short, long)]
        global: bool,
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
    /// Call a function with the given arguments
    #[clap(alias = "c")]
    Call {
        addr: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<i128>,
    },
    /// Read memory value at address
    Memget {
        addr: usize,
    },
    /// Write value to memory address  
    Memset {
        addr: usize,
        value: i128,
    },
    /// Set input buffer with text (automatically adds newline)
    SetInput {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        text: Vec<String>,
    },
}

#[derive(Parser, Clone, Debug)]
struct ReplLine {
    #[clap(subcommand)]
    command: Command,
}

pub fn repl<S: HasTypeInferenceResult + ModelState + 'static>(model: &Model<S>) {
    let mut editor = DefaultEditor::new().expect("Failed to create editor");
    let history_path = "history.txt";

    if editor.load_history(history_path).is_err() {
        println!("No previous history found.");
    }

    // Initialize persistent state
    let program = &model.image_scanner_result().image;
    let mut state = ReplState {
        caller: FunctionCaller::new(program.clone()),
    };

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
                    Ok(cmd) => match ReplCommands::<S>::run_command(cmd, model, &mut state) {
                        Ok(_) => {}
                        Err(err) => {
                            println!("{}", err.red())
                        }
                    },
                    Err(err) => {
                        println!("{err}")
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
                println!("Error: {err:?}");
                break;
            }
        }
    }
    editor
        .save_history(history_path)
        .expect("Failed to save history");
}

fn get_function<'a, S: HasTypeInferenceResult + ModelState>(
    model: &'a Model<S>,
    function_id: &FunctionId,
) -> Result<FunctionView<'a, S>, String> {
    model
        .get_function(function_id)
        .ok_or_else(|| format!("Function {function_id} does not exist"))
}

fn format_bounds<'a, I>(v: I) -> String
where
    I: IntoIterator<Item = &'a Type>,
{
    let v = v.into_iter().sorted().collect_vec();
    let out = v.iter().join(", ").to_string();
    if out.len() > 30 {
        v.iter().join(",\n").to_string()
    } else {
        out
    }
}

pub struct ReplCommands<S> {
    _data: PhantomData<S>,
}

impl<S> ReplCommands<S>
where
    S: HasTypeInferenceResult + ModelState + 'static,
{
    fn as_hlr(model: &Model<S>) -> Option<&Model<HlrConstructionComplete>> {
        match_type!(model, {
            &Model<HlrConstructionComplete> as m => {
                Some(m)
            },
            _ => None
        })
    }

    fn run_command(cmd: ReplLine, model: &Model<S>, state: &mut ReplState) -> Result<(), String> {
        match cmd.command {
            Command::Print {
                function,
                hlr,
                type_vars,
            } => {
                let config = PrettyPrintConfig::default().with_show_types_var_ids(type_vars);
                if hlr && type_vars {
                    return Err("Cannot show both HLR and type vars".to_string());
                }

                if hlr {
                    let hlr_model =
                        Self::as_hlr(model).ok_or_else(|| "HLR not avaiable".to_string())?;
                    match function {
                        Some(function_id) => {
                            let fu = hlr_model
                                .hlr_program()
                                .functions
                                .iter()
                                .find(|f| f.original_id == function_id)
                                .ok_or(format!("Could not find function {function_id}"))?;
                            println!(
                                "{}",
                                fu.pretty_print_with_config_and_data(
                                    &config,
                                    hlr_model.type_inference_result(),
                                )
                            );
                        }
                        None => println!(
                            "{}",
                            hlr_model.hlr_program().pretty_print_with_config_and_data(
                                &config,
                                hlr_model.type_inference_result()
                            )
                        ),
                    }
                } else {
                    match function {
                        Some(function_id) => {
                            let fu = get_function(model, &function_id)?;
                            println!("{}", fu.pretty_print_with_config(&config));
                        }
                        None => {
                            println!("{}", model.pretty_print_with_config(&config));
                        }
                    }
                }
            }
            Command::Functions => {
                Self::list_functions(model)?;
            }
            Command::Variables {
                id,
                function,
                global,
            } => Self::list_variables(model, id, function, global)?,
            Command::History { tv_id, resolve } => Self::changelog(model, tv_id, resolve)?,
            Command::Constraints { id, function } => Self::constraint(model, id, function)?,
            Command::Call { addr, args } => Self::call_function(&addr, args, model, state)?,
            Command::Memget { addr } => Self::memget(addr, state)?,
            Command::Memset { addr, value } => Self::memset(addr, value, state)?,
            Command::SetInput { text } => Self::set_input(text, state)?,
        }
        Ok(())
    }
    pub fn format_path<'a>(
        model: &'a Model<S>,
        path: &TypeVarPath,
    ) -> (String, Option<&'a Expression<SsaMemoryReference>>) {
        let expr = path.expression_from_model(model);
        let role = match path {
            TypeVarPath::AssignmentTargetVersioned { vmr, .. } => format!("Assign to {vmr}"),
            TypeVarPath::AssignmentTargetDeref { .. } => "Assign to deref".to_string(),
            TypeVarPath::FunctionDefArg { index, .. } => format!("DefArg[{index}]"),
            TypeVarPath::FunctionDefArgTuple { .. } => "FunctionDefArgTuple".to_string(),
            TypeVarPath::FunctionDefRet { index, .. } => format!("DefRet[{index}]"),
            TypeVarPath::FunctionDefRetTuple { .. } => "FunctionDefRetTuple".to_string(),
            TypeVarPath::AssignmentSrc {
                expression_path: _, ..
            } => "AssignmentSrc".to_string(),
            TypeVarPath::IfCond {
                expression_path: _, ..
            } => "IfCond".to_string(),
            TypeVarPath::Output {
                expression_path: _, ..
            } => "Output".to_string(),
            TypeVarPath::CallAddress {
                expression_path: _, ..
            } => "CallAddress".to_string(),
            TypeVarPath::CallArgTuple { .. } => "CallArgTuple".to_string(),
            TypeVarPath::CallArg {
                index,
                expression_path: _,
                ..
            } => format!("CallArg[{index}]"),
            TypeVarPath::CallRetTuple { .. } => "CallRetTuple".to_string(),
            TypeVarPath::CallRet { index, vmr, .. } => format!("CallRet[{index}] {vmr}"),
            TypeVarPath::PhiAssignment { .. } => "PhiAssignment".to_string(),
            TypeVarPath::PhiAssignmentArg { index, .. } => {
                format!("PhiAssignmentArg: {index}")
            }
            TypeVarPath::FunctionArgsRefinement {
                original_type_var_id,
                ..
            } => format!("FunctionArgsRefinement for {original_type_var_id}"),
            TypeVarPath::FunctionRetsRefinement {
                original_type_var_id,
                ..
            } => format!("FunctionRetsRefinement for {original_type_var_id}"),
            TypeVarPath::TupleRefinement {
                index,
                original_type_var_id,
                ..
            } => format!("TupleRefinement[{index}] for {original_type_var_id}"),
            TypeVarPath::PointerRefinement {
                original_type_var_id,
                ..
            } => format!("PointerRefinement for {original_type_var_id}"),
            TypeVarPath::SymbolRenaming { .. } => "SymbolRenaming".to_string(),
            TypeVarPath::StructField { struct_id, index } => {
                format!("StructField[{index}] for struct {struct_id}")
            }
        };
        (role, expr)
    }

    pub fn list_variables_data(
        model: &Model<S>,
        id: Option<TypeVarId>,
        function: Option<FunctionId>,
        global: bool,
    ) -> Result<(Vec<TypeVarRow>, Vec<usize>), String> {
        let ti = model.type_inference_result();
        let mut data = Vec::new();
        let mut converged_rows = Vec::new();
        for (row, (tv, tv_node)) in ti
            .type_var_nodes
            .iter()
            .filter(|(tv_id, n)| {
                id.is_none_or(|id| id == **tv_id)
                    && function.is_none_or(|f| f == n.path.function_id())
            })
            .filter(|(_, n)| !global || n.vmr.is_some_and(|vmr| vmr.is_global()))
            .sorted_by_key(|(id, _)| *id)
            .enumerate()
        {
            let state = ti.type_var_states.get(tv).unwrap();
            let (role, expr) = Self::format_path(model, &tv_node.path);

            data.push(TypeVarRow {
                id: format!("{tv}"),
                function: format!("{}", tv_node.path.function_id()),
                inst: tv_node
                    .path
                    .instruction_id()
                    .map(|c| c.to_string())
                    .unwrap_or_default()
                    .to_string(),
                role,
                expr: expr.map(|e| e.to_string()).unwrap_or_default(),
                lower: match state {
                    TypeVarState::Bounds { lower_bounds, .. } => format_bounds(lower_bounds),
                    TypeVarState::Converged(ty) => {
                        converged_rows.push(row);
                        format!("{ty}").green().to_string()
                    }
                },
                upper: match state {
                    TypeVarState::Bounds { upper_bounds, .. } => format_bounds(upper_bounds),
                    _ => "".to_string(),
                },
            });
        }
        Ok((data, converged_rows))
    }

    fn list_variables(
        model: &Model<S>,
        id: Option<TypeVarId>,
        function: Option<FunctionId>,
        global: bool,
    ) -> Result<(), String> {
        let (data, converged_rows) = Self::list_variables_data(model, id, function, global)?;
        let mut table = Table::new(data);
        table
            .with(Style::modern())
            .modify(Columns::new(5..7), Width::wrap(30))
            .modify(Columns::single(4), Width::wrap(15));
        for row in converged_rows {
            table.modify((row + 1, 5), Span::column(2));
            table.modify((row + 1, 5), Width::wrap(50));
        }
        println!("{table}");
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
                    &tir.resolve_type(new_bound)
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

    pub fn changelog_data(
        model: &Model<S>,
        tv_id: Option<TypeVarId>,
        resolve: bool,
    ) -> Result<Vec<ChangeRow>, String> {
        let ti: &TypeInferenceResult = model.type_inference_result();

        let mut data = Vec::new();

        for (time, change) in ti
            .change_log
            .iter()
            .enumerate()
            .filter(|(_, c)| tv_id.is_none_or(|id| c.tv_id == id))
        {
            let mut involved_tvs = HashSet::new();
            match &change.kind {
                ChangeLogKind::AddedBound { new_bound, .. } => {
                    involved_tvs.extend(new_bound.involved_type_vars());
                }
                ChangeLogKind::Converged { new_type, .. } => {
                    involved_tvs.extend(new_type.involved_type_vars());
                }
                ChangeLogKind::DependencyConverged {
                    dependent_var_id,
                    new_value,
                } => {
                    involved_tvs.insert(*dependent_var_id);
                    involved_tvs.extend(new_value.involved_type_vars());
                }
            }

            let context = involved_tvs
                .iter()
                .map(|id| {
                    let node = &ti.type_var_nodes[id];
                    let (role, expr) = Self::format_path(model, &node.path);
                    format!(
                        "{} -> {} @ {}: {}",
                        id,
                        role,
                        node.path.function_id(),
                        expr.map(|e| e.to_string()).unwrap_or_default()
                    )
                })
                .sorted()
                .join("\n");

            data.push(ChangeRow {
                iter: change.iteration,
                time,
                tv_id: format!("{}", change.tv_id),
                kind: Self::format_change_log(ti, &change.kind, resolve),
                reason: match &change.kind {
                    ChangeLogKind::AddedBound { reason, .. } => match reason {
                        BoundChangeReason::Constraint(id) => {
                            let mut reasons = vec![];
                            let mut current_id = Some(*id);
                            while let Some(current_id_val) = current_id {
                                let constraint = ti
                                    .constraint_store
                                    .get_constraint_by_id(current_id_val)
                                    .unwrap();
                                reasons.push(format!(
                                    "{}: {:?} @ {}/{}",
                                    current_id_val,
                                    constraint.reason,
                                    constraint.origin_function_id,
                                    constraint.origin_instruction_id
                                ));
                                current_id = ti.constraint_store.get_parent_id(current_id_val);
                            }
                            reasons.join("\n")
                        }
                        _ => format!("{reason}"),
                    },
                    ChangeLogKind::Converged {
                        convergence_type, ..
                    } => format!("{convergence_type}"),
                    ChangeLogKind::DependencyConverged { .. } => "Dependency".to_string(),
                },
                context,
            });
        }
        Ok(data)
    }

    fn changelog(model: &Model<S>, tv_id: Option<TypeVarId>, resolve: bool) -> Result<(), String> {
        if let Some(tv_id) = tv_id {
            if let Ok((data, _)) = Self::list_variables_data(model, Some(tv_id), None, false) {
                if let Some(row) = data.first() {
                    println!("{}", "Variable Context".bold().underline());
                    println!("{:<15}: {}", "ID", row.id);
                    println!("{:<15}: {}", "Function", row.function);
                    println!("{:<15}: {}", "Instruction", row.inst);
                    println!("{:<15}: {}", "Role", row.role);
                    println!("{:<15}: {}", "Expression", row.expr);
                    let ti = model.type_inference_result();
                    let state = ti.type_var_states.get(&tv_id).unwrap();
                    match state {
                        TypeVarState::Converged(ty) => {
                            println!("{:<15}: {}", "State", "Converged".green());
                            println!("{:<15}: {}", "Type", format!("{ty}").green());
                        }
                        TypeVarState::Bounds {
                            lower_bounds,
                            upper_bounds,
                        } => {
                            println!("{:<15}: Bounds", "State");
                            println!("{:<15}: {}", "Lower bound", format_bounds(lower_bounds));
                            println!("{:<15}: {}", "Upper bound", format_bounds(upper_bounds));
                        }
                    }
                    println!();
                }
            }
        }

        let data = Self::changelog_data(model, tv_id, resolve)?;
        if data.is_empty() {
            println!("No history found for the given type variable.");
            return Ok(());
        }
        let mut table = Table::new(data);
        table.with(tabled::settings::Style::modern());
        println!("{table}");

        Ok(())
    }

    fn constraint(
        model: &Model<S>,
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

        let mut add_constraint = |constraint_id: &ConstraintId, constraint: &Constraint| {
            data.push(ConstraintRow {
                id: format!("{constraint_id}"),
                function: format!("{}", constraint.origin_function_id),
                instruction: format!("{}", constraint.origin_instruction_id),
                sub_type: format!("{}", constraint.sub_type), // .display_with(ti)),
                super_type: format!("{}", constraint.super_type), // .display_with(ti)),
                reason: format!("{:?}", constraint.reason),
                parent: ti
                    .constraint_store
                    .get_parent_id(*constraint_id)
                    .map(|c| format!("{c}"))
                    .unwrap_or_default(),
            });
        };

        if let Some(id_filter) = id {
            let mut current_id = id_filter;
            while let Some(constraint) = ti.constraint_store.get_constraint_by_id(current_id) {
                add_constraint(&current_id, constraint);
                found = true;
                match ti.constraint_store.get_parent_id(current_id) {
                    Some(parent_id) => current_id = parent_id,
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
        println!("{table}");

        Ok(())
    }

    fn list_functions(model: &Model<S>) -> Result<(), String> {
        let mut data = Vec::new();
        
        for (id, _function_info) in model.functions().sorted_by_key(|f| f.0) {
            let name = model.user_defs().get_function_name(id)
                .map(|s| s.clone())
                .unwrap_or("—".to_string());
            
            data.push(FunctionRow {
                name,
                address: format!("{}", id.index()),
            });
        }
        
        let mut table = Table::new(data);
        table.with(Style::rounded());
        println!("{table}");
        
        Ok(())
    }

    fn call_function(addr_str: &str, args: Vec<i128>, model: &Model<S>, state: &mut ReplState) -> Result<(), String> {
        let program = &model.image_scanner_result().image;
        
        // Try to parse as a number first, otherwise look up symbol name
        let addr = match addr_str.parse::<i128>() {
            Ok(num) => {
                if num < 0 {
                    return Err("Function address cannot be negative".to_string());
                }
                num
            }
            Err(_) => {
                // Look up function name in user symbols
                let user_defs = model.user_defs();
                let mut found_addr = None;
                
                // Search through all functions for a matching name
                for (function_id, _) in model.functions() {
                    if let Some(function_name) = user_defs.get_function_name(function_id) {
                        if function_name == addr_str {
                            found_addr = Some(function_id.index() as i128);
                            break;
                        }
                    }
                }
                
                match found_addr {
                    Some(addr) => addr,
                    None => return Err(format!("Function '{}' not found in symbols", addr_str)),
                }
            }
        };
        
        let addr_usize = addr as usize;
        if addr_usize >= program.len() {
            return Err(format!("Function address {} is beyond program size {}", addr, program.len()));
        }
        
        println!("Calling function '{}' at address {} with {} arguments: {:?}", addr_str, addr, args.len(), args);
        
        match state.caller.call_function(addr_usize, &args) {
            Ok(result) => {
                if result.completed {
                    println!("Function completed successfully");
                } else {
                    println!("Function halted without returning");
                }
                
                if !result.outputs.is_empty() {
                    println!("Outputs: {:?}", result.outputs);
                    // Convert outputs to ASCII string, showing printable characters
                    let ascii_chars: Vec<char> = result.outputs.iter()
                        .map(|&val| {
                            if (32..=126).contains(&val) {
                                val as u8 as char
                            } else if val == 10 {
                                '\n'  // Show newlines
                            } else if val == 9 {
                                '\t'  // Show tabs
                            } else {
                                '?'
                            }
                        })
                        .collect();
                    
                    // Only show ASCII output if it contains some printable characters
                    let printable_count = result.outputs.iter()
                        .filter(|&&val| (32..=126).contains(&val) || val == 10 || val == 9)
                        .count();
                    
                    if printable_count > 0 {
                        let ascii_string: String = ascii_chars.into_iter().collect();
                        println!("ASCII: \"{}\"", ascii_string);
                    }
                }
                
                if !result.return_values.is_empty() {
                    println!("Return values: {:?}", result.return_values);
                }
                
                if result.outputs.is_empty() && result.return_values.is_empty() {
                    println!("No outputs or return values");
                }
            }
            Err(err) => {
                println!("Function call failed: {err}");
            }
        }
        
        Ok(())
    }

    fn memget(addr: usize, state: &ReplState) -> Result<(), String> {
        let value = state.caller.get_memory(addr);
        println!("Memory[{}] = {}", addr, value);
        Ok(())
    }

    fn memset(addr: usize, value: i128, state: &mut ReplState) -> Result<(), String> {
        state.caller.set_memory(addr, value);
        println!("Memory[{}] set to {}", addr, value);
        Ok(())
    }

    fn set_input(text: Vec<String>, state: &mut ReplState) -> Result<(), String> {
        let input_string = text.join(" ");
        state.caller.set_input_string(&input_string);
        println!("Input buffer set to: \"{}\" (with newline)", input_string);
        Ok(())
    }
}
