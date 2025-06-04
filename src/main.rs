use clap::{Parser, Subcommand};
use disasm::disasm::hlr;
use disasm::disasm::repl;
use disasm::disasm::v3::analysis::{self};
use disasm::disasm::v3::common::formatting::{Colors, ContextualPrettyPrint, PrettyPrintConfig};
use disasm::disasm::v3::pretty_print::{
    pretty_print_folded_ssa_with_config, pretty_print_ssa_stdout, pretty_print_ssa_with_config,
};
use disasm::disasm::v3::FunctionId;
use disasm::disasm::SymbolRenaming;
use itertools::Itertools;
use std::process;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Compile {
        source: String,
    },
    Disassemble {
        input: String,
    },
    Pipeline {
        input: String,
    },
    Ssa {
        #[arg(required_unless_present = "list_themes")]
        input: Option<String>,
        #[arg(
            long,
            default_value = "default",
            help = "Color theme (run with --list-themes to see all available themes)"
        )]
        theme: String,
        #[arg(long, help = "List all available color themes")]
        list_themes: bool,
    },
    FoldedSsa {
        #[arg(required_unless_present = "list_themes")]
        input: Option<String>,
        #[arg(
            long,
            default_value = "default",
            help = "Color theme (run with --list-themes to see all available themes)"
        )]
        theme: String,
        #[arg(long, help = "List all available color themes")]
        list_themes: bool,
    },
    Hlr {
        #[arg(required_unless_present = "list_themes")]
        input: Option<String>,
        #[arg(
            long,
            default_value = "default",
            help = "Color theme (run with --list-themes to see all available themes)"
        )]
        theme: String,
        #[arg(long, help = "List all available color themes")]
        list_themes: bool,
        #[arg(long, help = "Symbol renaming rules files")]
        symbols: Option<String>,
    },
    Types {
        #[arg(required_unless_present = "list_themes")]
        input: Option<String>,
        #[arg(
            long,
            default_value = "default",
            help = "Color theme (run with --list-themes to see all available themes)"
        )]
        theme: String,
        #[arg(long, help = "List all available color themes")]
        list_themes: bool,
        #[arg(long, help = "Function ID to print types for", default_value_t = usize::MAX)]
        function: usize,
        #[arg(long, help = "Show variable IDs")]
        show_var_ids: bool,
    },
    Repl {
        input: Option<String>,
        #[arg(long, help = "Symbol renaming rules files")]
        symbols: Option<String>,
    },
    FlowRecovery {
        input: String,
    },
}

fn main() {
    env_logger::builder()
        .format_target(false)
        .format_timestamp(None)
        .init();
    let cli = Cli::parse();

    match cli.command {
        Command::Compile { source } => compile(source),
        Command::Disassemble { input } => disassemble(input),
        Command::Pipeline { input } => pipeline(input),
        Command::Ssa {
            input,
            theme,
            list_themes,
        } => {
            if list_themes {
                list_available_themes();
                return;
            }
            validate_theme(&theme);
            ssa(input.unwrap(), theme)
        }
        Command::Types {
            input,
            theme,
            list_themes,
            function,
            show_var_ids,
        } => {
            if list_themes {
                list_available_themes();
                return;
            }
            validate_theme(&theme);
            types(
                input.unwrap(),
                (function != usize::MAX).then(|| FunctionId::new(function)),
                show_var_ids,
                theme,
            )
        }
        Command::FlowRecovery { input } => flow_recovery(input),
        Command::Repl { input, symbols } => repl(input.unwrap(), symbols),
        Command::FoldedSsa {
            input,
            theme,
            list_themes,
        } => {
            if list_themes {
                list_available_themes();
                return;
            }
            validate_theme(&theme);
            folded_ssa(input.unwrap(), theme)
        }
        Command::Hlr {
            input,
            theme,
            symbols,
            list_themes,
        } => {
            if list_themes {
                list_available_themes();
                return;
            }
            validate_theme(&theme);
            hlr(input.unwrap(), symbols, theme)
        }
    }
}

fn compile(source: String) {
    let source = std::fs::read_to_string(source);
    let out = disasm::disasm::parser::compile(&source.unwrap());
    println!("{}", out.iter().join(","))
}

fn parse_program(input: String) -> Vec<i128> {
    input
        .trim()
        .split(',')
        .map(|x| x.parse().unwrap())
        .collect::<Vec<i128>>()
}

fn disassemble(input: String) {
    let prog = parse_program(std::fs::read_to_string(input).unwrap());
    let model = analysis::binary_to_scanned_image(prog).unwrap();
    for func in model
        .image_scanner_result()
        .recognized_functions
        .iter()
        .sorted_by_key(|f| f.0)
        .map(|f| f.1)
    {
        println!("function {}", func.span.start);
        for inst in &func.instructions {
            println!("{:5} {:8}  {}", inst.id, inst.span.start, inst);
        }
        println!();
    }
}

fn pipeline(input: String) {
    let prog = parse_program(std::fs::read_to_string(input).unwrap());
    analysis::binary_to_function_calls(prog).unwrap();
}

fn list_available_themes() {
    println!("Available color themes:");
    for (name, description) in Colors::get_theme_descriptions() {
        println!("  {name:20} - {description}");
    }
}

fn validate_theme(theme: &str) {
    if theme != "default" && Colors::get_theme_by_name(theme).is_none() {
        eprintln!("Error: Invalid theme name '{theme}'.");
        eprintln!("Available themes: {}", Colors::get_theme_names().join(", "));
        eprintln!("You can also run with --list-themes for more detailed theme information.");
        process::exit(1);
    }
}

fn ssa(input: String, theme: String) {
    let prog = parse_program(std::fs::read_to_string(input).unwrap());
    let model = analysis::binary_to_function_calls(prog).unwrap();

    if theme == "default" {
        pretty_print_ssa_stdout(&model);
        return;
    }

    let config = get_theme_config(&theme, false);
    println!("{}", pretty_print_ssa_with_config(&model, config));
}

fn folded_ssa(input: String, theme: String) {
    let prog = parse_program(std::fs::read_to_string(input).unwrap());
    // The analysis function `binary_to_folded_ssa` returns Model<FoldedSsaComplete>
    // The existing `pretty_print_ssa_stdout` expects Model<FunctionCallAnalysisComplete>
    // We'll need to adapt this. For now, let's assume we have a way to print it.
    // This might involve making pretty_print_ssa_stdout generic or creating a new one.
    // For this step, we'll call the existing SSA printers, anticipating they can be adapted.
    let model = analysis::binary_to_folded_ssa(prog).unwrap();

    if theme == "default" {
        pretty_print_ssa_stdout(&model); // This will likely need adjustment to accept Model<FoldedSsaComplete>
        return;
    }

    let config = get_theme_config(&theme, false); // `show_types` is false for SSA view
                                                  // Similar to above, pretty_print_ssa_with_config might need adjustment.
    println!("{}", pretty_print_folded_ssa_with_config(&model, config));
}

fn types(input: String, function: Option<FunctionId>, show_var_ids: bool, _theme: String) {
    let prog = parse_program(std::fs::read_to_string(input).unwrap());
    let model = analysis::binary_to_type_inference(prog, &SymbolRenaming::new()).unwrap();
    if let Some(function_id) = function {
        let fu = model.function(&function_id);
        println!("{}", fu.pretty_print());
    } else {
        let config = PrettyPrintConfig::default().with_show_types_var_ids(show_var_ids);
        println!("{}", model.pretty_print_with_config(&config));
    }
}

fn repl(input: String, symbols: Option<String>) {
    let prog = parse_program(std::fs::read_to_string(input).unwrap());
    let symbol_renaming = if let Some(symbols) = symbols {
        let symbols = std::fs::read_to_string(symbols).unwrap();
        SymbolRenaming::from_lines(&symbols).unwrap()
    } else {
        SymbolRenaming::new()
    };
    let model = analysis::binary_to_hlr(prog, &symbol_renaming).unwrap();
    repl::repl(&model);
}

fn flow_recovery(input: String) {
    let _prog = parse_program(std::fs::read_to_string(input).unwrap());
    // TODO: Implement flow recovery
    println!("Flow recovery not yet implemented");
}

fn hlr(input: String, symbols: Option<String>, theme: String) {
    let prog = parse_program(std::fs::read_to_string(input).unwrap());
    let symbol_renaming = if let Some(symbols) = symbols {
        let symbols = std::fs::read_to_string(symbols).unwrap();
        SymbolRenaming::from_lines(&symbols).unwrap()
    } else {
        SymbolRenaming::new()
    };
    let model = analysis::binary_to_hlr(prog, &symbol_renaming).unwrap();

    if theme == "default" {
        // For default theme, use the HLR program directly
        let hlr_program = model.hlr_program();
        println!(
            "{}",
            hlr_program.pretty_print_with_data(model.type_inference_result())
        );
        return;
    }

    let config = get_theme_config(&theme, false);

    // For custom themes, pass config to the HLR program's pretty printer
    let hlr_program = model.hlr_program();
    println!(
        "{}",
        hlr_program.pretty_print_with_config_and_data(&config, model.type_inference_result())
    );
}

fn get_theme_config(theme: &str, show_types: bool) -> PrettyPrintConfig {
    let colors = Colors::get_theme_by_name(theme).unwrap();

    PrettyPrintConfig {
        colors: Some(colors),
        show_types,
        show_vars: false,
        show_types_var_ids: false,
        indent_width: 4,
    }
}
