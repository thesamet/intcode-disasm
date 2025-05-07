use clap::{Parser, Subcommand};
use disasm::disasm::v3::analysis::{self};
use disasm::disasm::v3::common::formatting::{Colors, PrettyPrintConfig};
use disasm::disasm::v3::pretty_print::{
    pretty_print_ssa_stdout, pretty_print_ssa_with_config, pretty_print_with_types_stdout,
};
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
        } => {
            if list_themes {
                list_available_themes();
                return;
            }
            validate_theme(&theme);
            types(input.unwrap(), theme)
        }
        Command::FlowRecovery { input } => flow_recovery(input),
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
        println!("  {:20} - {}", name, description);
    }
}

fn validate_theme(theme: &str) {
    if theme != "default" && Colors::get_theme_by_name(theme).is_none() {
        eprintln!("Error: Invalid theme name '{}'.", theme);
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

fn types(input: String, theme: String) {
    let prog = parse_program(std::fs::read_to_string(input).unwrap());
    let model = analysis::binary_to_function_calls(prog).unwrap();

    if theme == "default" {
        pretty_print_with_types_stdout(&model);
        return;
    }

    let config = get_theme_config(&theme, true);
    println!("{}", pretty_print_ssa_with_config(&model, config));
}

fn flow_recovery(input: String) {
    let _prog = parse_program(std::fs::read_to_string(input).unwrap());
    // TODO: Implement flow recovery
    println!("Flow recovery not yet implemented");
}

fn get_theme_config(theme: &str, show_types: bool) -> PrettyPrintConfig {
    let colors = Colors::get_theme_by_name(theme).unwrap();

    PrettyPrintConfig {
        colors,
        show_types,
        show_vars: false,
        indent_width: 4,
    }
}
