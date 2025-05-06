use clap::{Parser, Subcommand};
use disasm::disasm::{
    v2::pretty_print::pretty_print_ssa,
    v3::analysis::{self},
};
use itertools::Itertools;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Compile { source: String },
    Disassemble { input: String },
    Pipeline { input: String },
    Ssa { input: String },
    Types { input: String },
    FlowRecovery { input: String },
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
        Command::Ssa { input } => ssa(input),
        _ => panic!("No command specified"),
        // Command::Types { input } => types(input),
        // Command::FlowRecovery { input } => flow_recovery(input),
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
    for func in model.image_scanner_result().recognized_functions.values() {
        println!("function {}", func.span.start);
        for inst in &func.instructions {
            println!("{:8}  {}", inst.span.start, inst);
        }
        println!();
    }
}

fn pipeline(input: String) {
    let prog = parse_program(std::fs::read_to_string(input).unwrap());
    analysis::binary_to_function_calls(prog).unwrap();
}

fn ssa(input: String) {
    let prog = parse_program(std::fs::read_to_string(input).unwrap());
    let model = analysis::binary_to_ssa(prog).unwrap();
    pretty_print_ssa(&model);
}
/*
fn types(input: String) {
    let prog = std::fs::read_to_string(input)
        .unwrap()
        .trim()
        .split(',')
        .map(|x| x.parse().unwrap())
        .collect::<Vec<i128>>();
    run_types(prog);
}

fn flow_recovery(input: String) {
    let prog = std::fs::read_to_string(input)
        .unwrap()
        .trim()
        .split(',')
        .map(|x| x.parse().unwrap())
        .collect::<Vec<i128>>();
    run_flow_recovery(prog);
}
*/
