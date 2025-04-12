mod disasm;

use clap::{Parser, Subcommand};
use disasm::v2::analysis::{self, run_analysis, run_analysis_ssa};
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
    }
}

fn compile(source: String) {
    let source = std::fs::read_to_string(source);
    let out = disasm::parser::compile(&source.unwrap());
    println!("{}", out.iter().join(","))
}

fn disassemble(input: String) {
    let prog = std::fs::read_to_string(input)
        .unwrap()
        .trim()
        .split(',')
        .map(|x| x.parse().unwrap())
        .collect::<Vec<i128>>();
    let scanner_result = analysis::disassemble(prog);
    for func in scanner_result.recognized_functions {
        println!("function {}", func.span.start);
        for inst in func.instructions {
            println!("{:8}  {}", inst.span.start, inst);
        }
        println!("");
    }
}

fn pipeline(input: String) {
    let prog = std::fs::read_to_string(input)
        .unwrap()
        .trim()
        .split(',')
        .map(|x| x.parse().unwrap())
        .collect::<Vec<i128>>();
    run_analysis(prog)
}

fn ssa(input: String) {
    let prog = std::fs::read_to_string(input)
        .unwrap()
        .trim()
        .split(',')
        .map(|x| x.parse().unwrap())
        .collect::<Vec<i128>>();
    run_analysis_ssa(prog);
}
