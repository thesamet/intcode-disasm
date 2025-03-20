mod disasm;

use clap::{Parser, Subcommand};
use disasm::{low_ir::Instruction, mid_ir};

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
    Intermediate { input: String },
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let cli = Cli::parse();

    match cli.command {
        Command::Compile { source } => compile(source),
        Command::Intermediate { input } => intermediate(input),
        Command::Disassemble { input } => disassemble(input),
    }
}

fn compile(source: String) {
    let source = std::fs::read_to_string(source);
    let program = disasm::parser::parse_program(&source.unwrap()).unwrap();
    let mut out = vec![];
    for inst in program {
        inst.1.serialize(&mut out);
    }
    println!("{}", out.iter().map(|x| x.to_string()).join(","))
}

fn disassemble(input: String) {
    let prog = std::fs::read_to_string(input)
        .unwrap()
        .trim()
        .split(',')
        .map(|x| x.parse().unwrap())
        .collect::<Vec<i128>>();
    let inst = Instruction::parse_program(&prog);
    for (addr, i) in inst.iter() {
        println!("{:8}  {}", addr, i);
    }
}

fn intermediate(input: String) {
    let prog = std::fs::read_to_string(input)
        .unwrap()
        .trim()
        .split(',')
        .map(|x| x.parse().unwrap())
        .collect::<Vec<i128>>();
    mid_ir::to_mid_ir(&prog);
    // for i in mid_ir {
    //     println!("{:?}", i);
    // }
}
