mod disasm;

use clap::{Parser, Subcommand};
use disasm::{low_ir::Instruction, mid_ir};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    input: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Disassemble,
    Intermediate,
}

fn main() {
    env_logger::builder().format_timestamp(None).init();
    let cli = Cli::parse();
    let prog = std::fs::read_to_string(cli.input.unwrap())
        .unwrap()
        .trim()
        .split(',')
        .map(|x| x.parse().unwrap())
        .collect::<Vec<i128>>();

    match cli.command {
        Command::Intermediate => intermediate(&prog),
        Command::Disassemble => disassemble(&prog),
    }
}

fn disassemble(prog: &[i128]) {
    let inst = Instruction::parse_program(prog);
    for (addr, i) in inst.iter() {
        println!("{:8}  {}", addr, i);
    }
}

fn intermediate(prog: &[i128]) {
    mid_ir::to_mid_ir(prog);
    // for i in mid_ir {
    //     println!("{:?}", i);
    // }
}
