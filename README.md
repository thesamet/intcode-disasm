# Disasm - Intcode Decompiler

A disassembler and decompiler for **Intcode** - a virtual machine that operates on comma-separated integers. The project performs static analysis to translate low-level bytecode into higher-level representations with advanced type inference.

## Quick Start

### Prerequisites

- Rust (latest stable)
- `trunk` for web UI development: `cargo install trunk`

### CLI Usage

```bash
# Basic disassembly
cargo run disassemble examples/level25.bin

# Full analysis pipeline with visualization
cargo run pipeline examples/level25.bin

# Interactive REPL for exploration
cargo run repl examples/level25.bin
```

### Web UI Setup

The web UI provides an interactive interface for exploring decompiled programs and type inference results.

#### 1. Start the Analysis Server

Load your Intcode program into the analysis server:

```bash
# Analyze a specific file
cargo run -p analysis-server <your_intcode_file>

# Example with provided test program
cargo run -p analysis-server test_program.txt
```

The server will:
- Load and analyze the Intcode program
- Run the complete V3 analysis pipeline (CFG, SSA, type inference)
- Start a web server on `http://127.0.0.1:8080`

#### 2. Build the Web UI

In a separate terminal, build the web frontend:

```bash
cd crates/web-ui
trunk build --release
```

**Note**: If `trunk` is not in your PATH, use the full path: `~/.cargo/bin/trunk build --release`

#### 3. Access the Web Interface

Open `http://127.0.0.1:8080` in your browser to explore:

- **Functions**: Navigate through decompiled functions with folded SSA views
- **Type Inference**: Explore inferred types and constraints (coming soon)
- **Analysis Results**: Interactive visualization of the complete analysis pipeline

## Architecture

### V3 Analysis Pipeline

```
Binary → Image Scanner → Control Flow → Data Flow → SSA → Function Calls → Folded SSA → Type Inference
```

### Components

- **CLI Commands**: Direct access to analysis pipeline with various output formats
- **Analysis Server**: Loads programs and serves analysis results via REST API
- **Web UI**: Interactive Leptos-based frontend for exploring results
- **Web Bridge**: Type-safe bridge between Rust analysis and web interface

### Key Features

- **Static Analysis**: Advanced control flow and data flow analysis
- **Type Inference**: Constraint-based type system with lattice-based types
- **SSA Form**: Static Single Assignment with optimization passes
- **Function Detection**: Automatic function boundary identification
- **Web Interface**: Real-time exploration of analysis results

## CLI Commands

- `compile <source>` - Compile assembly source to Intcode bytecode
- `disassemble <input>` - Basic disassembly of bytecode
- `pipeline <input>` - Run full analysis pipeline  
- `ssa <input>` - Output SSA form with color themes
- `folded-ssa <input>` - Output optimized SSA representation
- `types <input>` - Show type inference results
- `repl <input>` - Interactive analysis REPL

All visualization commands support `--theme <name>` and `--list-themes` options.

## Development

See `CLAUDE.md` for detailed development guidelines and architecture documentation.

### Build Commands

```bash
# Build everything
cargo build

# Run tests
cargo test

# Lint and format
cargo clippy
cargo fmt
```

## File Formats

**Input**: Comma-separated Intcode programs (e.g., `1,0,0,3,99`)

**Examples**:
- `test_program.txt` - Sample conditional program
- `examples/level25.bin` - Complex program with multiple functions

## Intcode Virtual Machine

Target architecture details:
- **Opcodes**: Add(1), Mul(2), Input(3), Output(4), JumpTrue(5), JumpFalse(6), Less(7), Equal(8), AdjustRelBase(9), Halt(99)
- **Parameter modes**: Memory(0), Immediate(1), Relative(2)  
- **R register**: Stack pointer for function calls
- **Indirect addressing**: Self-modifying code for pointer dereferencing

See `src/docs/machine_arch.md` for complete specification.