# Intcode Decompiler

A static analysis toolkit for **Intcode** — the fictional virtual machine from [Advent of Code 2019](https://adventofcode.com/2019/day/2). This project disassembles, decompiles, and type-infers Intcode programs, lifting raw bytecode into readable high-level representations.

---

## What is Intcode?

Intcode is a simple register-based virtual machine whose programs are encoded as comma-separated integers (e.g. `1,0,0,3,99`). It was introduced in Advent of Code 2019 and extended across several puzzles, eventually supporting I/O, conditional jumps, and relative addressing.

### Memory Model

An Intcode program is a flat integer array. The machine starts execution at address 0 and steps through instructions sequentially. Memory is effectively unbounded — reads from uninitialized addresses return 0.

### Parameter Modes

Each parameter in an instruction has a mode, encoded as digits in the opcode value:

| Mode | Name      | Meaning                                                   |
|------|-----------|-----------------------------------------------------------|
| 0    | Memory    | Parameter is an address; reads/writes that memory cell    |
| 1    | Immediate | Parameter is a literal value (read-only)                  |
| 2    | Relative  | Parameter is an offset from the **R** (relative base) register |

The mode digits are packed into the opcode from the hundreds digit upward. For example, `1202` means opcode `02` (multiply) with modes `2, 1, 0` for the three parameters.

### Opcodes

| Opcode | Mnemonic        | Parameters | Description                                                           |
|--------|-----------------|------------|-----------------------------------------------------------------------|
| 1      | Add             | a, b, dst  | `dst = a + b`                                                         |
| 2      | Mul             | a, b, dst  | `dst = a * b`                                                         |
| 3      | Input           | dst        | Read one integer from input into `dst`                                |
| 4      | Output          | src        | Emit `src` as output                                                  |
| 5      | JumpTrue        | cond, addr | Jump to `addr` if `cond != 0`                                         |
| 6      | JumpFalse       | cond, addr | Jump to `addr` if `cond == 0`                                         |
| 7      | Less            | a, b, dst  | `dst = (a < b) ? 1 : 0`                                              |
| 8      | Equal           | a, b, dst  | `dst = (a == b) ? 1 : 0`                                             |
| 9      | AdjustRelBase   | offset     | `R += offset`                                                         |
| 99     | Halt            | —          | Terminate execution                                                   |

### The R Register and Calling Convention

The **R** (relative base) register doubles as a stack pointer. Functions increment R on entry to allocate a stack frame and decrement it before returning. Arguments are passed at positive offsets above R before the call; the return address is stored at `[R]`. Local variables live at negative R offsets within the callee.

### Indirect Addressing

Intcode has no native pointer dereference instruction. Programs implement it by **self-modifying the operand** of a load or store instruction at runtime — overwriting the address field of a subsequent instruction before executing it. The decompiler detects this pattern and represents it as `*ptr` in the lifted output.

---

## What This Repo Provides

This project implements a complete static analysis pipeline for Intcode:

- **Execution** — an interpreter that runs programs interactively against stdin/stdout
- **Disassembly** — decodes raw bytecode into readable assembly notation
- **Control flow recovery** — identifies basic blocks and builds a control flow graph
- **SSA conversion** — converts the program to Static Single Assignment form
- **Function detection** — recovers function boundaries, signatures, and call sites
- **Type inference** — infers types (integers, booleans, chars, pointers, structs, generics) from usage patterns
- **High-level decompilation** — emits structured code with inferred control flow (if/else, loops)
- **Symbol support** — accepts user-supplied name and type annotations to improve output quality
- **Web UI** — an interactive browser interface for exploring analysis results
- **MCP server** — exposes analysis results via the Model Context Protocol for AI-assisted exploration

---

## Analysis Pipeline

The pipeline transforms bytecode through a sequence of typed analysis phases. Each phase produces a result that the next phase builds on.

```
Binary
  │
  ▼
Image Scanner        — detects function boundaries by recognizing call/return patterns
  │
  ▼
Control Flow Graph   — partitions each function into basic blocks and connects them
  │
  ▼
Data Flow Analysis   — computes liveness, reaching definitions, and use-before-def sets
  │
  ▼
SSA Conversion       — rewrites variables into Static Single Assignment form with φ-nodes
  │
  ▼
Function Call Analysis — identifies call sites, argument passing, and return value slots
  │
  ▼
Folded SSA           — eliminates redundant φ-nodes and simplifies expressions
  │
  ▼
Structure Analysis   — detects field-offset access patterns and infers struct layouts
  │
  ▼
Type Inference       — solves a constraint system to assign types to all variables
  │
  ▼
HLR (High-Level Repr.) — emits decompiled code with control flow and type annotations
```

### Type Inference

The type system uses a **lattice-based constraint solver**. Constraints are generated from instruction semantics (e.g. a value used as a jump target must be a code pointer; a value used in an arithmetic comparison with 0 is likely a boolean or an integer). The solver propagates types through φ-nodes and across call sites.

Supported types include `Int`, `Bool`, `Char`, `Pointer<T>`, `Array<N; T>`, user-defined structs, function types, and generic type parameters. When a function is called with incompatible pointer types at different call sites, the solver introduces a generic type variable (e.g. `T0`) rather than collapsing to an overly broad type.

### Self-Modifying Code Recovery

The indirect addressing pattern (self-modification as pointer dereference) is detected in the image scanner and SSA phases. The decompiler tracks which instructions modify which operand addresses at runtime, and reconstructs the pointer variable and its dereference into a single `*ptr` expression in the output.

---

## Usage

### Prerequisites

```bash
# Rust toolchain (stable)
rustup update stable

# For web UI only
cargo install trunk
```

### CLI Commands

All commands take an Intcode file (comma-separated integers) as input.

#### Run a program

Execute an Intcode program interactively. Output values in the ASCII range are printed as characters; larger values are printed as decimal integers.

```bash
cargo run -- run <input.txt>
```

#### Disassemble

Print raw bytecode as annotated assembly instructions.

```bash
cargo run -- disassemble <input.txt>
```

#### High-level decompilation

Decompile to a high-level representation with inferred types and control flow.

```bash
cargo run -- hlr <input.txt>

# With user-supplied symbol names and type annotations
cargo run -- hlr <input.txt> --symbols <symbols.txt>
```

#### SSA form

```bash
cargo run -- ssa <input.txt>
cargo run -- folded-ssa <input.txt>
```

#### Type inference results

```bash
cargo run -- types <input.txt>

# Limit to a specific function by its address
cargo run -- types <input.txt> --function 1234
```

#### Color themes

All visualization commands support `--theme <name>` and `--list-themes`:

```bash
cargo run -- hlr <input.txt> --list-themes
cargo run -- hlr <input.txt> --theme monokai
```

#### Interactive REPL

Explore the analysis results interactively. Inspect functions, call them with arguments using the built-in emulator, and examine inferred types.

```bash
cargo run -- repl <input.txt> --symbols <symbols.txt>
```

#### Compile assembly to Intcode

Write assembly in the Intcode assembly notation and compile it to bytecode:

```bash
cargo run -- compile <source.asm>
```

### Symbol Files

A symbol file provides name and type hints that are woven into the analysis output. This is the primary way to guide the decompiler toward more readable results.

```
# Globals
G 34  SEPARATOR_START
G 166 COMMAND_PROMPT

# Custom types
T EncodedString
S GameThing { a, msg: Pointer<EncodedString>, c, d }

# Function signatures
F 1234 print_encoded_string(encoded_string: Pointer<EncodedString>)
F 1353 process_game_thing(thing: Pointer<GameThing>)

# Local variable names and types
V 1234 [R-1]_0 str   Pointer<EncodedString>
V 1130 [R-2]_2 index Int

# Suppress noisy phi nodes
XPHI 2329 [R-1]_3
```

Available types: `Int`, `Bool`, `Char`, `Pointer<T>`, `Array<N; T>`, any name defined with `T` or `S`.

### Web UI

The web interface provides interactive navigation of functions, SSA graphs, and type information.

```bash
# Terminal 1 — start the analysis server
cargo run -p analysis-server -- <input.txt>

# Terminal 2 — build and serve the frontend
cd crates/web-ui && trunk build

# Open http://127.0.0.1:8080
```

### MCP Server

Expose analysis results to an AI assistant via the [Model Context Protocol](https://modelcontextprotocol.io):

```bash
cargo run -- mcp <input.txt> --symbols <symbols.txt>
```

---

## Building and Testing

```bash
cargo build
cargo test
cargo clippy
cargo fmt
```
