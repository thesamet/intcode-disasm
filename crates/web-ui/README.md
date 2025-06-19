# Disasm Web UI

Interactive web interface for exploring decompiled Intcode programs and type inference results.

## Quick Start

### 1. Start the Analysis Server

From the project root, start the analysis server with your Intcode program:

```bash
# Analyze a specific file
cargo run -p analysis-server <your_intcode_file>

# Example with test program
cargo run -p analysis-server test_program.txt
```

### 2. Build the Web UI

```bash
cd crates/web-ui
trunk build --release
```

### 3. Access the Interface

Open `http://127.0.0.1:8080` in your browser to explore the analysis results.

## Development

### Prerequisites

Install `trunk` for building the web frontend:
```bash
cargo install trunk
```

### Development Workflow

For active development, use trunk's development server alongside the analysis server:

```bash
# Terminal 1: Start analysis server
cargo run -p analysis-server test_program.txt

# Terminal 2: Start web UI development server
cd crates/web-ui
trunk serve --port 8081
```

Then access the development UI at `http://localhost:8081` (note: you'll need to configure CORS or use the production build served by the analysis server).

## Features

- **Function Explorer**: Navigate through decompiled functions with folded SSA views
- **Real Analysis Data**: Displays actual results from the disasm V3 analysis pipeline
- **Server Integration**: Fetches analysis results via REST API from analysis server
- **Responsive Design**: Clean, developer-focused interface

## Architecture

- **Frontend**: Leptos (Rust) compiled to WebAssembly
- **Backend**: Analysis server loads programs and serves results via REST API
- **Bridge**: `web-bridge` crate provides type-safe conversion between disasm library and web formats
- **Styling**: Custom CSS with modern, accessible design

## Current Features

✅ **Real Analysis Integration**: Connected to actual disasm analysis pipeline  
✅ **Function Navigation**: Browse detected functions and their folded SSA representations  
✅ **Server Architecture**: Analysis server loads specific files at startup  
🚧 **Type Inference Visualization**: Interactive exploration of type variables (planned)  
🚧 **Constraint Graph Viewer**: Visual representation of type constraints (planned)