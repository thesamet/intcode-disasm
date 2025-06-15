#!/usr/bin/env sh
cd "$(dirname "$0")"
cargo run -- mcp ../aoc-2019-rust/data/inputs/25.txt --symbols data/25.symbols
