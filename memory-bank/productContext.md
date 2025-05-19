# Product Context

This file provides a high-level overview of the project and the expected product that will be created. Initially it is based upon projectBrief.md (if provided) and all other available project-related information in the working directory. This file is intended to be updated as the project evolves, and should be used to inform all other modes of the project's goals and context.
2025-05-19 09:21:46 - Log of updates made will be appended as footnotes to the end of this file.

*

## Project Goal

* The "disasm" project is a decompiler for programs written in "Intcode assembly language". The primary goal is to translate decompiled assembly into a higher-level language with inferred type information.

## Key Features

* Decompilation of Intcode assembly programs into higher-level representations
* Type inference system to enhance the decompiled output with type information
* Static Single Assignment (SSA) form for program analysis
* Control flow and data flow analysis
* Function call detection and analysis

## Overall Architecture

* The project follows a pipeline architecture with multiple analysis stages:
  - Image scanning (parsing the raw Intcode program)
  - Control flow analysis (identifying basic blocks and functions)
  - Data flow analysis (tracking variable definitions and uses)
  - Function call analysis (identifying function calls and parameters)
  - Type inference (determining variable and expression types)
  - Folded SSA (optimizing the SSA representation)
  - Higher-level representation generation

2025-05-19 09:21:46 - Initial creation of the Memory Bank with project context derived from README.md and documentation files.