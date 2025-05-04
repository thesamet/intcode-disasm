# SSA Conversion Logic and Nuances (`src/disasm/v2/ssa_form.rs`)

Converting the v3 LIR (Lowered Intermediate Representation) after Data Flow Analysis into Static Single Assignment (SSA) form is a complex process within this codebase, implemented primarily in `src/disasm/v2/ssa_form.rs`. This document details the core logic, key data structures, and subtle issues encountered during its implementation and debugging, aiming to clarify the process for future maintenance.

## Overview: A Multi-Pass Process

The conversion isn't a single linear pass but involves several distinct conceptual stages working together:

1.  **Phi Function Placement (`place_phi_functions`):** Identifies which variables require phi functions at the start of which blocks based on dominance frontiers and data flow information (multiple incoming definitions for a live variable, or function return values being accessed). Only *places* the phi function structure (`PhiFunction { result: VersionedMemoryReference { version: 0, .. }, inputs: {} }`) without assigning final versions or inputs yet.

2.  **Pass 1: Versioning Writes & Phis (`build_ssa_blocks_with_write_versioning`):**
    *   Iterates through blocks topologically (or simply iterates, correctness ensured by later passes).
    *   Uses a **global `VersionRegistry`** (`version_registry`) to track the *next available version number* for each `MemoryReferenceType` across the entire function.
    *   Assigns initial versions to the `result` of placed phi functions, incrementing the global counter in `version_registry`. These versions are stored in the block's local `start_state` and `end_state`.
    *   Processes each instruction within the block using `map_rw`:
        *   **Writes (`map_write`):** For the `target` of an `Assign`, it creates the *next* version using the global `version_registry`, stores this new version in the block's local `end_state`, and uses this new version in the resulting `SsaMemoryReference` for the instruction's target.
        *   **Reads (`map_read`):** Converts source operands (`src` expression, `cond`, `addr`) using the state *before* the current instruction's write potentially occurred (using `pre_instr_state.convert_to_ssa_memory_reference`). The resulting `SsaMemoryReference` might contain intermediate versions.
    *   This pass produces `SsaBlock`s where write targets and phi results have their *final* versions, but reads and phi inputs might still hold intermediate versions or require lookup.

3.  **Pass 1.5: State Computation (`compute_start_end_states`):**
    *   Iteratively propagates the `end_state` version information from predecessor blocks to the `start_state` of successor blocks.
    *   This process continues until no more changes occur (convergence).
    *   It respects phi functions: if a block has a phi for variable `X`, the versions of `X` from predecessors do *not* propagate into that block's `start_state` (the phi result version takes precedence).
    *   Crucially, propagation must only happen *once* per variable per edge per iteration to avoid incorrect state merging or duplicate increments.
    *   This pass calculates the **final, converged `start_state` and `end_state`** for every block, representing the variable versions available at block entry and exit considering all control flow paths.

4.  **Pass 2: Resolving Reads & Phi Inputs (`populate_reads_and_phis`):**
    *   Re-iterates through the blocks and their instructions/phis.
    *   **Phi Inputs:** For each phi function, it looks up the version of the required variable in the *final `end_state`* of the corresponding predecessor block and populates the `inputs` map.
    *   **Instruction Reads:** Re-maps the read operands within instructions using the block's *final `start_state`*. This uses the `resolve_ssa_expression` logic to find the correct, final version for each read.

## Key Data Structures

*   **`MemoryReferenceType`:** An enum (`Memory`, `RelativeMemory`, `Pointer`) representing the *kind* of memory location being versioned. Used as the key in `VersionRegistry`.
*   **`VersionedMemoryReference`:** Holds a `MemoryReferenceType`, a `FunctionId` (v2), and a `version` number. Represents a specific definition site.
*   **`SsaMemoryReference`:** An enum wrapping either `Versioned(VersionedMemoryReference)` or `Deref(Box<Expression<SsaMemoryReference>>)`. This is the type used within SSA `Instruction`s and `Expression`s.
*   **`VersionRegistry`:** A `HashMap<MemoryReferenceType, VersionedMemoryReference>` tracking the *current* version for each variable kind within a specific scope (global function scope during Pass 1 writes, block-local scope for `start_state`/`end_state`).
    *   `current_version()`: Gets the latest known version (or 0 if unknown).
    *   `create_next_version()`: Gets the current version, increments it, stores the new version, and returns it. **Must be called exactly once per definition.**
    *   `set_version()`: Explicitly sets a version (used for initial state and propagation).
    *   `has_version_for()`: Checks if a version exists for a given kind.
    *   `convert_to_ssa_memory_reference()` / `convert_to_ssa_expression()`: Used in Pass 1 to transform `MemoryReference` -> `SsaMemoryReference` based on the *current* registry state. Handles `Deref` recursively.
    *   `resolve_ssa_expression()`: Used in Pass 2 to update an *existing* `Expression<SsaMemoryReference>` based on the *final* versions in a converged `start_state` registry. Handles `Deref` recursively.

## Subtle Issues and Solutions

### 1. Read-Before-Write in Instruction Mapping

*   **Problem:** In an instruction like `[R-4]_v2 = [R-4]_v1 + 10`, the read of `[R-4]` must use version `v1`, while the write creates `v2`. If the mapping process updates the global version registry *before* processing the read, the read might incorrectly resolve to `v2`.
*   **Solution (`build_ssa_blocks...`):**
    *   Before mapping each instruction with `map_rw`, clone the current global `version_registry` into `pre_instr_state`.
    *   Pass a 3-tuple `(&pre_instr_state, &mut version_registry, &mut end_state)` to `map_rw`.
    *   The `map_read` closure uses the immutable `pre_instr_state` (calling `convert_to_ssa_memory_reference`) to resolve reads based on the versions *before* the instruction's effect.
    *   The `map_write` closure uses the mutable `version_registry` (calling `create_next_version`) and `end_state` (calling `set_version`) to create the new version for the write target.

```rust
// Simplified build_ssa_blocks_with_write_versioning loop
for instr_node in block_view.low_instructions() {
    // Capture state *before* instruction mapping
    let pre_instr_state = version_registry.clone();

    // State tuple for map_rw
    let mut state = (&pre_instr_state, &mut version_registry, &mut end_state);

    // map_read uses state.0 (pre_instr_state)
    // map_write uses state.1 (version_registry) and state.2 (end_state)
    let ssa_instr = instr_node.map_rw(&mut state, map_read, map_write);
    instructions.push(ssa_instr);
}
```

### 2. Correct Read Resolution in Pass 2

*   **Problem:** When resolving reads in `populate_reads_and_phis` (Pass 2), simply looking up the version in the block's `start_state` is insufficient. If a variable is written *within* the current block before being read, its definition won't be in the `start_state` (which reflects versions *entering* the block). Defaulting to version 0 in this case is wrong.
*   **Solution (`resolve_ssa_expression` and `map_read` in `populate_reads_and_phis`):**
    *   When resolving a `Versioned(v_local)` read using a specific `registry` (the block's final `start_state`):
    *   Check `registry.has_version_for(&v_local.kind)`.
    *   If `true`: The definition from the start state dominates. Use `registry.current_version(&v_local.kind)`.
    *   If `false`: The definition must have occurred within the current block during Pass 1. The version already stored in `v_local` is the correct one. Return `SsaMemoryReference::Versioned(*v_local)`.

```rust
// Simplified resolve_ssa_expression logic
fn resolve_ssa_expression(&self, expr: &Expression<SsaMemoryReference>) -> Expression<SsaMemoryReference> {
    expr.map(&mut |op: &SsaMemoryReference| {
        match op {
            SsaMemoryReference::Versioned(v_partial) => {
                // 'self' is the start_state registry
                if self.has_version_for(&v_partial.kind) {
                    self.current_version(&v_partial.kind).into() // Use start_state version
                } else {
                    *op // Use the version already assigned in Pass 1
                }
            }
            SsaMemoryReference::Deref(inner) => {
                // Recurse using the same logic
                SsaMemoryReference::Deref(Box::new(self.resolve_ssa_expression(inner.as_ref())))
            }
        }
    })
}
```

### 3. Distinguishing Conversion vs. Resolution (`Deref` Recursion)

*   **Problem:** Using the same recursive function (`current_expression` initially) to both *convert* `MemoryReference` to `SsaMemoryReference` (Pass 1) and *resolve* versions within an existing `Expression<SsaMemoryReference>` (Pass 2) caused stack overflows. The conversion step within the resolution step could trigger infinite recursion on `Deref`.
*   **Solution:** Implement two distinct methods in `VersionRegistry`:
    *   `convert_to_ssa_expression`: Takes `Expression<MemoryReference>` -> `Expression<SsaMemoryReference>`. Used only in Pass 1 (`build_ssa_blocks...`).
    *   `resolve_ssa_expression`: Takes `Expression<SsaMemoryReference>` -> `Expression<SsaMemoryReference>`. Used only in Pass 2 (`populate_reads_and_phis`). This separation breaks the problematic recursive cycle.

### 4. Duplicate Version Increments/Propagation

*   **Problem:** Accidental duplication of calls like `create_next_version`, `set_version` within loops or state propagation logic led to incorrect, inflated version numbers.
*   **Solution:** Careful code review and testing to ensure each logical definition increments the version counter exactly once and each state propagation step applies versions correctly without duplication. For example, the bug fixed in `compute_start_end_states` involved removing extra `set_version` calls.

### 5. Phi Input Mapping

*   **Problem:** When creating the final `PhiFunction` in Pass 2, the `PredecessorKind` used as the key in the `inputs` map must also use `SsaMemoryReference` (containing the final versions), not the original `MemoryReference`.
*   **Solution (`populate_reads_and_phis`):** After retrieving the correct input `VersionedMemoryReference` from the predecessor's `end_state`, map the original `v3::PredecessorKind<MemoryReference>` to `v3::PredecessorKind<SsaMemoryReference>` using `pred.map(&mut map_mem_ref)` before inserting into the `phi.inputs` map. The `map_mem_ref` closure uses `pred_ssa_block.end_state.convert_to_ssa_memory_reference` to ensure the expressions within the predecessor kind are correctly versioned.


By understanding these distinct passes and potential pitfalls, especially around state management and the conversion/resolution distinction, the SSA conversion logic becomes more maintainable and robust.
