# Decision Log

This file records architectural and implementation decisions using a list format.
2025-05-19 09:24:04 - Log of updates made.

*

## Decision

* Implement a type inference system for the V3 decompiler that tracks upper and lower bounds for type variables until reaching a fixed point

## Rationale

* This approach allows for incremental refinement of types as more constraints are discovered
* The lattice structure with Unknown (bottom) and Any (top) provides a clear framework for type relationships
* Using an iterative constraint solver enables handling complex type relationships and dependencies
* Integrating after the function call analysis step leverages existing information about function boundaries and call sites

## Implementation Details

* The type system will include basic types (Integer, Boolean, Character), compound types (Pointer, Function, Tuple), and type variables
* Constraints will be generated from SSA expressions, phi functions, and instructions
* The constraint solver will use an iterative algorithm to solve constraints until a fixed point is reached
* The implementation will follow a phased approach, starting with the basic structure and type system, then constraint generation, constraint solving, and finally testing and integration

2025-05-19 09:24:04 - Initial creation of decisionLog.md based on the high-level design in the type inference README.
---
[2025-05-19 09:57:19] - Refined role of `analyzer.rs` in Type Inference
## Decision
* The `src/disasm/v3/type_inference/analyzer.rs` module, initially planned as the main orchestrator for type inference, will instead serve as a helper module for `src/disasm/v3/type_inference/solver.rs`.

## Rationale
* The primary logic for constraint solving resides in `solver.rs`. The `analyzer.rs` can encapsulate more complex or specific helper routines (e.g., for unification of complex types, or model interaction if needed by the solver) without being a full analysis pipeline step itself. This simplifies the main solver's direct responsibilities.

## Implementation Details
* `analyzer.rs` will contain the `TypeInferenceAnalyzer` struct. This struct will initially be empty and methods will be added as needed to support `solver.rs`.
* The `README.md` for type inference has been updated to reflect this changed role.
---
[2025-05-19 10:21:17] - Refined `glb` and `lub` type operations
## Decision
* The `Type::glb` and `Type::lub` functions in `src/disasm/v3/type_inference/types.rs` have been updated to incorporate more nuanced subtyping rules and behaviors for tuple and symbolic types.

## Rationale
* **Tuple Subtyping**: The previous tuple GLB/LUB logic assumed tuples of the same length or resulted in `Unknown`/`Any`. The new rule (`ts1` is a subtype of `ts2` if each element of `ts1` is a subtype of the corresponding element in `ts2`, and `ts1` has at least as many elements as `ts2`) provides a more flexible and accurate model for tuple compatibility.
* **Symbolic Composition**: Removing canonical ordering for `GLB(t1, t2)` and `LUB(t1, t2)` when `t1` or `t2` are `TypeVar` or other symbolic types allows for direct composition of these expressions, which might be important for the solver's step-by-step simplification.
* **New Subtyping Axioms**: Explicitly defining relationships like `Char <: Int`, `Pointer <: Int`, `Function <: Pointer(Any)`, and the role of `Truthy` makes the type lattice richer and allows for more precise inference.

## Implementation Details
* **`glb(Tuple(v1), Tuple(v2))`**: Result tuple length is `max(len(v1), len(v2))`. Common elements are GLB'd. Extra elements from the longer tuple are preserved.
* **`lub(Tuple(v1), Tuple(v2))`**: Result tuple length is `min(len(v1), len(v2))`. Elements are LUB'd.
* **Symbolic `GLB`/`LUB`**: Arguments `t1` and `t2` are boxed directly without reordering when forming `Type::GLB(Box::new(t1), Box::new(t2))` or `Type::LUB(Box::new(t1), Box::new(t2))`.
* **New Subtyping Rules Incorporated**:
    * `Char <: Int` => `glb(Char, Int) = Char`, `lub(Char, Int) = Int`
    * `Bool <: Int` => `glb(Bool, Int) = Bool`, `lub(Bool, Int) = Int`
    * `Pointer(T) <: Int` => `glb(Pointer(T), Int) = Pointer(T)`, `lub(Pointer(T), Int) = Int`
    * `Function <: Int` => `glb(Function, Int) = Function`, `lub(Function, Int) = Int`
    * `Function <: Pointer(Any)` => `glb(Function, Pointer(Any)) = Function`, `lub(Function, Pointer(Any)) = Pointer(Any)`
    * `Int <: Truthy` => `glb(Int, Truthy) = Int`, `lub(Int, Truthy) = Truthy` (and similar for `Bool`, `Char`, `Pointer`, `Function` due to transitivity).
    * `lub(Function, Pointer(T))` (where `T` is not `Any`) now correctly yields `Pointer(Any)` as `Function <: Pointer(Any)` and `Pointer(T) <: Pointer(Any)`.
---
[2025-05-19 10:29:33] - Implemented `Type::is_subtype_of` and refactored `glb`/`lub`
## Decision
* Implemented a new method `Type::is_subtype_of(&self, other: &Type) -> bool` in `src/disasm/v3/type_inference/types.rs`.
* Refactored `Type::glb` and `Type::lub` methods to utilize `is_subtype_of` for initial checks, simplifying their internal logic.

## Rationale
* **Centralized Subtyping Logic**: The `is_subtype_of` method consolidates all subtyping rules (axiomatic, structural, symbolic interactions) into a single, authoritative function. This improves clarity, maintainability, and consistency.
* **Simplified GLB/LUB**: By first checking `t1.is_subtype_of(t2)` and `t2.is_subtype_of(t1)`, the `glb` and `lub` functions can immediately return the appropriate type if a direct subtyping relationship exists. This significantly reduces the number of specific cases that need to be handled within their `match` statements.
* **Improved Readability**: The `glb` and `lub` functions become easier to understand as their primary role shifts to handling cases where no direct subtyping exists, focusing on structural combinations or forming new symbolic types.

## Implementation Details
* **`is_subtype_of` Implementation**:
    * Handles base cases: `self == other`, `Unknown` (bottom), `Any` (top).
    * Implements axiomatic rules: `Char <: Int`, `Bool <: Int`, `Pointer <: Int`, `Function <: Int`, `Function <: Pointer(Any)`, and `Truthy` relationships.
    * Implements structural rules: Covariant pointers, contravariant function parameters, covariant function returns, and specific tuple subtyping (`len(T1) >= len(T2)` and element-wise subtyping).
    * Defines interactions with symbolic `GLB` and `LUB` types (e.g., `X <: GLB(A,B)` iff `X <: A AND X <: B`).
* **`glb` Refactoring**:
    * Checks `t1.is_subtype_of(t2)` (returns `t1`) and `t2.is_subtype_of(t1)` (returns `t2`) first.
    * Remaining `match` focuses on structural combinations (Pointer, Function, Tuple) and forming symbolic `GLB` for `TypeVar` or other symbolic types, or `Unknown`.
* **`lub` Refactoring**:
    * Checks `t1.is_subtype_of(t2)` (returns `t2`) and `t2.is_subtype_of(t1)` (returns `t1`) first.
    * Remaining `match` focuses on specific LUB axioms (e.g., `lub(Char, Bool) = Int`), structural combinations (Pointer, Function, Tuple), and forming symbolic `LUB` for `TypeVar` or other symbolic types, or `Any`.