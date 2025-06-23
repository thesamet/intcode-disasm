# Type Inference Subsystem

This document provides detailed technical information about the V3 type inference subsystem, including architecture, debugging techniques, recent improvements, and known issues.

## Architecture Overview

The type inference system uses a **constraint-based approach** with the following key components:

### Core Components

1. **TypeVar System** (`types.rs`)
   - Type variables represent unknown types that get resolved through constraint solving
   - Each TypeVar has a unique `TypeVarId` and can be in two states:
     - `Bounds { upper_bounds, lower_bounds }` - actively being constrained
     - `Converged(Type)` - resolved to a concrete type

2. **Constraint Store** (`constraints.rs`)
   - Manages relationships between types through constraints
   - Supports equality constraints (`A = B`) and subtype constraints (`A <: B`)
   - Tracks constraint dependencies and updates them as types converge

3. **Inference Algorithm State** (`type_bounds_map.rs`)
   - Central registry for all type variables and their current states
   - Manages convergence tracking and dependency relationships
   - Provides deterministic iteration over type variables

4. **Constraint Generator** (`constraints_generator.rs`)
   - Analyzes SSA instructions to generate type constraints
   - Handles function calls, assignments, arithmetic, and memory operations
   - Integrates with UserDefs for symbol-based type hints

5. **Solver** (`solver.rs`)
   - Main orchestrator that runs the constraint solving algorithm
   - Implements compound type refinement for functions, tuples, and pointers
   - Handles generic pattern detection and transformation

### Analysis Pipeline

```
SSA Instructions → Constraint Generation → Iterative Solving → Generic Detection → Type Results
```

## Key Concepts

### Type Variable Paths

Type variables are identified by their semantic path in the program:

```rust
pub enum TypeVarPath {
    AssignmentSrc { function_id, instruction_id, expression_path },
    CallArg { function_id, instruction_id, index, expression_path },
    FunctionDefArg { function_id, index },
    PointerRefinement { function_id, original_type_var_id },
    // ... many others
}
```

### Compound Type Refinement

The system uses **refinement strategies** to handle complex types:

- **FunctionRefinement**: Decomposes function types into argument and return tuples
- **TupleRefinement**: Breaks tuples into individual element types  
- **PointerRefinement**: Creates refined type variables for pointer targets

### Generic Pattern Detection

A sophisticated system detects when type variables should become generic:

1. **Refinement Analysis**: Identifies PointerRefinement variables with incompatible bounds
2. **Generic Opportunity Creation**: Marks type variables as candidates for generics
3. **Generic Transformation**: Replaces refined types with proper generic type variables

## UserDefs Integration

The type inference system integrates with **UserDefs** (symbol definitions) to incorporate user-provided type hints:

### Symbol File Format
```
# Functions with typed parameters
F 1234 print_string(s: Pointer<EncodedString>)
F 1130 array_foreach(list: Pointer<T>, length: Int, item_size: Int, handler: Function(Pointer<T>, Int) -> ())

# Global variables
G 34 SEPARATOR_START Pointer<EncodedString>

# Struct definitions
S GameThing { a: Int, b: Pointer<EncodedString>, c: Bool, d: Function() -> () }

# Local variables
V 1234 [R-1]_0 temp_string Pointer<EncodedString>

# Exclude problematic phi nodes
XPHI 2329 [R-1]_3
```

### UserDefs Priority
- UserDefs constraints have **higher priority** than inferred constraints
- Function parameter types from UserDefs are enforced strongly
- Struct field types are used as starting constraints for type inference

## Debugging Techniques

### 1. Type Bounds Analysis
```rust
ctx.model.type_inference_result().print_all_type_bounds();
```

Output format:
```
ty42  AssignmentSrc { function_id: FunctionId(1130), instruction_id: InstructionId(5) } ∈ [lower_bounds, upper_bounds]
ty43  PointerRefinement { function_id: FunctionId(1130), original_type_var_id: TypeVarId(40) } == Int
```

### 2. Debug Logging
```bash
RUST_LOG=debug cargo run <command>
```

Key debug categories:
- Constraint generation and application
- Generic pattern detection iterations
- Type variable convergence events
- Refinement type transformations

### 3. Test Case Development
Create targeted test cases in `type_inference_tests.rs`:

```rust
#[test]
fn test_specific_issue() {
    let ctx = TypeInferenceComplete::test_context_with_user_defs(
        r#"
        assembly_code_here
        "#,
        UserDefs::from_lines(r#"
        symbol_definitions_here
        "#).unwrap(),
    ).unwrap();
    
    assert_marker_type!(ctx, 'a', Type::expected_type());
}
```

### 4. REPL Integration
Set `REPL=1` environment variable to drop into interactive debugging when assertions fail:

```bash
REPL=1 cargo test test_name
```

## Recent Improvements

### Generic Pattern Detection Enhancement (2024)

**Problem**: Functions called with different pointer types were showing `PointerRefinement` types instead of proper generics.

**Root Cause**: The generic detection system wasn't properly identifying PointerRefinement type variables that should become generic when they have incompatible bounds.

**Solution Implemented**:

1. **Enhanced `detect_generic_patterns()`**:
   ```rust
   // Check for PointerRefinement with incompatible bounds
   if let TypeVarPath::PointerRefinement { original_type_var_id, .. } = &node.path {
       let has_generic_bounds = upper_bounds.iter().any(|t| matches!(t, Type::Generic(_)));
       let has_multiple_type_vars = upper_bounds.iter()
           .filter(|t| matches!(t, Type::TypeVar(_)))
           .count() > 1;
       let concrete_types: Vec<_> = upper_bounds.iter()
           .filter(|t| !matches!(t, Type::TypeVar(_) | Type::Any))
           .collect();
       
       if has_generic_bounds || has_multiple_type_vars || concrete_types.len() >= 2 {
           // Create generic opportunity
       }
   }
   ```

2. **Enhanced `apply_generic_transformations()`**:
   ```rust
   // For PointerRefinement, update original type variable
   if let TypeVarPath::PointerRefinement { original_type_var_id, .. } = &opportunity.refinement_path {
       if !self.state.get_type_var_state(original_type_var_id).is_converged() {
           let generic_pointer_type = Type::Pointer(Box::new(Type::Generic(generic_id)));
           self.state.converge(original_type_var_id, generic_pointer_type, ConverganceType::ReplacedWithGeneric);
       }
   }
   ```

**Results**: 
- Function signatures now show `Pointer<T6>` instead of `Pointer<PointerRefinement { ... }>`
- Generic types are properly propagated through function call chains
- Type inference is more robust for polymorphic functions

### Non-Deterministic Behavior Fix (2024)

**Problem**: Type inference results were inconsistent between runs, showing different generic IDs and sometimes different parameter types.

**Root Cause**: HashMap iteration order was causing constraint processing to happen in different orders.

**Solution**: Made all HashMap iterations deterministic:

```rust
// Before: non-deterministic
self.constraints.iter()

// After: deterministic
pub fn iter(&self) -> impl Iterator<Item = (&ConstraintId, &Constraint)> {
    let mut items: Vec<_> = self.constraints.iter().collect();
    items.sort_by_key(|(id, _)| id.index());
    items.into_iter()
}
```

**Fixed locations**:
- `ConstraintStore::iter()`
- `InferenceAlgorithmState::iter_all_type_states()`  
- `InferenceAlgorithmState::iter_all_type_nodes()`
- `InferenceAlgorithmState::iter_all_vmr_to_type_var_id()`
- `Solver::try_solving()` type variable processing
- `Solver::detect_generic_patterns()` type variable processing

**Results**: 
- Consistent type inference results across multiple runs
- Deterministic generic ID assignment
- Stable function signature generation

### Debug Output Robustness (2024)

**Problem**: `RUST_LOG=debug` mode was causing panics due to unsafe `unwrap()` calls in type display code.

**Root Cause**: Type display methods were doing `user_defs.get_struct(id).unwrap().name` but struct IDs could be temporarily invalid during intermediate analysis phases.

**Solution**: Replaced `unwrap()` with graceful fallbacks:

```rust
// Before: panic-prone
self.registry.user_defs().get_struct(*id).unwrap().name

// After: robust
if let Some(struct_def) = self.registry.user_defs().get_struct(*id) {
    write!(f, "{}", struct_def.name)
} else {
    write!(f, "Struct({})", id.index())
}
```

**Results**:
- Debug logging works reliably without crashes
- Graceful degradation when type information is temporarily unavailable
- Better debugging experience for developers

## Common Issues and Solutions

### 1. PointerRefinement Not Becoming Generic

**Symptoms**: Function parameters show `PointerRefinement { ... }` instead of generic types.

**Debug Steps**:
1. Check if function is called with different pointer types
2. Verify generic pattern detection is running: look for "Generic pattern detection" logs
3. Check if PointerRefinement has multiple bounds or incompatible constraints

**Solution**: The enhanced generic detection system should handle this automatically. If not, check constraint generation for the function calls.

### 2. Empty Struct Field Bounds

**Symptoms**: Struct field types show empty bounds `∈ [{}, {}]`.

**Root Cause**: Struct field constraints aren't being properly connected to usage patterns.

**Debugging**: 
- Check if struct analysis is finding the struct usage
- Verify field access constraints are being generated
- Look for connections between field types and their usage contexts

### 3. Function Signature Inconsistency

**Symptoms**: Function signatures vary between runs or show unexpected parameter types.

**Solution**: Ensure all HashMap iterations are deterministic (this should be fixed in current version).

### 4. Type Variable Not Converging

**Symptoms**: Type variables remain in `Bounds` state instead of converging to concrete types.

**Debug Steps**:
1. Check upper and lower bounds intersection
2. Look for constraint cycles or contradictions
3. Verify UserDefs constraints are being applied correctly
4. Check if generic detection is interfering with convergence

## Testing Strategy

### Unit Tests
- **Focused tests** for specific type inference scenarios
- **Regression tests** for previously fixed issues
- **UserDefs integration tests** for symbol-based constraints

### Integration Tests  
- **Full pipeline tests** using real assembly programs
- **Consistency tests** to verify deterministic behavior
- **Performance tests** for large programs

### Test Utilities
- `assert_marker_type!` - verify specific type variable resolution
- `assert_function_pointer!` - check function type inference
- `TestContextBuilder` - create controlled test environments
- REPL integration for interactive debugging

## Performance Considerations

### Constraint Store Optimization
- Constraint deduplication to avoid redundant work
- Efficient dependency tracking for incremental updates
- Priority-based constraint processing

### Memory Management
- Type variable lifecycle management
- Constraint pruning after convergence
- Efficient representation of bounds sets

### Algorithmic Complexity
- Fixed-point iteration with convergence detection
- Constraint propagation ordering for faster convergence
- Generic detection as separate post-processing phase

## Future Improvements

### 1. Enhanced Struct Field Inference
- Better connection between field access patterns and field types
- Improved constraint propagation for struct operations
- Support for nested struct field access

### 2. Function Signature Inference Improvements
- More sophisticated polymorphic function detection
- Better handling of higher-order functions
- Improved constraint generation for complex call patterns

### 3. Performance Optimizations
- Incremental constraint solving for large programs
- Parallel constraint processing where possible
- More efficient data structures for constraint storage

### 4. Error Reporting
- Better error messages for type conflicts
- Source location tracking for constraint origins
- Suggestions for resolving type inference failures

## Implementation Notes

### Critical Patterns

1. **Always use hierarchical access**: `model.function(&function_id).block(&block_id).ssa()`
2. **Prefer deterministic iteration**: Sort by ID indices before iterating
3. **Handle missing UserDefs gracefully**: Use `if let Some()` instead of `unwrap()`
4. **Type variable dependencies**: Ensure proper dependency tracking for convergence
5. **Generic transformation timing**: Run after main constraint solving is complete

### Code Conventions

- **Strong typing**: Use custom ID types (`TypeVarId`, `ConstraintId`) over primitives
- **Early returns**: Prefer early exits over deep nesting in constraint generation
- **Comprehensive logging**: Use debug logging for tracking constraint flow
- **Robust error handling**: Avoid panics in type display and constraint application
- **Test coverage**: Every major feature should have dedicated test cases

This documentation should be updated as the type inference system evolves and new features are added.