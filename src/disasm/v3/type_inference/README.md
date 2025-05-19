# Type Inference System for V3

This document outlines the design and implementation of the type inference system for the V3 decompiler.

## Overview

The type inference system is an iterative process that tracks upper and lower bounds for type variables until reaching a fixed point. It follows the existing analysis pipeline structure and integrates after the function call analysis step.

## Directory Structure

```
src/disasm/v3/type_inference/
├── analyzer.rs     - Main analyzer implementation
├── constraints.rs  - Type constraints definition and operations
├── mod.rs          - Module exports
├── result.rs       - Type inference results data structure
├── solver.rs       - Constraint solver implementation
├── types.rs        - Type system definition
└── tests.rs        - Unit tests
```

## Type System

The type system is defined in `types.rs` and includes the following types:

```rust
/// Represents the possible types in our type system
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Type {
    /// Unknown type (bottom of the lattice)
    Unknown,
    /// Integer type
    Integer,
    /// Boolean type (result of comparisons)
    Boolean,
    /// Character type (for input/output operations)
    Character,
    /// Pointer type with optional pointee type
    Pointer(Box<Type>),
    /// Function type with parameter and return types
    Function {
        params: Vec<Type>,
        returns: Vec<Type>,
    },
    /// Type variable used during inference
    TypeVar(usize),
    /// Tuple type (for function arguments and returns)
    Tuple(Vec<Type>),
    /// Any type (top of the lattice)
    Any,
}
```

The type system also includes bounds for type variables:

```rust
/// Represents the bounds for a type variable
#[derive(Debug, Clone)]
pub struct TypeBounds {
    /// Lower bounds (types that are subtypes of this variable)
    pub lower_bounds: HashSet<Type>,
    /// Upper bounds (types that are supertypes of this variable)
    pub upper_bounds: HashSet<Type>,
}
```

## Constraints

Constraints are defined in `constraints.rs` and include:

```rust
/// Represents a type constraint between two types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    /// t1 = t2 (equality constraint)
    Equal(Type, Type),
    /// t1 <: t2 (subtype constraint)
    Subtype(Type, Type),
}

/// Reason for a constraint between types
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConstraintReason {
    /// Addition operations imply integer types
    AddOperation,
    /// Multiplication operations imply integer types
    MulOperation,
    /// Comparison operations imply boolean result
    ComparisonResult,
    /// Comparison operands must be comparable
    ComparisonOperands,
    /// Assignment propagates types
    Assignment,
    /// Function parameter binding
    FunctionParameter,
    /// Function return binding
    FunctionReturn,
    /// Phi node assignment
    PhiAssignment,
    /// Pointer dereference
    Dereference,
    /// Conditional jump
    ConditionalJump,
    /// Input operation
    InputOperation,
    /// Output operation
    OutputOperation,
}
```

## Constraint Generation

The constraint generator is implemented in `constraints.rs` and generates constraints from SSA expressions:

```rust
pub struct ConstraintGenerator {
    /// Next available type variable ID
    next_type_var: usize,
    /// Maps SSA variables to their type variables
    var_types: HashMap<SsaMemoryReference, Type>,
    /// Generated constraints
    constraints: Vec<Constraint>,
}

impl ConstraintGenerator {
    /// Generate constraints from an expression
    pub fn generate_constraints_from_expr(&mut self, expr: &Expression<SsaMemoryReference>) -> Type {
        match expr {
            Expression::Constant(_) => Type::Integer,
            Expression::Addressable(addr) => self.get_or_create_type_for_var(addr),
            Expression::Binary { op, lhs, rhs } => {
                let lhs_type = self.generate_constraints_from_expr(lhs);
                let rhs_type = self.generate_constraints_from_expr(rhs);

                match op {
                    // Arithmetic operations require integer operands and produce integers
                    BinaryOperator::Add | BinaryOperator::Sub | BinaryOperator::Mul => {
                        self.add_constraint(Constraint::Equal(lhs_type.clone(), Type::Integer));
                        self.add_constraint(Constraint::Equal(rhs_type, Type::Integer));
                        Type::Integer
                    },
                    // Comparison operations require comparable operands and produce booleans
                    BinaryOperator::LessThan | BinaryOperator::LessThanOrEqual |
                    BinaryOperator::GreaterThan | BinaryOperator::GreaterThanOrEqual |
                    BinaryOperator::Equals | BinaryOperator::NotEquals => {
                        self.add_constraint(Constraint::Equal(lhs_type, rhs_type));
                        Type::Boolean
                    },
                }
            },
            // Handle other expression types...
        }
    }
}
```

## Constraint Solving

The constraint solver is implemented in `solver.rs` and uses an iterative algorithm to solve constraints:

```rust
pub struct ConstraintSolver {
    /// Type bounds for each type variable
    type_bounds: HashMap<usize, TypeBounds>,
    /// Constraints to be processed
    constraints: Vec<Constraint>,
}

impl ConstraintSolver {
    /// Solve constraints until a fixed point is reached
    pub fn solve(&mut self) -> Result<HashMap<usize, Type>, String> {
        let mut changed = true;

        // Iterate until fixed point
        while changed {
            changed = false;

            // Process each constraint
            let constraints = std::mem::take(&mut self.constraints);
            for constraint in constraints {
                let new_constraints = self.process_constraint(constraint)?;
                if !new_constraints.is_empty() {
                    changed = true;
                    self.constraints.extend(new_constraints);
                }
            }
        }

        // Compute final types from bounds
        self.compute_final_types()
    }

    /// Process a single constraint, potentially generating new constraints
    fn process_constraint(&mut self, constraint: Constraint) -> Result<Vec<Constraint>, String> {
        match constraint {
            Constraint::Equal(t1, t2) => self.process_equality(t1, t2),
            Constraint::Subtype(t1, t2) => self.process_subtype(t1, t2),
        }
    }

    // Implementation of process_equality, process_subtype, etc.
}
```

## Main Analyzer

The main analyzer is implemented in `analyzer.rs` and integrates with the existing pipeline:

```rust
pub struct TypeInferenceAnalyzer {
    model: Model<FunctionCallAnalysisComplete>,
}

impl TypeInferenceAnalyzer {
    pub fn new(model: Model<FunctionCallAnalysisComplete>) -> Self {
        Self { model }
    }

    pub fn run(model: Model<FunctionCallAnalysisComplete>) -> Result<Model<TypeInferenceComplete>, Error> {
        let analyzer = Self::new(model);
        analyzer.analyze()
    }

    fn analyze(self) -> Result<Model<TypeInferenceComplete>, Error> {
        let mut result = TypeInferenceResult::new();

        // Process each function
        for (_, function) in self.model.functions() {
            self.analyze_function(&function, &mut result);
        }

        // Return a new model with the updated state
        Ok(self.model.with_type_inference_result(result))
    }

    fn analyze_function(&self, function: &Function, result: &mut TypeInferenceResult) {
        // Generate constraints from function
        let mut constraint_generator = ConstraintGenerator::new();

        // Process each block in the function
        for (_, block) in function.blocks() {
            // Process phi functions
            for phi in &block.phi_functions {
                constraint_generator.generate_constraints_from_phi(phi);
            }

            // Process instructions
            for instr in block.instructions() {
                constraint_generator.generate_constraints_from_instruction(instr);
            }
        }

        // Solve constraints
        let constraints = constraint_generator.take_constraints();
        let var_types = constraint_generator.take_var_types();

        let mut solver = ConstraintSolver::new(constraints);
        let type_solution = solver.solve().unwrap_or_else(|_| HashMap::new());

        // Update result with inferred types
        result.add_function_types(function.function_id(), var_types, type_solution);
    }
}
```

## Result Structure

The result structure is defined in `result.rs`:

```rust
#[derive(Debug, Clone, Default)]
pub struct TypeInferenceResult {
    /// Maps function IDs to their inferred types
    pub function_types: HashMap<FunctionId, FunctionTypeInfo>,
}

#[derive(Debug, Clone)]
pub struct FunctionTypeInfo {
    /// Maps SSA variables to their inferred types
    pub var_types: HashMap<SsaMemoryReference, Type>,
}
```

## Integration with Analysis Pipeline

The type inference system is integrated into the analysis pipeline in `src/disasm/v3/analysis.rs`:

```rust
pub fn binary_to_type_inference(binary: Vec<i128>) -> Result<Model<TypeInferenceComplete>, Error> {
    let model = binary_to_function_calls(binary)?;
    TypeInferenceAnalyzer::run(model)
}

pub fn binary_to_folded_ssa(binary: Vec<i128>) -> Result<Model<FoldedSsaComplete>, Error> {
    let model = binary_to_type_inference(binary)?;
    FoldedSsaBuilder::run(model)
}
```

## Implementation Strategy

1. **First Phase**: Create the basic structure and type system
   - Implement the type system in `types.rs`
   - Set up the result structure in `result.rs`
   - Create the analyzer skeleton in `analyzer.rs`
   - Update the model to include the new state

2. **Second Phase**: Implement constraint generation
   - Implement constraint generation for expressions
   - Handle phi functions and instructions
   - Generate constraints for function calls and returns

3. **Third Phase**: Implement constraint solving
   - Implement the iterative constraint solver
   - Handle type variable bounds
   - Implement fixed-point computation

4. **Fourth Phase**: Testing and integration
   - Write unit tests for the type system
   - Test constraint generation and solving
   - Integrate with the existing pipeline
   - Test end-to-end with sample programs