// disasm/src/disasm/v3/type_inference/constraints.rs

use crate::disasm::v3::{FunctionId, InstructionId};
use super::types::Type; // Assuming types.rs is in the parent module (type_inference)

/// Describes the reason a type constraint was generated.
/// This helps in debugging and understanding the inference process.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConstraintReason {
    /// `target = src` implies `type(src) <: type(target)`
    Assignment,
    /// `f(...)` implies `type(f) <: Function { ... }`
    FunctionCallImpliesFunctionType,
    /// `f(...)` and `type(f) :: Function { params: P, ... }` implies `type(actual_arg_i) <: type(P_i)`
    FunctionCallArgument(usize /* argument index */),
    /// `return expr;` in function `f` with declared return type `R` implies `type(expr) <: R`
    ReturnStatement,
    /// An operand for an arithmetic operation (e.g., +, *, <) implies `type(operand) <: Int`
    ArithmeticOperand,
    /// `lhs < rhs` or `lhs == rhs` implies `type(lhs) <: type(rhs)` (or vice-versa for symmetric ops, or both <: Int)
    ComparisonOperand, // Could be more specific, e.g. ComparisonRequiresIntLHS, ComparisonRequiresIntRHS
    /// `*p` (dereference) implies `type(p) <: Pointer(T)` for some T.
    PointerDereferenceSource,
    /// `*p = val` implies `type(val) <: T` where `type(p) <: Pointer(T)`.
    PointerDereferenceTarget,
    /// For a phi node `var = PHI(v1, v2, ...)`, implies `type(v_i) <: type(var)` for each incoming value.
    PhiNodeOperand,
    /// Type variable unification constraint, e.e. `TypeVar(X) <: TypeVar(Y)`
    TypeVariableSubstitution,
    /// Placeholder for other or more specific reasons.
    Other(String),
}

/// Represents a subtype constraint: `sub_type <: super_type`.
/// It also tracks the origin (source code location) and reason for the constraint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Constraint {
    pub sub_type: Type,
    pub super_type: Type,
    pub origin_function_id: FunctionId,
    pub origin_instruction_id: InstructionId,
    pub reason: ConstraintReason,
}

impl Constraint {
    pub fn new(
        sub_type: Type,
        super_type: Type,
        origin_function_id: FunctionId,
        origin_instruction_id: InstructionId,
        reason: ConstraintReason,
    ) -> Self {
        Constraint {
            sub_type,
            super_type,
            origin_function_id,
            origin_instruction_id,
            reason,
        }
    }
}
