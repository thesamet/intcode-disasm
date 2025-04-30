use std::fmt;

use crate::disasm::v2::{
    model::{BlockId, FunctionId},
    native::NativeInstructionId,
};

use super::{types::Type, visuals::TraceColors};

/// Reason for a constraint between types
#[derive(Debug, Copy, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum ConstraintReason {
    /// Addition operations imply integer types
    AddRules,

    /// Multiplication operations imply integer types
    MulImpliesInt,

    /// Comparison destination implies boolean type
    CompareDstImpliesBool,

    /// Comparison sources imply integer types
    CompareSrcImpliesInt,

    /// Output operations imply character type
    OutputImpliesChar,

    /// Input operations imply character type
    InputImpliesChar,

    /// Jump conditions imply boolean type
    JumpConditionImpliesTruthy,

    /// Both sides of a comparison must have the same type
    CompareSrcSameType,

    /// Assignment operations propagate types
    Assignment,

    /// Dereference operations imply pointer type
    Deref,

    /// Function parameter binding implies same type
    FunctionParameterBinding,

    /// Function return binding implies same type
    FunctionReturnBinding,

    /// Phi assignments propagate types
    PhiAssignment,

    /// Indirect function calls imply function pointer type
    IndirectFunctionCall {
        calling_block: BlockId,
    },
    ImmediateIsSubtypeOfInt,
    PointerSubtype,
    FunctionTypeParameter,
    TupleSubtype,
    FunctionPointerSubtype,
    FunctionPointerSignature,
    FunctionParameterBindingBetweenCalleeAndTypeVar,
    FunctionParameterBindingAtCallSite,
}

impl fmt::Display for ConstraintReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Delegate to the Debug implementation
        write!(f, "{:?}", self)
    }
}

/// Represents a constraint between two types. The constraint implies that
/// the left type is a subtype of the right type.
#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq)]
pub struct Constraint {
    pub left: Type,
    pub right: Type,

    /// The instruction address where this constraint was generated
    pub addr: NativeInstructionId,
    pub function_id: FunctionId,

    /// The reason for this constraint
    pub reason: ConstraintReason,
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        TraceColors::format_constraint(self).fmt(f)
    }
}
