use std::fmt;

use crate::disasm::v2::{instructions::InstructionId, model::FunctionId};

use super::{types::Type, visuals::TraceColors};

/// Reason for a constraint between types
#[derive(Debug, Clone, Copy, PartialEq, Ord, PartialOrd, Eq)]
pub enum ConstraintReason {
    /// Addition operations imply integer types
    AddSecondParameterImpliesInt,

    // The addition is either numeric or pointer addition. The destination is a more
    // generic type that can contain the type of the first parameter.
    AddFirstParameterSubtypeOfDestination,

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
    IndirectFunctionCall,
    ImmediateIsSubtypeOfInt,
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
    pub addr: InstructionId,
    pub function_id: FunctionId,

    /// The reason for this constraint
    pub reason: ConstraintReason,
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Format the left side with appropriate color
        let left_str = if let Type::Variable(var) = &self.left {
            TraceColors::format_var(var)
        } else {
            TraceColors::format_type(&self.left)
        };

        // Format the right side with appropriate color
        let right_str = if let Type::Variable(var) = &self.right {
            TraceColors::format_var(var)
        } else {
            TraceColors::format_type(&self.right)
        };

        // Format the location and reason
        let location = TraceColors::format_location(format!("{}:{}", self.function_id, self.addr));
        let reason = TraceColors::format_constraint(self.reason);

        write!(
            f,
            "{} {} {} {} {} {} {}",
            left_str,
            TraceColors::format_relation("<:"),
            right_str,
            TraceColors::format_location("at"),
            location,
            TraceColors::format_location("because"),
            reason
        )
    }
}
