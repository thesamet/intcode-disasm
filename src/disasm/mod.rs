mod code_printer;
pub mod parser;
pub mod v2;

use thiserror::Error;
use v2::type_inference::{
    constraints::Constraint,
    solver::BoundType,
    types::{Type, VariableKind},
    TypeInferenceResult,
};

/// Represents errors that can occur during disassembly operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("Disassembly operation failed")]
    DisassemblyFailed,

    #[error("Type conflict for {key}: existing {bound_type} bound {current_value} and {other} at {constraint}")]
    TypeConflict {
        key: VariableKind,
        bound_type: BoundType,
        current_value: Type,
        other: Type,
        constraint: Constraint,
        partial_result: Box<TypeInferenceResult>,
    },

    #[error("{bound_type} bound conflict: type conflict between {left} and {right} for {var_type} at {constraint}")]
    BoundConflict {
        bound_type: BoundType,
        left: Type,
        right: Type,
        var_type: Type,
        constraint: Constraint,
    },
    #[error("Type inconsistency for {key}: {bound_type} bound {lower} not a subtype of {upper}")]
    TypeInconsistency {
        key: VariableKind,
        bound_type: BoundType,
        lower: Type,
        upper: Type,
    },
}
