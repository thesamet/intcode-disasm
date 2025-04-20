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

    #[error("Type conflict for {key}: type conflict between existing {bound_type} bound {current_bound} and {other} at {constraint}")]
    TypeConflict {
        key: VariableKind,
        bound_type: BoundType,
        other: Type,
        current_bound: Type,
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
}
