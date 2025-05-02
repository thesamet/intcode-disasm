mod code_printer;
// pub mod hlr;
pub mod model2;
pub mod parser;
mod test_utils;
pub mod v2;

use thiserror::Error;
/*
use v2::type_inference::{
    constraints::Constraint,
    solver::BoundType,
    types::{Type, VariableKind},
    visuals::TraceColors,
    TypeInferenceResult,
};
*/

/// Represents errors that can occur during disassembly operations
#[derive(Error, Debug)]
pub enum Error {
    /*
    #[error("Type conflict for {key}: existing {bound_type} bound {current_value} and {other} at {constraint}")]
    TypeConflict {
        key: VariableKind,
        bound_type: BoundType,
        current_value: Type,
        other: Type,
        constraint: Constraint,
        partial_result: Box<TypeInferenceResult>,
    },

    #[error("Type inconsistency for {key}: {bound_type} bound {lower} not a subtype of {upper}")]
    TypeInconsistency {
        key: VariableKind,
        bound_type: BoundType,
        lower: Type,
        upper: Type,
    },
    #[error("Invalid function pointer value {addr} for {}", TraceColors::format_constraint(.constraint))]
    InvalidFunctionPointerValue { addr: usize, constraint: Constraint },
    */
    #[error("Analysis failed: {0}")]
    AnalysisFailure(String),
}
