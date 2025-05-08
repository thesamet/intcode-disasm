use std::fmt::{self, Display};

use colored::Colorize;
use constraints::Constraint;
use types::Type;
use types::VariableKind;
use visuals::TraceColors;

// Declare the submodules
pub mod constraints;
pub mod result;
pub mod types;
pub mod visuals;
/*
pub mod analyzer;
pub mod solver;
pub mod tests;

// Re-export key types and functions for external use
pub use analyzer::TypeInferenceAnalyzer;
pub use result::TypeInferenceResult;
*/

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisTrace {
    pub key: VariableKind,
    pub change: BoundChange,
    pub reason: ChangeReason,
}

impl fmt::Display for AnalysisTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Colorize the key type

        let key_str = TraceColors::format_var(&self.key);

        if self.change.bound_type == BoundType::Upper {
            write!(
                f,
                "{} {:>14} {} {:<18} was {:<8}",
                TraceColors::format_header("Type"),
                key_str,
                ":<".blue(),
                TraceColors::format_type(&self.change.new_bounds.upper),
                TraceColors::format_type(&self.change.old_bounds.upper)
            )?;
        } else {
            write!(
                f,
                "{} {:>14} {} {:<18} was {:<8}",
                TraceColors::format_header("Type"),
                key_str,
                ":>".green(),
                TraceColors::format_type(&self.change.new_bounds.lower),
                TraceColors::format_type(&self.change.old_bounds.lower)
            )?;
        }
        write!(f, "{}", self.reason)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundChange {
    pub bound_type: BoundType,
    pub old_bounds: TypeBounds,
    pub new_bounds: TypeBounds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeReason {
    DecreaseUpperBoundFromConstraint { constraint: Constraint, other: Type },
    IncreaseLowerBoundFromConstraint { constraint: Constraint, other: Type },
    ConcreteRefinement,
}

impl Display for ChangeReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            ChangeReason::DecreaseUpperBoundFromConstraint { constraint, other } => {
                let other_str = if let Type::Variable(var) = other {
                    TraceColors::format_var(var)
                } else {
                    TraceColors::format_type(other)
                };

                let constraint_str = TraceColors::format_constraint(constraint).to_string();

                write!(f, "  {constraint_str} with {other_str}")
            }
            ChangeReason::IncreaseLowerBoundFromConstraint { constraint, other } => {
                let other_str = if let Type::Variable(var) = other {
                    TraceColors::format_var(var)
                } else {
                    TraceColors::format_type(other)
                };
                let constraint_str = TraceColors::format_constraint(constraint).to_string();
                write!(f, "  {constraint_str} with {other_str}")
            }
            ChangeReason::ConcreteRefinement => {
                write!(
                    f,
                    "  {}",
                    TraceColors::format_bound("Concrete type refinement")
                )
            }
        }
    }
}

/// Enum to distinguish between upper and lower bound conflicts
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum BoundType {
    Upper,
    Lower,
}

impl fmt::Display for BoundType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BoundType::Upper => write!(f, "Upper"),
            BoundType::Lower => write!(f, "Lower"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeBounds {
    pub lower: Type,
    pub upper: Type,
}

impl TypeBounds {
    fn new(lower: Type, upper: Type) -> Self {
        Self { lower, upper }
    }
}
