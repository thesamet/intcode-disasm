use colored::{Color, ColoredString, Colorize};
use itertools::Itertools;
use std::fmt;

use super::{
    constraints::Constraint,
    types::{Type, VariableKind},
};

/// Color scheme for trace and type inference visualization
pub struct TraceColors;

impl TraceColors {
    // Type colors
    pub fn var() -> Color {
        Color::BrightCyan
    }
    pub fn type_var() -> Color {
        Color::Yellow
    }
    pub fn type_name() -> Color {
        Color::BrightMagenta
    }
    pub fn bound() -> Color {
        Color::BrightYellow
    }
    pub fn location() -> Color {
        Color::Blue
    } // Using blue instead of bright black for better readability
    pub fn header() -> Color {
        Color::BrightBlue
    }

    // Apply colors to different elements
    pub fn format_var(var: &VariableKind) -> ColoredString {
        let function_id = match var.origin_info() {
            Some(oi) => format!("{}:", oi.function_id),
            None => "".to_string(),
        };
        match var {
            VariableKind::SsaVar(var) => {
                format!("{}{}", function_id, var).color(Self::var()).bold()
            }
            VariableKind::Const { value, .. } => format!("{}{}", function_id, value)
                .color(Self::var())
                .bold(),
            VariableKind::TypeVar(_) => format!("{}", var).color(Self::type_var()).bold(),
        }
    }

    pub fn format_type(typ: &Type) -> ColoredString {
        match typ {
            Type::Variable(var) => Self::format_var(var),
            Type::Tuple(ts) => {
                let mut s = "Tuple(".to_string();
                for (_, t) in ts.iter().with_position() {
                    s.push_str(&Self::format_type(t));
                    s.push_str(", ");
                }
                s.push(')');
                s.color(Self::type_name()).bold()
            }
            _ => format!("{}", typ).color(Self::type_name()).bold(),
        }
    }



    pub fn format_constraint(c: &Constraint) -> String {
        // Format the left side with appropriate color
        let left_str = if let Type::Variable(var) = &c.left {
            TraceColors::format_var(var)
        } else {
            TraceColors::format_type(&c.left)
        };

        // Format the right side with appropriate color
        let right_str = if let Type::Variable(var) = &c.right {
            TraceColors::format_var(var)
        } else {
            TraceColors::format_type(&c.right)
        };

        // Format the location and reason
        let location = TraceColors::format_location(format!("{}:{}", c.function_id, c.addr));
        let reason = c.reason.to_string();

        format!(
            "{left_str} {} {right_str} {}{} {} {}",
            TraceColors::format_relation("<:"),
            TraceColors::format_location("@"),
            location,
            TraceColors::format_location(":"),
            reason
        )
    }

    pub fn format_location<T: fmt::Display>(location: T) -> ColoredString {
        format!("{}", location).color(Self::location())
    }

    pub fn format_bound<T: fmt::Display>(bound: T) -> ColoredString {
        format!("{}", bound).color(Self::bound()).bold()
    }

    pub fn format_header<T: fmt::Display>(header: T) -> ColoredString {
        format!("{}", header).color(Self::header()).bold()
    }

    pub fn format_relation(text: &str) -> ColoredString {
        text.color(Self::bound()).bold()
    }
}
