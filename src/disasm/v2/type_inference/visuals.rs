use colored::{Color, ColoredString, Colorize};
use std::fmt;

/// Color scheme for trace and type inference visualization
pub struct TraceColors;

impl TraceColors {
    // Type colors
    pub fn var() -> Color {
        Color::BrightCyan
    }
    pub fn type_name() -> Color {
        Color::BrightMagenta
    }
    pub fn bound() -> Color {
        Color::BrightYellow
    }
    pub fn constraint() -> Color {
        Color::BrightGreen
    }
    pub fn location() -> Color {
        Color::Blue
    } // Using blue instead of bright black for better readability
    pub fn header() -> Color {
        Color::BrightBlue
    }

    // Apply colors to different elements
    pub fn format_var<T: fmt::Display>(var: T) -> ColoredString {
        format!("{}", var).color(Self::var()).bold()
    }

    pub fn format_type<T: fmt::Display>(typ: T) -> ColoredString {
        format!("{}", typ).color(Self::type_name()).bold()
    }

    pub fn format_constraint<T: fmt::Display>(constraint: T) -> ColoredString {
        format!("{}", constraint).color(Self::constraint()).bold()
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
