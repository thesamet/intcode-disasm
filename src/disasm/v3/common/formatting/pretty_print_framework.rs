use super::colors::{Colors, SemanticColor}; // Import SemanticColor
use colored::Colorize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub struct PrettyPrintConfig {
    pub colors: Option<Colors>,
    pub show_types: bool,
    pub show_types_var_ids: bool,
    pub show_vars: bool,
    pub indent_width: usize,
}

impl Default for PrettyPrintConfig {
    fn default() -> Self {
        Self {
            colors: Some(Colors::default()),
            show_types: true,
            show_vars: true,
            show_types_var_ids: false,
            indent_width: 4,
        }
    }
}

impl PrettyPrintConfig {
    // Accessor methods
    pub fn colors(&self) -> Option<&Colors> {
        self.colors.as_ref()
    }

    pub fn apply_colors(&self) -> bool {
        // Added accessor
        self.colors.is_some()
    }

    pub fn show_types(&self) -> bool {
        self.show_types
    }

    pub fn show_vars(&self) -> bool {
        self.show_vars
    }

    pub fn get_show_types_var_ids(&self) -> bool {
        self.show_types_var_ids
    }

    pub fn indent_width(&self) -> usize {
        self.indent_width
    }

    // Builder methods
    pub fn with_colors(mut self, colors: Colors) -> Self {
        self.colors = Some(colors);
        self
    }

    pub fn with_no_colors(mut self) -> Self {
        self.colors = None;
        self
    }

    pub fn with_show_types(mut self, show_types: bool) -> Self {
        self.show_types = show_types;
        self
    }

    pub fn with_show_vars(mut self, show_vars: bool) -> Self {
        self.show_vars = show_vars;
        self
    }

    pub fn with_show_types_var_ids(mut self, show_types_var_ids: bool) -> Self {
        self.show_types_var_ids = show_types_var_ids;
        self
    }

    pub fn with_indent_width(mut self, indent_width: usize) -> Self {
        self.indent_width = indent_width;
        self
    }
}

// Wrapper type to handle conditional coloring efficiently
#[derive(Clone, Copy)]
pub struct FormattedText<'a, T: fmt::Display> {
    text: T,
    pub color: Option<colored::Color>,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, T: fmt::Display> fmt::Display for FormattedText<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(color) = self.color {
            write!(f, "{}", self.text.to_string().color(color))
        } else {
            write!(f, "{}", self.text)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormattingContext<'a> {
    pub config: &'a PrettyPrintConfig,
    pub indent_level: usize,
    pub parent_precedence: Option<u8>, // For expressions
}

impl<'a> FormattingContext<'a> {
    pub fn new(config: &'a PrettyPrintConfig) -> Self {
        Self {
            config,
            indent_level: 0,
            parent_precedence: None,
        }
    }

    pub fn colors(&self) -> Option<&Colors> {
        self.config.colors.as_ref()
    }

    // Check this before applying colors
    pub fn colors_enabled(&self) -> bool {
        // Added method
        self.config.apply_colors()
    }

    // Helper method for conditional formatting
    // Takes text convertible to string and a semantic color type
    pub fn format<T: fmt::Display>(
        &self,
        text: T,
        semantic: SemanticColor,
    ) -> FormattedText<'a, T> {
        let color = self.config.colors.map(|c| c.get_color(semantic));
        FormattedText {
            text,
            color,
            _marker: std::marker::PhantomData,
        }
    }

    // Create a new context with increased indentation
    pub fn indented(&self) -> Self {
        let mut ctx = *self;
        ctx.indent_level += 1;
        ctx
    }

    // Create a context for a nested expression
    pub fn with_precedence(&self, precedence: u8) -> Self {
        let mut ctx = *self;
        ctx.parent_precedence = Some(precedence);
        ctx
    }

    // Get the current indentation string
    pub fn indent_str(&self) -> String {
        " ".repeat(self.indent_level * self.config.indent_width())
    }

    // Convenience methods to access config
    pub fn show_types(&self) -> bool {
        self.config.show_types()
    }

    pub fn show_vars(&self) -> bool {
        self.config.show_vars()
    }

    // Convenience formatters for common punctuation
    pub fn fmt_open_paren(&self) -> FormattedText<'a, char> {
        self.format('(', SemanticColor::LowPrio)
    }
    pub fn fmt_close_paren(&self) -> FormattedText<'a, char> {
        self.format(')', SemanticColor::LowPrio)
    }
    pub fn fmt_open_brace(&self) -> FormattedText<'a, char> {
        self.format('{', SemanticColor::LowPrio)
    }
    pub fn fmt_close_brace(&self) -> FormattedText<'a, char> {
        self.format('}', SemanticColor::LowPrio)
    }
    pub fn fmt_open_bracket(&self) -> FormattedText<'a, char> {
        self.format('[', SemanticColor::LowPrio)
    }
    pub fn fmt_close_bracket(&self) -> FormattedText<'a, char> {
        self.format(']', SemanticColor::LowPrio)
    }
    pub fn fmt_colon(&self) -> FormattedText<'a, char> {
        self.format(':', SemanticColor::LowPrio)
    }
    pub fn fmt_comma(&self) -> FormattedText<'a, &'static str> {
        self.format(", ", SemanticColor::LowPrio)
    }
    pub fn fmt_eq(&self) -> FormattedText<'a, char> {
        self.format('=', SemanticColor::Operator)
    }
    pub fn fmt_semicolon(&self) -> FormattedText<'a, char> {
        self.format(';', SemanticColor::LowPrio)
    }
    pub fn fmt_ampersand(&self) -> FormattedText<'a, char> {
        self.format('&', SemanticColor::Operator)
    }
    pub fn fmt_star(&self) -> FormattedText<'a, char> {
        self.format('*', SemanticColor::Operator)
    }
    pub fn fmt_dot(&self) -> FormattedText<'a, char> {
        self.format('.', SemanticColor::LowPrio)
    }
}

pub trait ContextualPrettyPrint {
    // Pretty print with context including indentation
    fn pretty_print_with_context(&self, ctx: &FormattingContext) -> String;

    // Convenience method with default context
    fn pretty_print_with_config(&self, config: &PrettyPrintConfig) -> String {
        self.pretty_print_with_context(&FormattingContext::new(config))
    }

    fn pretty_print(&self) -> String {
        self.pretty_print_with_config(&PrettyPrintConfig::default())
    }

    fn nocolor(&self) -> String {
        // Added method
        let config = PrettyPrintConfig::default().with_no_colors();
        self.pretty_print_with_config(&config)
    }
}

#[macro_export]
macro_rules! derive_display {
    ($t:ident { $($param:ty),* }) => {
        impl <$($param),*> std::fmt::Display for $t<$($param),*> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.pretty_print())
            }
        }
    };
    ($t:ty) => {
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.pretty_print())
            }
        }
    };
}
