use super::colors::Colors;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub struct PrettyPrintConfig {
    pub colors: Colors,
    pub show_types: bool,
    pub show_vars: bool,
    pub indent_width: usize,
}

impl Default for PrettyPrintConfig {
    fn default() -> Self {
        Self {
            colors: Colors::default(),
            show_types: true,
            show_vars: true,
            indent_width: 4,
        }
    }
}

impl PrettyPrintConfig {
    // Accessor methods
    pub fn colors(&self) -> &Colors {
        &self.colors
    }
    
    pub fn show_types(&self) -> bool {
        self.show_types
    }
    
    pub fn show_vars(&self) -> bool {
        self.show_vars
    }
    
    pub fn indent_width(&self) -> usize {
        self.indent_width
    }
    
    // Builder methods
    pub fn with_colors(mut self, colors: Colors) -> Self {
        self.colors = colors;
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
    
    pub fn with_indent_width(mut self, indent_width: usize) -> Self {
        self.indent_width = indent_width;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormattingContext<'a> {
    pub config: &'a PrettyPrintConfig,

    pub indent_level: usize,
    pub indent_width: usize,
    pub parent_precedence: Option<u8>, // For expressions
}

impl<'a> FormattingContext<'a> {
    pub fn new(config: &'a PrettyPrintConfig) -> Self {
        Self {
            config,
            indent_level: 0,
            indent_width: 4,
            parent_precedence: None,
        }
    }

    pub fn colors(&self) -> &Colors {
        &self.config.colors
    }

    // Create a new context with increased indentation
    pub fn indented(&self) -> Self {
        let mut ctx = self.clone();
        ctx.indent_level += 1;
        ctx
    }

    // Create a context for a nested expression
    pub fn with_precedence(&self, precedence: u8) -> Self {
        let mut ctx = self.clone();
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
}
