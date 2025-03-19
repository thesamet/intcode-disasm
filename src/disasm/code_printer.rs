use std::fmt::{Arguments, Write};

#[macro_export]
macro_rules! line {
    ($dst:expr, $($arg:tt)*) => {
        $dst.line_fmt(std::format_args!($($arg)*))
    };
}

pub trait CodeWriter {
    fn line(&mut self, s: &str);

    fn line_fmt(&mut self, args: Arguments<'_>) {
        let mut s = String::new();
        s.write_fmt(args).unwrap();
        self.line(&s)
    }

    fn indented(&mut self) -> IndentedWriter
    where
        Self: Sized,
    {
        IndentedWriter { parent: self }
    }

    fn single_line_mode(&mut self) -> SingleLineWriter
    where
        Self: Sized,
    {
        SingleLineWriter {
            parent: self,
            c: vec![],
        }
    }
}

pub struct CodePrinter {
    out: String,
}

impl CodePrinter {
    pub fn new() -> Self {
        CodePrinter { out: String::new() }
    }

    pub fn result(self) -> String {
        self.out
    }
}

impl CodeWriter for CodePrinter {
    fn line(&mut self, s: &str) {
        self.out.push_str(s);
        self.out.push('\n');
    }
}

pub struct IndentedWriter<'a> {
    parent: &'a mut dyn CodeWriter,
}

impl<'a> CodeWriter for IndentedWriter<'a> {
    fn line(&mut self, s: &str) {
        self.parent.line(&format!("  {}", s));
    }
}

pub struct SingleLineWriter<'a> {
    parent: &'a mut dyn CodeWriter,
    c: Vec<String>,
}

impl<'a> Drop for SingleLineWriter<'a> {
    fn drop(&mut self) {
        self.parent.line(&self.c.join(" "));
    }
}

impl<'a> CodeWriter for SingleLineWriter<'a> {
    fn line(&mut self, s: &str) {
        self.c.push(s.to_string());
    }
}
