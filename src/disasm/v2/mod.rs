pub mod analysis;
pub mod control_flow;
pub mod data_flow;
pub mod dispatching;
pub mod events;
pub mod id_types;
#[cfg(test)]
mod integration_tests;
pub mod listeners;
pub mod model;
pub mod native;
pub mod pretty_print;
pub mod ssa_form;
pub mod type_inference;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[allow(unused)]
impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        assert!(start <= end);
        Span { start, end }
    }

    pub fn contains(&self, s: &Span) -> bool {
        self.start <= s.start && s.end <= self.end
    }

    pub fn contains_address(&self, p: usize) -> bool {
        self.start <= p && p < self.end
    }

    pub fn with_start(&self, start: usize) -> Self {
        assert!(start <= self.end);
        Self::new(start, self.end)
    }
}
