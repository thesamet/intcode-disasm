pub mod analysis;
pub mod control_flow;
pub mod dispatching;
mod events;
pub mod id_types;
pub mod instructions;
pub mod listeners;
pub mod model;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

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
