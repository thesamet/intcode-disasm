pub mod analysis;
pub mod control_flow;
pub mod data_flow;
pub mod dispatching;
pub mod events;
pub mod id_types;
pub mod instructions;
pub mod listeners;
pub mod model;
pub mod native;
pub mod pretty_print;
pub mod ssa_form;
pub mod type_inference;
// #[cfg(test)]
// mod integration_tests;

pub use crate::disasm::v3::Span;
