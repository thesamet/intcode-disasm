use crate::disasm::v3::{
    common::{
        function_call::{CalleeInfo, CallSiteInfo},
        instruction::InstructionNode,
        memory_reference::MemoryReference,
        span::Span,
    },
    control_flow::{block::Block, function::Function, NextKind, PredecessorKind},
    data_flow::{block::DataFlowBlock, DataFlowComplete},
    id_types::{BlockId, FunctionId},
    model::{FunctionCallComplete, Model, ModelState, SsaComplete},
    native::NativeInstruction,
    ssa::block::SsaBlock,
};
use std::fmt::Debug;

/// Trait for view types that provide read-only access to model components
pub trait ModelView<T> {
    /// Get a reference to the underlying data
    fn data(&self) -> &T;
}

// NOTE: Struct definitions and impl blocks were removed from here as they were duplicates.
// The correct definitions are expected to be in their respective modules (e.g., control_flow/block.rs, control_flow/function.rs).
// The Debug derive should be added to the original struct definitions.
