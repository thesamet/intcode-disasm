use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::sync::atomic::AtomicUsize;

// Re-export the macro from v2
pub(crate) use crate::disasm::v2::id_types::define_id_type;

// Define common ID types
define_id_type!(FunctionId);
define_id_type!(BlockId);
define_id_type!(NativeInstructionId); // Added
define_id_type!(InstructionId); // LIR Instruction ID
define_id_type!(PointerId);

static INSTRUCTION_ID_COUNTER: AtomicUsize = AtomicUsize::new(0); // For LIR InstructionId

impl InstructionId {
    pub fn fresh() -> Self {
        let next = INSTRUCTION_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        InstructionId::new(next)
    }
}
