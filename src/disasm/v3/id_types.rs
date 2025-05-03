use std::fmt::{Debug, Display};
use std::hash::Hash;

// Re-export the macro from v2
pub use crate::disasm::v2::id_types::define_id_type;

// Define common ID types
define_id_type!(FunctionId);
define_id_type!(BlockId);
define_id_type!(InstructionId);
