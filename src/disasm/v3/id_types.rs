use std::fmt::Debug;
use std::hash::Hash;
use std::sync::atomic::AtomicUsize;

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

macro_rules! define_id_type {
    ($id_type:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $id_type(usize);

        #[allow(unused)]
        impl $id_type {
            pub fn new(id: usize) -> Self {
                Self(id)
            }

            pub fn index(&self) -> usize {
                self.0
            }
        }

        impl From<usize> for $id_type {
            fn from(id: usize) -> Self {
                Self(id)
            }
        }

        impl std::fmt::Display for $id_type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let name_str = stringify!($id_type);
                let prefix = name_str
                    .get(0..2)
                    .map(|s| s.to_lowercase())
                    .unwrap_or_else(|| "id".to_string()); // Fallback prefix
                                                          // write!(f, "{}{}", prefix, self.0)
                f.pad(&format!("{}{}", prefix, self.0))
            }
        }

        impl std::str::FromStr for $id_type {
            type Err = String;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                s.parse::<usize>()
                    .map($id_type::new)
                    .map_err(|e| format!("Failed to parse FunctionId: {}", e))
            }
        }

        impl $id_type {}
    };
}
pub(crate) use define_id_type;
