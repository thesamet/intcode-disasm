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
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
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
                    .map_err(|e| format!("Failed to parse $id_type: {}", e))
            }
        }

        impl rmcp::schemars::JsonSchema for $id_type {
            fn schema_name() -> String {
                // This should return the name of the type for the schema definition
                stringify!($id_type).to_string()
            }

            fn json_schema(
                _gen: &mut rmcp::schemars::SchemaGenerator,
            ) -> rmcp::schemars::schema::Schema {
                // Since FunctionId is a newtype around usize, its schema is the same as usize's schema
                // We delegate the schema generation to the usize implementation
                usize::json_schema(_gen)
            }
        }

        /*
        impl serde::Serialize for $id_type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_newtype_struct(stringify!($id_type), &self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $id_type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct PrimitiveVisitor;
                impl<'a> serde::de::Visitor<'a> for PrimitiveVisitor {
                    type Value = $id_type;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str(stringify!($id_type))
                    }

                    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        Ok($id_type::new(v as usize))
                    }
                }

                deserializer.deserialize_newtype_struct(stringify!($id_type), PrimitiveVisitor {})
            }
        }
        */

        impl $id_type {}
    };
}
pub(crate) use define_id_type;
