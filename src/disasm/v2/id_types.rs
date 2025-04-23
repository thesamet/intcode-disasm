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
                write!(f, "{}{}", prefix, self.0)
            }
        }

        impl $id_type {}
    };
}
pub(crate) use define_id_type;
