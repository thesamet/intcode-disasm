macro_rules! define_id_type {
    ($id_type:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $id_type(u64);

        impl $id_type {
            pub fn new(id: u64) -> Self {
                Self(id)
            }

            pub fn index(&self) -> u64 {
                self.0
            }
        }

        paste::paste! {
            mod [<counter_ $id_type>] {
                use std::sync::atomic::{AtomicU64, Ordering};

                #[allow(non_upper_case_globals)]
                static COUNTER: AtomicU64 = AtomicU64::new(0);

                pub fn next() -> u64 {
                    COUNTER.fetch_add(1, Ordering::Relaxed)
                }

                pub fn reset() {
                    COUNTER.store(0, Ordering::Relaxed)
                }
            }
        }

        impl $id_type {
            /// Generate a fresh ID automatically
            pub fn fresh() -> Self {
                let id = paste::paste! { [<counter_ $id_type>]::next() };
                Self(id)
            }

            /// Reset the ID counter (useful for tests)
            pub fn reset_counter() {
                paste::paste! { [<counter_ $id_type>]::reset() };
            }
        }
    };
}
pub(crate) use define_id_type;
