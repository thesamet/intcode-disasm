macro_rules! define_id_type {
    ($id_type:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $id_type(usize);

        impl $id_type {
            pub fn new(id: usize) -> Self {
                Self(id)
            }

            pub fn index(&self) -> usize {
                self.0
            }

            pub fn unassigned() -> Self {
                Self(usize::MAX)
            }
        }

        impl From<usize> for $id_type {
            fn from(id: usize) -> Self {
                Self(id)
            }
        }

        paste::paste! {
            mod [<counter_ $id_type:snake>] {
                use std::sync::atomic::{AtomicUsize, Ordering};

                #[allow(non_upper_case_globals)]
                static COUNTER: AtomicUsize = AtomicUsize::new(0);

                pub fn next() -> usize {
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
                let id = paste::paste! { [<counter_ $id_type:snake>]::next() };
                Self(id)
            }

            /// Reset the ID counter (useful for tests)
            pub fn reset_counter() {
                paste::paste! { [<counter_ $id_type:snake>]::reset() };
            }
        }
    };
}
pub(crate) use define_id_type;
