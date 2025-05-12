#[cfg(test)]
mod tests {

    use crate::disasm::v3::ssa::types::VersionableMemoryKind;
    use crate::disasm::v3::FunctionId;
    use model_macros::build_expr;

    use crate::disasm::v3::ssa::{SsaMemoryReference, VersionedMemoryReference};
    use crate::lir_expr;

    fn rel_mem(offset: i128, ver: usize) -> SsaMemoryReference {
        SsaMemoryReference::Versioned(VersionedMemoryReference::new(
            VersionableMemoryKind::RelativeMemory(offset),
            FunctionId::new(0),
            ver,
        ))
    }

    fn global_mem(addr: usize, ver: usize) -> SsaMemoryReference {
        SsaMemoryReference::Versioned(VersionedMemoryReference::new(
            VersionableMemoryKind::Memory(addr),
            FunctionId::new(0),
            ver,
        ))
    }

    #[test]
    fn test() {
        assert_eq!(build_expr! { [R-3].5 }, rel_mem(-3, 5));
        assert_eq!(build_expr! { [R+2].7 }, rel_mem(2, 7));
        assert_eq!(build_expr! { [155].7 }, global_mem(155, 7));
        assert_eq!(build_expr! { [155].7 }, global_mem(155, 7));
        assert_eq!(build_expr! { [155].7 }.to_string(), "foo");
        assert_eq!(
            build_expr! { [R+2].7 + [R-3].5 },
            lir_expr! { add {rel_mem(2, 7).into()} {rel_mem(-3, 5).into()} }
        );
        assert_eq!(
            build_expr! { [R+2].3 - [R+3].0 },
            lir_expr! { sub {rel_mem(2, 3).into()} {rel_mem(3, 0).into()} }
        );
        assert_eq!(
            build_expr! { [R+2].7 + [R-3].5 },
            lir_expr! { add {rel_mem(2, 7).into()} {rel_mem(-3, 5).into()} }
        );
        assert_eq!(
            build_expr! { [R+1].3 * [R-2].2 },
            lir_expr! { mul {rel_mem(1, 3).into()} {rel_mem(-2, 2).into()} }
        );
        assert_eq!(
            build_expr! { [R+1].3 + [354].7 * [R-2].7 },
            lir_expr! { add {
                rel_mem(1, 3).into()}
            {mul {global_mem(354, 7).into()} {rel_mem(-2, 7).into()}}
            }
        );
        assert_eq!(
            build_expr! { ([R+1].3 + [R+1].5) * [R-2].7 },
            lir_expr! {
                mul {
                    add { rel_mem(1, 3).into() } { rel_mem(1, 5).into() }
                } {
                    rel_mem(-2, 7).into()
                }
            }
        );
    }
}
