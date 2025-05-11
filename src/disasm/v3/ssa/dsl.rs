use crate::disasm::v3::{
    lir::{BinaryOperator, Expression},
    FunctionId,
};

use super::{types::VersionableMemoryKind, SsaMemoryReference, VersionedMemoryReference};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RelativeMemoryBuilder(i128);

impl From<RelativeMemoryBuilder> for VersionableMemoryKind {
    fn from(value: RelativeMemoryBuilder) -> Self {
        VersionableMemoryKind::RelativeMemory(value.0)
    }
}

impl<A> From<A> for Expression<A> {
    fn from(value: A) -> Self {
        Expression::Addressable(value)
    }
}

const R: RelativeMemoryBuilder = RelativeMemoryBuilder(0);

impl core::ops::Sub<i128> for RelativeMemoryBuilder {
    type Output = RelativeMemoryBuilder;

    fn sub(self, rhs: i128) -> Self::Output {
        RelativeMemoryBuilder(self.0 - rhs)
    }
}

impl core::ops::Add<i128> for RelativeMemoryBuilder {
    type Output = RelativeMemoryBuilder;

    fn add(self, rhs: i128) -> Self::Output {
        RelativeMemoryBuilder(self.0 + rhs)
    }
}

impl core::ops::BitXor<usize> for RelativeMemoryBuilder {
    type Output = SsaMemoryReference;

    fn bitxor(self, rhs: usize) -> Self::Output {
        SsaMemoryReference::Versioned(VersionedMemoryReference::new(
            VersionableMemoryKind::RelativeMemory(self.0),
            FunctionId::new(0),
            rhs,
        ))
    }
}

impl<B> core::ops::Add<B> for SsaMemoryReference
where
    B: Into<Expression<SsaMemoryReference>>,
{
    type Output = Expression<SsaMemoryReference>;

    fn add(self, rhs: B) -> Self::Output {
        Expression::Binary {
            lhs: Box::new(self.into()),
            rhs: Box::new(rhs.into()),
            op: BinaryOperator::Add,
        }
    }
}

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

#[cfg(test)]
mod tests {

    use model_macros::build_expr;

    use crate::lir_expr;

    use super::*;

    #[test]
    fn test() {
        assert_eq!(build_expr! { [R-3].5 }, rel_mem(-3, 5));
        assert_eq!(build_expr! { [R+2].7 }, rel_mem(2, 7));
        /*
        assert_eq!(
            versioned_memory! { [R + 5].7 },
            RelativeMemoryBuilder(5).version(7)
        );
        assert_eq!(
            versioned_memory! { [R].25 },
            RelativeMemoryBuilder(0).version(25)
        );
        assert_eq!(
            versioned_memory! { [1123].4 },
            GlobalMemory(1123).version(4)
        );
        assert_eq!(
            versioned_memory! { [1123].4 } + versioned_memory! { [R].5 },
            Expression {}
        );
        */
        //assert_eq!(ver! { *([R-4].9) }, Deref(RelativeMemory(-4).version(9)));
    }
}
