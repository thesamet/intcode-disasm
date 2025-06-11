use crate::disasm::v3::common::formatting::ContextualPrettyPrint;
use crate::disasm::v3::lir::{BinaryOperator, Expression, ExpressionPath, TypeVarPath};
use crate::disasm::v3::model::{FoldedSsaComplete, Model};

use crate::disasm::v3::model::StructureAnalysisComplete;
use crate::disasm::v3::ssa::SsaMemoryReference;
use crate::disasm::Error;

#[derive(Debug, Clone)]
pub struct StructuralAnalysisResult {
    // TODO
}

#[derive(Default)]
struct DerefCollector {
    derefs: Vec<(ExpressionPath, Expression<SsaMemoryReference>, i128)>,
}

impl DerefCollector {
    fn new() -> DerefCollector {
        DerefCollector { derefs: vec![] }
    }
}

impl crate::disasm::v3::lir::expression::ExpressionPathVisitor<SsaMemoryReference>
    for DerefCollector
{
    type Return = ();
    type Error = Error;

    fn default_return(&mut self) -> Self::Return {}

    fn visit_addressable(
        &mut self,
        path: &ExpressionPath,
        addressable: &SsaMemoryReference,
        _: Option<Self::Return>,
    ) -> Result<Self::Return, Self::Error> {
        match addressable.as_deref().and_then(|e| e.as_binary()) {
            Some((BinaryOperator::Add, base, Expression::Constant(offset))) if *offset < 10 => {
                self.derefs.push((path.clone(), base.clone(), *offset));
            }
            _ => {}
        }
        Ok(self.default_return())
    }
}

pub(crate) fn analyze_structure(
    model: Model<FoldedSsaComplete>,
) -> Result<Model<StructureAnalysisComplete>, Error> {
    for (_, f) in model.functions() {
        for (_, b) in f.blocks() {
            for i in &b.folded_ssa().instructions {
                for (tvp, e) in i.collect_all_expressions() {
                    let mut v = DerefCollector::new();
                    e.visit(&mut v, &ExpressionPath::root())?;
                    for k in v.derefs {
                        println!(
                            "{} {} {} {}",
                            f.function_id(),
                            i.id,
                            k.1.pretty_print(),
                            k.2
                        )
                    }
                }
            }
        }
    }
    let result = StructuralAnalysisResult {};
    Ok(model.with_structural_analysis_result(result))
}
