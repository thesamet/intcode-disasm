use std::collections::HashMap;

use crate::disasm::symbol_renaming::StructId;
use crate::disasm::v3::function_call::result::add_function_view_when;
use crate::disasm::v3::lir::{BinaryOperator, Expression, ExpressionPath, MemoryReferenceInfo};
use crate::disasm::v3::model::{FoldedSsaComplete, Model};

use crate::disasm::v3::model::StructureAnalysisComplete;
use crate::disasm::v3::ssa::{SsaMemoryReference, VersionedMemoryReference};
use crate::disasm::v3::type_inference::Type;
use crate::disasm::v3::FunctionId;
use crate::disasm::{Error, UserDefs};

#[derive(Debug, Clone)]
pub struct StructuralAnalysisResult {
    functions: HashMap<FunctionId, FunctionStructInfo>,

    // Struct sizes for structs used as global variables. This is to overcome
    // the fact that memory is versioned, but we assume all versions of global
    // memory refer to the same struct.
    global_structs: HashMap<usize, StructId>,

    structs: HashMap<StructId, StructInfo>,
}

add_function_view_when!(StructuralAnalysis, structural_analysis, FunctionStructInfo);

#[derive(Debug, Clone)]
pub struct StructInfo {
    size: usize,
}

impl StructInfo {
    fn new(size: usize) -> StructInfo {
        StructInfo { size }
    }
}

#[derive(Debug, Clone)]
pub struct FunctionStructInfo {
    // Struct sizes for structs used as relative memory.
    register_structs: HashMap<VersionedMemoryReference, StructId>,
}

#[derive(Default)]
struct FieldAccessCollector {
    // Expresions of the form *(expr + const)
    derefs: Vec<(ExpressionPath, Expression<SsaMemoryReference>, i128)>,
    // Expresions of the form (vmr + const). After we know expr is some vmr
    // that is a pointer to struct, an expression of the form (vmr+const) may be
    // a reference to a pointer field
    potential_pointer_adds: HashMap<VersionedMemoryReference, Vec<usize>>,
}

impl FieldAccessCollector {
    fn new() -> FieldAccessCollector {
        FieldAccessCollector {
            derefs: vec![],
            potential_pointer_adds: HashMap::new(),
        }
    }
}

impl crate::disasm::v3::lir::expression::ExpressionPathVisitor<SsaMemoryReference>
    for FieldAccessCollector
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
        self.default_return();
        Ok(())
    }

    fn visit_binary(
        &mut self,
        _path: &ExpressionPath,
        expr: &Expression<SsaMemoryReference>,
        _op: BinaryOperator,
        _lhs: Self::Return,
        _rhs: Self::Return,
    ) -> Result<Self::Return, Self::Error> {
        match expr.as_binary() {
            Some((
                BinaryOperator::Add,
                Expression::Addressable(SsaMemoryReference::Versioned(vmr)),
                Expression::Constant(offset),
            )) if *offset < 10 => {
                self.potential_pointer_adds
                    .entry(*vmr)
                    .or_default()
                    .push(*offset as usize);
            }
            _ => {}
        }
        self.default_return();
        Ok(())
    }
}

pub(crate) fn analyze_structure(
    model: Model<FoldedSsaComplete>,
    user_defs: &UserDefs,
) -> Result<Model<StructureAnalysisComplete>, Error> {
    let mut result = StructuralAnalysisResult {
        functions: HashMap::new(),
        global_structs: HashMap::new(),
        structs: HashMap::new(),
    };
    let mut global_adds: HashMap<usize, Vec<usize>> = HashMap::new();
    for (function_id, f) in model.functions() {
        result.functions.insert(
            f.function_id(),
            FunctionStructInfo {
                register_structs: HashMap::new(),
            },
        );
        let mut hm: HashMap<VersionedMemoryReference, Vec<usize>> = HashMap::new();
        if let Some(def) = user_defs.get_functions().get(&f.function_id()) {
            let entry_vars = &model
                .function(&function_id)
                .callee_info()
                .parameter_entry_vars;
            for (index, (_, typ)) in def.args().iter().enumerate() {
                let Some(struct_id) = typ.as_ref().and_then(Type::as_struct) else {
                    continue;
                };
                let vmr = entry_vars.get(&((index + 1) as i128)).unwrap();
                result
                    .functions
                    .get_mut(&function_id)
                    .unwrap()
                    .register_structs
                    .insert(*vmr, struct_id);
            }
        };
        for (_, b) in f.blocks() {
            for i in &b.folded_ssa().instructions {
                for (tvp, e) in i.collect_all_expressions() {
                    let mut v = FieldAccessCollector::new();
                    e.visit(&mut v, &ExpressionPath::root())?;
                    for (_, base, offset) in v.derefs {
                        let Expression::Addressable(SsaMemoryReference::Versioned(vmr)) = base
                        else {
                            panic!("Expected VMR as base for struct field");
                        };
                        hm.entry(vmr).or_default().push(offset as usize);
                        if let Some(offsets) = v.potential_pointer_adds.get(&vmr) {
                            if vmr.is_stack_relative() {
                                hm.get_mut(&vmr).unwrap().extend(offsets);
                            }
                        }
                    }
                    for (vmr, offsets) in v.potential_pointer_adds {
                        if let Some(addr) = vmr.as_global() {
                            global_adds.entry(addr).or_default().extend(offsets);
                        }
                    }
                }
            }
        }
        for (vmr, offsets) in hm {
            let size = *offsets.iter().max().unwrap();
            let struct_info = StructInfo::new(size);
            if vmr.is_stack_relative() {
                if !result.functions[&f.function_id()]
                    .register_structs
                    .contains_key(&vmr)
                {
                    let struct_id = StructId::fresh();
                    result.structs.insert(struct_id, struct_info);
                    result
                        .functions
                        .get_mut(&f.function_id())
                        .unwrap()
                        .register_structs
                        .insert(vmr, struct_id);
                }
            } else if let Some(addr) = vmr.as_global() {
                let struct_id = result
                    .global_structs
                    .entry(addr)
                    .or_insert_with(StructId::fresh);
                let si = result.structs.entry(*struct_id).or_insert(struct_info);
                si.size = si.size.max(size);
                si.size = si.size.max(
                    global_adds
                        .get(&addr)
                        .map(|f| *f.iter().max().unwrap())
                        .unwrap_or(0),
                );
            } else {
                unreachable!("Unexpected VMR type.")
            }
        }
    }
    for (f, fi) in &result.functions {
        if fi.register_structs.is_empty() {
            continue;
        };
    }
    Ok(model.with_structural_analysis_result(result))
}
