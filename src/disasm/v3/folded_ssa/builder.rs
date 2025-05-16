use std::collections::HashMap;

use itertools::Itertools;

use super::result::{FoldedSsaBlock, FoldedSsaResult};
use crate::disasm::v3::common::fixed_point_mut;
use crate::disasm::v3::control_flow::FunctionView;
use crate::disasm::v3::lir::{Expression, Instruction}; // Assuming InstructionNode is needed for transformation logic
use crate::disasm::v3::model::{FoldedSsaComplete, FunctionCallAnalysisComplete, Model};
use crate::disasm::v3::ssa::types::SsaMemoryReference;
use crate::disasm::v3::ssa::VersionedMemoryReference;
use crate::disasm::v3::BlockId;
// For InstructionNode<SsaMemoryReference>
use crate::disasm::Error;

/// Builds a "folded" SSA representation where expressions are made richer
/// by eliminating temporary variables and folding their definitions into use sites.
pub struct FoldedSsaBuilder {
    model: Model<FunctionCallAnalysisComplete>,
}

impl FoldedSsaBuilder {
    pub fn new(model: Model<FunctionCallAnalysisComplete>) -> Self {
        Self { model }
    }

    /// Runs the folded SSA building process.
    ///
    /// # Arguments
    /// * `model` - The model in the `SsaComplete` state.
    ///
    /// # Returns
    /// * `Ok(Model<FoldedSsaComplete>)` - If the building process is successful.
    /// * `Err(Error)` - If an error occurs.
    pub fn run(
        model: Model<FunctionCallAnalysisComplete>,
    ) -> Result<Model<FoldedSsaComplete>, Error> {
        let builder = Self::new(model);
        builder.analyze()
    }

    fn analyze(self) -> Result<Model<FoldedSsaComplete>, Error> {
        let mut output_ssa_result = FoldedSsaResult {
            blocks: Default::default(),
        };

        for (_, function_view) in self.model.functions().sorted_by_key(|f| f.0) {
            let res = self.transform_function(function_view);
            output_ssa_result.blocks.extend(res);
        }

        // Transition the model to the new state with the folded SSA result.
        Ok(self.model.with_folded_ssa_result(output_ssa_result))
    }

    fn transform_function(
        &self,
        function_view: FunctionView<FunctionCallAnalysisComplete>,
    ) -> HashMap<BlockId, FoldedSsaBlock> {
        let mut current = HashMap::new();
        for (_, block) in function_view.blocks() {
            current.insert(
                block.block_id(),
                FoldedSsaBlock {
                    instructions: block.ssa().instructions.clone(),
                },
            );
        }

        fixed_point_mut(current, |current| {
            let mut defs = HashMap::new();
            let mut reads: HashMap<_, Vec<_>> = HashMap::new();

            let mut instructions_changed = false;
            for (_, block) in current.iter_mut() {
                for instruction in block.instructions.iter_mut() {
                    *instruction = instruction.map_expr(|e| match e.simplify() {
                        Some(e) => {
                            instructions_changed = true;
                            e
                        }
                        None => e.clone(),
                    });
                }
            }
            if instructions_changed {
                return true;
            }
            for (block_id, block) in current.iter() {
                for instruction in block.instructions.iter() {
                    if let Instruction::Assign {
                        target: SsaMemoryReference::Versioned(mr),
                        src,
                        ..
                    } = &instruction.kind
                    {
                        defs.insert(*mr, (*block_id, instruction.id, src.clone()));
                    };
                    for r in instruction
                        .kind
                        .collect_read_addresses()
                        .iter()
                        .filter_map(|r| r.as_versioned())
                    {
                        reads
                            .entry(*r)
                            .or_default()
                            .push((*block_id, instruction.id));
                    }
                }
            }
            for (var, (var_def_block_id, var_def_instruction_id, expr)) in &defs {
                let Some(&(use_block, use_instruction)) =
                    reads.get(var).and_then(|v| v.iter().exactly_one().ok())
                else {
                    continue;
                };
                println!("Removing {var_def_instruction_id} from {var_def_block_id} to be replaced with {expr}");

                current
                    .get_mut(var_def_block_id)
                    .unwrap()
                    .instructions
                    .retain(|i| i.id != *var_def_instruction_id);

                println!("Looking for use block {use_block:?} and instruction {use_instruction:?} to update {var}");
                let use_instruction = current
                    .get_mut(&use_block)
                    .unwrap()
                    .instructions
                    .iter_mut()
                    .find(|i| i.id == use_instruction)
                    .unwrap();

                fn update_read_args(
                    var: &VersionedMemoryReference,
                    expr: &Expression<SsaMemoryReference>,
                    scrutinee: &SsaMemoryReference,
                ) -> Expression<SsaMemoryReference> {
                    match scrutinee {
                        SsaMemoryReference::Versioned(x) => {
                            if x == var {
                                expr.clone()
                            } else {
                                Expression::Addressable(scrutinee.clone())
                            }
                        }
                        SsaMemoryReference::Deref(e) => {
                            e.flat_map(&mut |s| update_read_args(var, expr, s))
                        }
                    }
                }

                fn update_write_arg(
                    var: &VersionedMemoryReference,
                    expr: &Expression<SsaMemoryReference>,
                    scrutinee: &SsaMemoryReference,
                ) -> SsaMemoryReference {
                    match scrutinee {
                        SsaMemoryReference::Versioned(x) => {
                            assert_ne!(x, var);
                            scrutinee.clone()
                        }
                        SsaMemoryReference::Deref(e) => SsaMemoryReference::Deref(Box::new(
                            e.flat_map(&mut |s| update_read_args(var, expr, s)),
                        )),
                    }
                }

                /*
                *use_instruction = use_instruction.flat_map_rw(
                    &mut (),
                    |_, x| {
                        if x.as_versioned() == Some(var) {
                            expr.clone()
                        } else {
                            Expression::Addressable(x.clone())
                        }
                    },
                    |_, x| x.clone(),
                );
                */

                *use_instruction = use_instruction.flat_map_rw(
                    &mut (),
                    |_, x| update_read_args(var, expr, x),
                    |_, x| update_write_arg(var, expr, x),
                );
                return true;
            }
            false
        })
    }
}
