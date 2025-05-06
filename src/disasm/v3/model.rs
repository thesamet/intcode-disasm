use std::marker::PhantomData;

use crate::disasm::v2::listeners::variable_analyzer::VariableMergerResult;
use crate::disasm::v2::type_inference::result::TypeInferenceResult;
use crate::disasm::v3::control_flow::ControlFlowGraphResult;
use crate::disasm::v3::data_flow::DataFlowResult;
use crate::disasm::v3::function_call::FunctionCallAnalysisResult;
use crate::disasm::v3::id_types::BlockId;
use crate::disasm::v3::image_scanner::ImageScannerResult;
use crate::disasm::v3::ssa::SsaResult;

#[derive(Clone, Debug)]
pub struct InputBinary {
    pub image: Vec<i128>,
}

impl InputBinary {
    pub fn new(image: Vec<i128>) -> Self {
        InputBinary { image }
    }
}

#[states]
enum ModelState {
    InitialState(InputBinary),
    ImageScannerComplete(ImageScannerResult),
    ControlFlowGraphComplete(ControlFlowGraphResult),
    DataFlowComplete(DataFlowResult),
    SsaComplete(SsaResult),
    FunctionCallAnalysisComplete(FunctionCallAnalysisResult),
}

#[model]
#[derive(Clone, Debug)]
pub struct Model<S: ModelState> {}

impl Model<InitialState> {
    pub fn from_binary(binary: Vec<i128>) -> Model<InitialState> {
        Model::new(InputBinary::new(binary))
    }
}

impl<S: ModelState> Model<S> {
    pub fn image(&self) -> &Vec<i128>
    where
        S: HasInputBinary,
    {
        &self.input_binary().image
    }

    pub fn type_inference_result(&self) -> Option<&TypeInferenceResult> {
        None
    }

    pub fn variable_merger_result(&self) -> Option<&VariableMergerResult> {
        None
    }
}

macro_rules! add_block_view_when {
    ($result_type:ident, $result_var:ident) => {
        paste::paste! {
            add_block_view_when!($result_type, $result_var, [<$result_type Block>]);
        }
    };
    ($result_type:ident, $result_var:ident, $block_type:ty) => {
        paste::paste! {
            impl<'a, S: crate::disasm::v3::model::ModelState> crate::disasm::v3::control_flow::BlockView<'a, S>
            where
                S: crate::disasm::v3::model::[<Has $result_type Result>],
            {
                pub fn $result_var(&self) -> &'a $block_type {
                    self.model
                        .[<$result_type:snake:lower _result>]()
                        .blocks
                        .get(&self.block_id())
                        .as_ref()
                        .unwrap_or_else(|| {
                            panic!(
                                "Could not find {} information for block {}",
                                stringify!($result_var),
                                self.block_id()
                            )
                        })
                }
            }
        }
    };
}
pub(crate) use add_block_view_when;
use model_macros::{model, states};

use super::control_flow::BlockView;

impl<S: ModelState> Model<S>
where
    S: HasControlFlowGraphResult,
{
    pub fn find_block<'a>(&'a self, block_id: &BlockId) -> Option<BlockView<'a, S>> {
        self.all_blocks()
            .find(|(id, _)| id == block_id)
            .map(|(_, b)| b)
    }

    pub fn all_blocks<'a>(&'a self) -> impl Iterator<Item = (BlockId, BlockView<'a, S>)> {
        self.functions()
            .flat_map(move |(_, function)| function.blocks())
    }
}
