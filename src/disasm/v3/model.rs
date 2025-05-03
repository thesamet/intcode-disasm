use std::collections::HashMap;
use std::marker::PhantomData;

use crate::disasm::v3::control_flow::{ControlFlowGraphResult, Function};
use crate::disasm::v3::data_flow::DataFlowResult;
use crate::disasm::v3::function_call::FunctionCallAnalysisResult;
use crate::disasm::v3::id_types::{BlockId, FunctionId};
use crate::disasm::v3::image_scanner::ImageScannerResult;
use crate::disasm::v3::ssa::SsaResult;

// --- State Types ---
pub trait ModelState {}

pub struct InitialState {}
pub struct ImageScannerComplete {}
pub struct ControlFlowGraphComplete {}
pub struct DataFlowComplete {}
pub struct SsaComplete {}
pub struct FunctionCallComplete {}

impl ModelState for InitialState {}
impl ModelState for ImageScannerComplete {}
impl ModelState for ControlFlowGraphComplete {}
impl ModelState for DataFlowComplete {}
impl ModelState for SsaComplete {}
impl ModelState for FunctionCallComplete {}

// --- Capability Traits ---
pub trait HasImageScannerResult {}
pub trait HasControlFlowGraphResult {}
pub trait HasDataFlowResult {}
pub trait HasSsaResult {}
pub trait HasFunctionCallAnalysisResult {}

// Implement capability traits for appropriate states
impl HasImageScannerResult for ImageScannerComplete {}
impl HasImageScannerResult for ControlFlowGraphComplete {}
impl HasImageScannerResult for DataFlowComplete {}
impl HasImageScannerResult for SsaComplete {}
impl HasImageScannerResult for FunctionCallComplete {}

impl HasControlFlowGraphResult for ControlFlowGraphComplete {}
impl HasControlFlowGraphResult for DataFlowComplete {}
impl HasControlFlowGraphResult for SsaComplete {}
impl HasControlFlowGraphResult for FunctionCallComplete {}

impl HasDataFlowResult for DataFlowComplete {}
impl HasDataFlowResult for SsaComplete {}
impl HasDataFlowResult for FunctionCallComplete {}

impl HasSsaResult for SsaComplete {}
impl HasSsaResult for FunctionCallComplete {}
impl HasFunctionCallAnalysisResult for FunctionCallComplete {}

// Base Model struct that holds the state and data
pub struct Model<S: ModelState> {
    // Analysis results
    pub image_scanner_result: Option<ImageScannerResult>,
    pub control_flow_graph_result: Option<ControlFlowGraphResult>,
    pub data_flow_result: Option<DataFlowResult>,
    pub ssa_result: Option<SsaResult>,
    pub function_call_analysis_result: Option<FunctionCallAnalysisResult>,
    
    // Type state marker
    pub marker: PhantomData<S>,
}

impl Model<InitialState> {
    pub fn new() -> Self {
        Model {
            image_scanner_result: None,
            control_flow_graph_result: None,
            data_flow_result: None,
            ssa_result: None,
            function_call_analysis_result: None,
            marker: PhantomData,
        }
    }
    
    pub fn with_image(self, image: Vec<i128>) -> Self {
        // In the future, we might want to store the image here
        self
    }
}

// Accessor methods for each state
impl<S: ModelState> Model<S> 
where S: HasImageScannerResult 
{
    pub fn image_scanner_result(&self) -> &ImageScannerResult {
        self.image_scanner_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S> 
where S: HasControlFlowGraphResult 
{
    pub fn control_flow_graph_result(&self) -> &ControlFlowGraphResult {
        self.control_flow_graph_result.as_ref().unwrap()
    }
    
    pub fn function(&self, function_id: &FunctionId) -> &Function {
        self.control_flow_graph_result()
            .functions
            .get(function_id)
            .unwrap_or_else(|| panic!("Function {function_id} not found"))
    }
}

impl<S: ModelState> Model<S> 
where S: HasDataFlowResult 
{
    pub fn data_flow_result(&self) -> &DataFlowResult {
        self.data_flow_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S> 
where S: HasSsaResult 
{
    pub fn ssa_result(&self) -> &SsaResult {
        self.ssa_result.as_ref().unwrap()
    }
}

impl<S: ModelState> Model<S> 
where S: HasFunctionCallAnalysisResult 
{
    pub fn function_call_analysis_result(&self) -> &FunctionCallAnalysisResult {
        self.function_call_analysis_result.as_ref().unwrap()
    }
}
