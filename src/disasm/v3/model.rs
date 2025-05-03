use std::marker::PhantomData;

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

// Base Model struct that holds the state
pub struct Model<S: ModelState> {
    marker: PhantomData<S>,
}

impl<S: ModelState> Model<S> {
    pub fn new() -> Model<InitialState> {
        Model {
            marker: PhantomData,
        }
    }
}
