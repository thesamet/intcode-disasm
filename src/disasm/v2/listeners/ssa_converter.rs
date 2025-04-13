use log::info;

use crate::disasm::v2::{
    dispatching::EventCollector,
    events::{DataFlowAnalysisPhaseComplete, Event, ModelEventListener, SsaConversionComplete},
    model::ProgramModel,
    ssa_form::SsaResult,
};

/// Listener that converts the program to SSA form
pub struct SsaConverter {}

impl SsaConverter {
    /// Create a new SSA converter
    pub fn new() -> Self {
        Self {}
    }
}

impl ModelEventListener for SsaConverter {
    fn on_data_flow_analysis_phase_complete(
        &mut self,
        model: &mut ProgramModel,
        _event: DataFlowAnalysisPhaseComplete,
        collector: &mut EventCollector<Event>,
    ) {
        let ssa_result = SsaResult::from_program_model(model);
        model.set_ssa_result(ssa_result);
        info!("SSA conversion complete");
        collector.publish(SsaConversionComplete {});
    }
}
