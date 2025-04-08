use log::{info, warn};

use crate::disasm::v2::{
    dispatching::{EventCollector, EventListener},
    events::{Event, SsaConversionComplete},
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

impl EventListener<Event, ProgramModel> for SsaConverter {
    fn on_event(
        &mut self,
        model: &mut ProgramModel,
        event: Event,
        collector: &mut EventCollector<Event>,
    ) {
        match event {
            // Wait for data flow analysis to complete for all functions
            Event::DataFlowAnalysisComplete(_) => {
                let ssa_result = SsaResult::from_program_model(model);
                model.set_ssa_result(ssa_result);
                info!("SSA conversion complete");
                collector.publish(SsaConversionComplete { completed: true });
            }
            _ => {}
        }
    }
}
