use log::{info, warn};

use crate::disasm::{
    v2::{
        dispatching::EventCollector,
        events::{DataFlowAnalysisPhaseComplete, Event, ModelEventListener, SsaConversionComplete},
        model::ProgramModel,
        ssa_form::SsaResult,
    },
    v3::{
        analysis::run_analysis_ssa, // We'll use this for now, knowing it does one extra step (SSA)
        control_flow::ControlFlowGraphBuilder,
        data_flow::DataFlowAnalyzer,
        image_scanner::ImageScanner,
        model::{DataFlowComplete, InitialState, Model},
    },
    Error,
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
    ) -> Result<(), Error> {
        info!("Running v3 analysis pipeline up to DataFlowComplete for v2 SSA conversion...");

        // 1. Get the image from the v2 model
        let image = model.get_image().clone();

        // 2. Run v3 analysis pipeline
        // Create initial v3 model
        let v3_model_initial = Model::<InitialState>::new();
        // Run analysis phases
        let v3_model_scanned = ImageScanner::run(image, v3_model_initial)?;
        let v3_model_cfg = ControlFlowGraphBuilder::run(v3_model_scanned)?;
        let v3_model_data_flow = DataFlowAnalyzer::run(v3_model_cfg)?;

        // 3. Call the (soon-to-be-modified) SSA conversion using the v3 model
        // Note: We are changing the function signature SsaResult::from_program_model expects
        let ssa_result = SsaResult::from_program_model(&v3_model_data_flow); // Pass v3 model

        // 4. Store the v2 SsaResult back into the v2 ProgramModel
        // model.set_ssa_result(ssa_result);

        info!("SSA conversion (using v3 data) complete");
        collector.publish(SsaConversionComplete {});
        Ok(())
    }
}
