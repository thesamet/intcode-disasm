use crate::disasm::hlr::ast::HlrProgram;
use crate::disasm::v2::dispatching::EventCollector;
use crate::disasm::v2::events::{Event, StructureRecoveryComplete};
use crate::disasm::v2::listeners::hlr_optimizer::HlrOptimizer;
use crate::disasm::v2::model::ProgramModel;
use crate::disasm::Error;

/// Listener that optimizes the high-level representation (HLR) of the program
/// to make it more readable by transforming control flow structures and expressions.
///
/// This listener runs after the ControlFlowStructureRecoveryListener has completed
/// its work and further refines the HLR program.
#[derive(Debug, Default)]
pub struct HlrOptimizationListener {
    /// The optimized high-level representation of the program
    optimized_hlr_program: Option<HlrProgram>,
}

impl HlrOptimizationListener {
    pub fn new() -> Self {
        Self::default()
    }
}

impl crate::disasm::v2::events::ModelEventListener for HlrOptimizationListener {
    fn on_structure_recovery_complete(
        &mut self,
        model: &mut ProgramModel,
        _event: StructureRecoveryComplete,
        _sender: &mut EventCollector<Event>,
    ) -> Result<(), Error> {
        println!("Received StructureRecoveryComplete event. Starting HLR optimization...");

        // Get the HLR program from the model
        let hlr_program = model.get_hlr_program().ok_or_else(|| {
            Error::AnalysisError("HLR program not found for optimization".to_string())
        })?;

        // Create an optimizer and optimize the program
        let optimizer = HlrOptimizer::new(model);
        let optimized_program = optimizer.optimize(hlr_program)?;

        // Store the optimized program
        self.optimized_hlr_program = Some(optimized_program.clone());
        model.set_optimized_hlr_program(optimized_program);

        println!("HLR optimization finished.");
        Ok(())
    }
}
