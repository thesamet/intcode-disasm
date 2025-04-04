use log::{debug, info};

use crate::disasm::v2::{
    dispatching::{EventCollector, EventListener},
    events::{DataFlowAnalysisComplete, Event, SsaConversionComplete},
    model::ProgramModel,
    ssa_form::SsaProgram,
};

/// Listener that converts the program to SSA form
#[derive(Clone, Debug)]
pub struct SsaConverter {
    /// The SSA form representation of the program
    ssa_program: Option<SsaProgram>,
}

impl SsaConverter {
    /// Create a new SSA converter
    pub fn new() -> Self {
        Self {
            ssa_program: None,
        }
    }
    
    /// Get the SSA program (if converted)
    pub fn get_ssa_program(&self) -> Option<&SsaProgram> {
        self.ssa_program.as_ref()
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
                // Check if all functions have been analyzed
                let functions = model.functions().keys().count();
                let ready_for_ssa = model.get_data_flow_result()
                    .map(|dfa| dfa.block_results.len() > 0)
                    .unwrap_or(false);
                
                if ready_for_ssa && functions > 0 {
                    info!("Converting program to SSA form");
                    
                    // Convert the program to SSA form
                    let ssa_program = SsaProgram::from_program_model(model);
                    self.ssa_program = Some(ssa_program);
                    
                    // Notify that SSA conversion is complete
                    info!("SSA conversion complete");
                    collector.publish(SsaConversionComplete {
                        completed: true,
                    });
                }
            }
            _ => {
                // Ignore other events
            }
        }
    }
}