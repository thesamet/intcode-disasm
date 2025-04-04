use log::{debug, info, warn};

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
        info!("SsaConverter received event: {:?}", event);
        
        match event {
            // Wait for data flow analysis to complete for all functions
            Event::DataFlowAnalysisComplete(_) => {
                // Check if all functions have been analyzed
                let functions = model.functions().keys().count();
                info!("Function count: {}", functions);
                
                let ready_for_ssa = model.get_data_flow_result()
                    .map(|dfa| {
                        let has_results = dfa.block_results.len() > 0;
                        info!("Data flow analysis has {} block results", dfa.block_results.len());
                        has_results
                    })
                    .unwrap_or_else(|| {
                        warn!("No data flow analysis results available");
                        false
                    });
                
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
                } else {
                    warn!("Not ready for SSA conversion: ready_for_ssa={}, functions={}", 
                          ready_for_ssa, functions);
                }
            }
            _ => {
                // Ignore other events
                info!("Ignoring unhandled event");
            }
        }
    }
}