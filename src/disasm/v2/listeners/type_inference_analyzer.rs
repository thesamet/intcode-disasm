use log::{info, warn};
use std::collections::HashMap;

use crate::disasm::v2::{
    dispatching::{EventCollector, EventListener},
    events::{Event, TypeInferenceComplete},
    model::ProgramModel,
    ssa_form::SsaProgram,
    type_inference::{Type, TypeInference, TypeVarId},
};

/// Analyzer that performs type inference on SSA form
#[derive(Clone)]
pub struct TypeInferenceAnalyzer {
    /// The SSA form representation of the program
    ssa_program: Option<SsaProgram>,

    /// The type inference engine
    type_inference: TypeInference,

    /// The type substitution results after unification
    substitution: Option<HashMap<TypeVarId, Type>>,
}

#[allow(dead_code)]
impl TypeInferenceAnalyzer {
    /// Create a new type inference analyzer
    pub fn new() -> Self {
        Self {
            ssa_program: None,
            type_inference: TypeInference::new(),
            substitution: None,
        }
    }

    /// Get the type inference results
    pub fn get_type_inference(&self) -> &TypeInference {
        &self.type_inference
    }

    /// Get the type substitution results
    pub fn get_substitution(&self) -> Option<&HashMap<TypeVarId, Type>> {
        self.substitution.as_ref()
    }
}

impl EventListener<Event, ProgramModel> for TypeInferenceAnalyzer {
    fn on_event(
        &mut self,
        model: &mut ProgramModel,
        event: Event,
        collector: &mut EventCollector<Event>,
    ) {
        match event {
            // Start type inference after SSA conversion is complete
            Event::SsaConversionComplete(_) => {
                info!("Starting type inference analysis");

                // Get the SSA converter listener from the model
                let ssa_converter = model.ssa_converter.as_ref();

                if let Some(ssa_converter) = ssa_converter {
                    if let Some(ssa_program) = ssa_converter.get_ssa_program() {
                        // Store a copy of the SSA program
                        self.ssa_program = Some(ssa_program.clone());

                        // Generate type constraints from the SSA form
                        self.type_inference
                            .generate_constraints_for_program(ssa_program);

                        // Solve the constraints through unification
                        match self.type_inference.unify() {
                            Ok(substitution) => {
                                info!("Type inference completed successfully");
                                self.substitution = Some(substitution);

                                // Signal that type inference is complete
                                collector.publish(TypeInferenceComplete { completed: true });
                            }
                            Err(error) => {
                                warn!("Type inference failed: {}", error);
                            }
                        }
                    } else {
                        warn!("SSA program not available");
                    }
                } else {
                    warn!("SSA converter not found in model");
                }
            }
            _ => {
                // Ignore other events
            }
        }
    }
}
