use crate::disasm::v3::model::{Model, ModelState};
use crate::disasm::dispatching::{EventCollector, EventListener};
use crate::disasm::events::Event;
use crate::disasm::Error;

/// Builds the control flow graph from the image scanner results
pub struct ControlFlowGraphBuilder {
    // Builder configuration and state
}

impl ControlFlowGraphBuilder {
    pub fn new() -> Self {
        Self {}
    }
}

impl EventListener<Event, Model<ModelState>> for ControlFlowGraphBuilder {
    fn on_event(
        &mut self,
        model: &mut Model<ModelState>,
        event: Event,
        collector: &mut EventCollector<Event>,
    ) -> Result<(), Error> {
        // Implementation would build the control flow graph
        Ok(())
    }
}
