use super::{function::Function, FunctionView};
use crate::disasm::v3::{
    id_types::FunctionId,
    model::{HasControlFlowGraphResult, Model, ModelState},
};
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct ControlFlowGraphResult {
    functions: HashMap<FunctionId, Function>,
}

impl ControlFlowGraphResult {
    pub fn new(functions: HashMap<FunctionId, Function>) -> Self {
        ControlFlowGraphResult { functions }
    }
}

impl<S: ModelState> Model<S>
where
    S: HasControlFlowGraphResult,
{
    /// Returns a function view for the specified function ID.
    ///
    /// # Parameters
    /// * `function_id` - The ID of the function to retrieve
    ///
    /// # Returns
    /// A `FunctionView` for the specified function
    ///
    /// # Panics
    /// Panics if the function ID does not exist in the model
    pub fn function<'a, 'b>(&'a self, function_id: &'b FunctionId) -> FunctionView<'a, S> {
        self.get_function(function_id)
            .unwrap_or_else(|| panic!("Function {} does not exist", function_id))
    }

    pub fn get_function<'a>(&'a self, function_id: &FunctionId) -> Option<FunctionView<'a, S>> {
        let function = self
            .control_flow_graph_result()
            .functions
            .get(function_id)
            .map(|function| FunctionView::new(self, function));
        function
    }

    /// Returns an iterator over all functions in the model.
    ///
    /// # Returns
    /// An iterator that yields tuples of function IDs and their corresponding function views
    pub fn functions<'a>(&'a self) -> impl Iterator<Item = (FunctionId, FunctionView<'a, S>)> {
        self.control_flow_graph_result()
            .functions
            .iter()
            .map(|(id, function)| (*id, FunctionView::new(self, function)))
    }
    /// Returns whether a function exists in the model.
    ///
    /// # Parameters
    /// * `function_id` - The ID of the function to check for
    ///
    /// # Returns
    /// `true` if the function exists, `false` otherwise
    pub fn has_function(&self, function_id: &FunctionId) -> bool {
        self.control_flow_graph_result()
            .functions
            .contains_key(function_id)
    }
}
