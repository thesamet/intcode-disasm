use std::collections::HashMap;
use crate::disasm::v3::id_types::FunctionId;
use super::function::Function;

#[derive(Debug, Clone)]
pub struct ControlFlowGraphResult {
    pub functions: HashMap<FunctionId, Function>,
}
