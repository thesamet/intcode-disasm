use itertools::Itertools;
use rmcp::model::{
    Implementation, InitializeRequestParam, InitializeResult, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::transport::stdio;
use rmcp::{
    handler::server::tool::IntoCallToolResult,
    model::{CallToolResult, Content, IntoContents},
    schemars, tool, ServiceExt,
};
use serde::{ser::SerializeStruct, Serialize, Serializer};

use crate::disasm::repl::ReplCommands;
use crate::disasm::v3::common::formatting::ContextualPrettyPrint;
use crate::disasm::v3::lir::MemoryReferenceInfo;
use crate::disasm::v3::model::{HasTypeInferenceResult, ModelState};
use crate::disasm::v3::type_inference::{TypeVarId, TypeVarState};
use crate::disasm::v3::{
    cfg::FunctionView,
    model::{HlrConstructionComplete, Model},
    FunctionId,
};
use rmcp::{Error as McpError, RoleServer};

#[derive(Clone)]
pub struct DisasmService {
    model: Model<HlrConstructionComplete>,
}

impl<'a> Serialize for FunctionView<'a, HlrConstructionComplete> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Function", 4)?;
        state.serialize_field("function_id", &self.function_id())?;
        state.serialize_field("entry_block", &self.entry_block())?;
        state.serialize_field("stack_size", &self.stack_size())?;
        state.serialize_field("code", &self.pretty_print())?;
        state.end()
    }
}

impl<'a> IntoContents for FunctionView<'a, HlrConstructionComplete> {
    fn into_contents(self) -> Vec<Content> {
        vec![Content::json(self).unwrap()]
    }
}

#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct TypeVarRow {
    id: String,
    function: String,
    inst: String,
    role: String,
    expr: String,
    lower: Option<Vec<String>>,
    upper: Option<Vec<String>>,
    converged: Option<String>,
}

#[tool(tool_box)]
impl DisasmService {
    pub fn new(model: Model<HlrConstructionComplete>) -> Self {
        Self { model }
    }

    #[tool(description = "List the SSA representation of a function")]
    fn list_ssa_function(
        &self,
        #[tool(param)]
        #[schemars(description = "The function to disassemble")]
        function_id: FunctionId,
    ) -> Result<CallToolResult, McpError> {
        self.model
            .get_function(&function_id)
            .ok_or_else(|| {
                McpError::invalid_params(format!("Function {function_id} does not exist"), None)
            })
            .and_then(|f| f.into_call_tool_result())
    }

    pub fn list_variables_data<S: HasTypeInferenceResult + ModelState + 'static>(
        model: &Model<S>,
        id: Option<TypeVarId>,
        function: Option<FunctionId>,
        global: bool,
    ) -> Result<Vec<TypeVarRow>, String> {
        let ti = model.type_inference_result();
        let mut data = Vec::new();
        for (tv, tv_node) in ti
            .type_var_nodes
            .iter()
            .filter(|(tv_id, n)| {
                id.is_none_or(|id| id == **tv_id)
                    && function.is_none_or(|f| f == n.path.function_id())
            })
            .filter(|(_, n)| !global || n.vmr.is_some_and(|vmr| vmr.is_global()))
            .sorted_by_key(|(id, _)| *id)
        {
            let state = ti.type_var_states.get(tv).unwrap();
            let (role, expr) = ReplCommands::format_path(model, &tv_node.path);

            data.push(TypeVarRow {
                id: format!("{tv}"),
                function: format!("{}", tv_node.path.function_id()),
                inst: tv_node
                    .path
                    .instruction_id()
                    .map(|c| c.to_string())
                    .unwrap_or_default()
                    .to_string(),
                role,
                expr: expr.map(|e| e.to_string()).unwrap_or_default(),
                lower: match state {
                    TypeVarState::Bounds { lower_bounds, .. } => Some(
                        lower_bounds
                            .iter()
                            .map(|bs| bs.display_with(model.type_inference_result()).to_string())
                            .collect(),
                    ),
                    TypeVarState::Converged(_ty) => None,
                },
                upper: match state {
                    TypeVarState::Bounds { upper_bounds, .. } => Some(
                        upper_bounds
                            .iter()
                            .map(|bs| bs.display_with(model.type_inference_result()).to_string())
                            .collect(),
                    ),
                    TypeVarState::Converged(_ty) => None,
                },
                converged: match state {
                    TypeVarState::Converged(ty) => {
                        Some(ty.display_with(model.type_inference_result()).to_string())
                    }
                    _ => None,
                },
            });
        }
        Ok(data)
    }

    #[tool(description = "List variables in the model based on filters")]
    fn list_variables(
        &self,
        #[tool(param)]
        #[schemars(description = "The optional type variable ID to filter by")]
        id: Option<TypeVarId>,
        #[tool(param)]
        #[schemars(description = "The optional function ID to filter by")]
        function: Option<FunctionId>,
        #[tool(param)]
        #[schemars(description = "Whether to include only global variables")]
        global: Option<bool>,
    ) -> Result<CallToolResult, McpError> {
        let data = Self::list_variables_data(&self.model, id, function, global.unwrap_or(false))
            .map_err(|e| McpError::invalid_params(e, None))?;

        Ok(CallToolResult::success(vec![Content::json(data)?]))
    }

    #[tool(description = "Shows the history of a type variable")]
    fn history(
        &self,
        #[tool(param)]
        #[schemars(description = "The optional type variable ID to filter by")]
        tv_id: Option<TypeVarId>,
        #[tool(param)]
        #[schemars(description = "Whether to include only global variables")]
        resolve: Option<bool>,
    ) -> Result<CallToolResult, McpError> {
        let data = ReplCommands::changelog_data(&self.model, tv_id, resolve.unwrap_or(false))
            .map_err(|e| McpError::invalid_params(e, None))?;

        Ok(CallToolResult::success(vec![Content::json(data)?]))
    }
}

#[tool(tool_box)]
impl rmcp::ServerHandler for DisasmService {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder()
                .enable_tools().build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "This server provides decompile information for an intcode program. Use 'list_ssa_function' to get the SSA representation of a function. It takes as an only param the function id as u64".to_string(),
            ),
            ..Default::default()
        }
    }
    async fn initialize(
        &self,
        _request: InitializeRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        Ok(self.get_info())
    }
}

pub async fn mcp(model: Model<HlrConstructionComplete>) -> Result<(), Box<dyn std::error::Error>> {
    let service = DisasmService::new(model);
    eprintln!("MCP server started");
    let service = service.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
