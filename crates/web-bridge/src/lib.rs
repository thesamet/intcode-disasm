// Bridge between disasm library and web frontend
// Handles serialization and WASM compatibility

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(not(target_arch = "wasm32"))]
use disasm::disasm::v3::analysis::binary_to_hlr;

#[cfg(not(target_arch = "wasm32"))]
use disasm::disasm::UserDefs;

#[derive(Error, Debug)]
pub enum BridgeError {
    #[error("Analysis failed: {0}")]
    AnalysisError(String),
    #[error("Serialization failed: {0}")]
    SerializationError(String),
}

/// Web-compatible representation of analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAnalysisResult {
    pub functions: Vec<WebFunction>,
    pub program_size: usize,
    pub analysis_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebFunction {
    pub id: u32,
    pub name: String,
    pub ssa_folded_code: String,
    pub hlr_code: String,
    pub instruction_count: usize,
    pub entry_point: usize,
}

/// Main analysis function that bridges disasm library to web frontend
#[cfg(not(target_arch = "wasm32"))]
pub fn analyze_program_for_web(program: Vec<i128>) -> Result<WebAnalysisResult, BridgeError> {
    // Run full analysis pipeline to HLR
    let user_defs = UserDefs::new(); // Use empty user definitions for web
    let model = binary_to_hlr(program.clone(), user_defs).map_err(|e| {
        BridgeError::AnalysisError(format!("Pipeline failed: {:?}", e))
    })?;

    // Extract folded SSA results
    let mut functions = Vec::new();
    
    // Get all function IDs from the model using the correct API
    let function_ids = model.image_scanner_result().function_ids();
    
    for function_id in function_ids {
        // Get folded SSA for this function using hierarchical access
        let function_view = model.function(&function_id);
        
        // Format folded SSA as string  
        let ssa_code = format_function_folded_ssa_from_hlr(&model, &function_id);
        
        // Format HLR as string
        let hlr_code = format_function_hlr(&model, &function_id);
        
        // Get function info from image scanner
        let recognized_functions = &model.image_scanner_result().recognized_functions;
        let function_info = recognized_functions.iter()
            .find(|(id, _)| **id == function_id)
            .map(|(_, func)| func);
        
        let instruction_count = function_info.map(|f| f.instructions.len()).unwrap_or(0);
        let entry_point = function_info.map(|f| f.instructions[0].span.start).unwrap_or(0);
        
        functions.push(WebFunction {
            id: function_id.index() as u32, // Extract the numeric value
            name: format!("function_{}", function_id.index()),
            ssa_folded_code: ssa_code,
            hlr_code,
            instruction_count,
            entry_point,
        });
    }
    
    Ok(WebAnalysisResult {
        functions,
        program_size: program.len(),
        analysis_complete: true,
    })
}

/// WASM-only stub - returns mock data since full analysis pipeline isn't available in WASM
#[cfg(target_arch = "wasm32")]
pub fn analyze_program_for_web(program: Vec<i128>) -> Result<WebAnalysisResult, BridgeError> {
    // For WASM, return mock data for now
    // In a real implementation, you'd send the data to a server for analysis
    Ok(WebAnalysisResult {
        functions: vec![
            WebFunction {
                id: 0,
                name: "function_0".to_string(),
                ssa_folded_code: format!(
                    "// Mock folded SSA for {} instruction program\n// Real analysis would run on server\nv0 = input()\nv1 = add v0, 42\noutput(v1)\nhalt()",
                    program.len()
                ),
                hlr_code: format!(
                    "// Mock HLR for {} instruction program\n// Real analysis would run on server\ninput = read_input();\nresult = input + 42;\nprint(result);",
                    program.len()
                ),
                instruction_count: program.len(),
                entry_point: 0,
            }
        ],
        program_size: program.len(),
        analysis_complete: false, // Indicate this is mock data
    })
}

// Helper function to format folded SSA for a function using hierarchical access
#[cfg(not(target_arch = "wasm32"))]
fn format_function_folded_ssa(function_view: &disasm::disasm::v3::cfg::FunctionView<disasm::disasm::v3::model::FoldedSsaComplete>) -> String {
    use disasm::disasm::v3::common::formatting::ContextualPrettyPrint;
    use disasm::disasm::v3::common::formatting::pretty_print_framework::PrettyPrintConfig;
    
    // Use the pretty print system with web CSS output
    let config = PrettyPrintConfig::default()
        .with_show_types(false)
        .with_show_vars(false)
        .with_web_css_output(true); // Enable CSS class output for web
    
    function_view.pretty_print_with_config(&config)
}

// Helper function to format folded SSA from HLR model
#[cfg(not(target_arch = "wasm32"))]
fn format_function_folded_ssa_from_hlr(model: &disasm::disasm::v3::model::Model<disasm::disasm::v3::model::HlrConstructionComplete>, function_id: &disasm::disasm::v3::FunctionId) -> String {
    use disasm::disasm::v3::common::formatting::ContextualPrettyPrint;
    use disasm::disasm::v3::common::formatting::pretty_print_framework::PrettyPrintConfig;
    
    // Use the pretty print system with web CSS output
    let config = PrettyPrintConfig::default()
        .with_show_types(false)
        .with_show_vars(false)
        .with_web_css_output(true) // Enable CSS class output for web
        .with_no_colors(); // Disable ANSI colors for web output
    
    // Access the folded SSA from the HLR model
    let function_view = model.function(function_id);
    function_view.pretty_print_with_config(&config)
}

// Helper function to format HLR for a function
#[cfg(not(target_arch = "wasm32"))]
fn format_function_hlr(model: &disasm::disasm::v3::model::Model<disasm::disasm::v3::model::HlrConstructionComplete>, function_id: &disasm::disasm::v3::FunctionId) -> String {
    use disasm::disasm::v3::common::formatting::ContextualPrettyPrint;
    use disasm::disasm::v3::common::formatting::pretty_print_framework::PrettyPrintConfig;
    
    // Use the pretty print system with web CSS output
    let config = PrettyPrintConfig::default()
        .with_show_types(false)
        .with_show_vars(false)
        .with_web_css_output(true) // Enable CSS class output for web
        .with_no_colors(); // Disable ANSI colors for web output
    
    // Get the HLR program and find the specific function
    let hlr_program = model.hlr_program();
    
    // Debug: Log the function IDs available in HLR and config settings
    log::debug!("Looking for function {} in HLR program", function_id.index());
    log::debug!("Available HLR functions: {:?}", 
        hlr_program.functions.iter().map(|f| f.original_id.index()).collect::<Vec<_>>());
    log::debug!("HLR config web_css_output: {}", config.web_css_output);
    
    // Find the HLR function with matching original_id
    if let Some(hlr_function) = hlr_program.functions.iter().find(|f| f.original_id == *function_id) {
        log::debug!("Found HLR function for {}", function_id.index());
        // Format just this function with web CSS output
        let result = hlr_function.pretty_print_with_config_and_data(&config, model.type_inference_result());
        log::debug!("HLR output first 100 chars: {}", result.chars().take(100).collect::<String>());
        result
    } else {
        // Fallback: show a message that this function's HLR isn't available
        log::debug!("HLR function for {} not found", function_id.index());
        format!("// HLR for function {} not available\n// (The function may be too simple for HLR generation)", function_id.index())
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen]
    pub fn analyze_intcode_program(program_json: &str) -> Result<String, JsValue> {
        let program: Vec<i128> = serde_json::from_str(program_json)
            .map_err(|e| JsValue::from_str(&format!("Parse error: {}", e)))?;
        
        let result = analyze_program_for_web(program)
            .map_err(|e| JsValue::from_str(&format!("Analysis error: {}", e)))?;
        
        serde_json::to_string(&result)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
}