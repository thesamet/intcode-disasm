// Analysis interface using real disasm library via web-bridge
use serde::{Deserialize, Serialize};
use web_bridge::analyze_program_for_web;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub functions: Vec<FunctionInfo>,
    pub type_variables: Vec<TypeVarInfo>,
    pub constraints: Vec<ConstraintInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub id: u32,
    pub name: String,
    pub ssa_code: String,
    pub hlr_code: String,
    pub instruction_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeVarInfo {
    pub id: String,
    pub function_id: u32,
    pub instruction: u32,
    pub role: String,
    pub type_info: String,
    pub status: TypeVarStatus,
    pub history: Vec<TypeVarChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeVarChange {
    pub iteration: u32,
    pub change_type: String,
    pub reason: String,
    pub new_bounds: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TypeVarStatus {
    Converged,
    Bounded,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConstraintInfo {
    pub id: String,
    pub subtype: String,
    pub supertype: String,
    pub reason: String,
    pub function_id: Option<u32>,
    pub instruction: Option<u32>,
}

// Analysis function that calls the server for real analysis in WASM mode
#[cfg(target_arch = "wasm32")]
pub fn analyze_program(_program: Vec<i128>) -> Result<AnalysisResult, String> {
    // For now, return an error suggesting to use the server
    Err("Real-time analysis not yet implemented in web mode. Please use the analysis server.".to_string())
}

// Native analysis function using disasm library directly
#[cfg(not(target_arch = "wasm32"))]
#[allow(dead_code)]
pub fn analyze_program(program: Vec<i128>) -> Result<AnalysisResult, String> {
    // Call the real disasm analysis pipeline
    let web_result = analyze_program_for_web(program)
        .map_err(|e| format!("Analysis failed: {e}"))?;
    
    // Convert WebAnalysisResult to our UI AnalysisResult format
    let functions = web_result.functions.into_iter().map(|web_func| {
        FunctionInfo {
            id: web_func.id,
            name: web_func.name,
            ssa_code: web_func.ssa_folded_code.clone(),
            hlr_code: format!("// HLR view coming soon\n{}", web_func.ssa_folded_code),
            instruction_count: web_func.instruction_count,
        }
    }).collect();
    
    Ok(AnalysisResult {
        functions,
        // TODO: Extract real type variables and constraints from analysis
        type_variables: vec![], // Placeholder for now
        constraints: vec![],     // Placeholder for now
    })
}