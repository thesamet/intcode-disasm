use leptos::*;
use leptos_router::*;
use crate::analysis::{AnalysisResult, FunctionInfo};
use wasm_bindgen_futures::spawn_local;
use web_sys::{Request, RequestInit, Response};
use wasm_bindgen::JsCast;

async fn fetch_analysis_from_server() -> Result<AnalysisResult, String> {
    let window = web_sys::window().unwrap();
    let resp_value = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_str("/api/analysis")
    ).await.map_err(|_| "Failed to fetch analysis")?;
    
    let resp: Response = resp_value.dyn_into().unwrap();
    let text = wasm_bindgen_futures::JsFuture::from(resp.text().unwrap())
        .await.map_err(|_| "Failed to read response")?;
    
    let text_str = text.as_string().unwrap();
    
    // Parse the JSON response
    #[derive(serde::Deserialize)]
    struct ServerResponse {
        result: web_bridge::WebAnalysisResult,
    }
    
    let server_response: ServerResponse = serde_json::from_str(&text_str)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;
    
    // Convert to UI format
    let functions = server_response.result.functions.into_iter().map(|web_func| {
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
        type_variables: vec![], // TODO: Add real type variable data
        constraints: vec![],    // TODO: Add real constraint data
    })
}

#[component]
pub fn FunctionPage() -> impl IntoView {
    let params = use_params_map();
    let function_id = move || {
        params.with(|params| {
            params.get("id")
                .and_then(|id| id.parse::<u32>().ok())
                .unwrap_or(0)
        })
    };

    let (analysis_result, set_analysis_result) = create_signal(None::<AnalysisResult>);
    let (show_ssa, set_show_ssa) = create_signal(true);
    let (loading, set_loading) = create_signal(true);
    let (error, set_error) = create_signal(None::<String>);
    
    // Load analysis results from server on mount
    create_effect(move |_| {
        spawn_local(async move {
            match fetch_analysis_from_server().await {
                Ok(result) => {
                    set_analysis_result.set(Some(result));
                    set_loading.set(false);
                }
                Err(e) => {
                    log::error!("Failed to fetch analysis: {}", e);
                    set_error.set(Some(e));
                    set_loading.set(false);
                }
            }
        });
    });

    view! {
        <div class="container">
            <h1>"Function " {function_id}</h1>
            
            <div class="function-layout">
                <nav class="function-nav">
                    <h3>"Functions"</h3>
                    <Show when=move || analysis_result.get().is_some()>
                        <ul class="function-list">
                            <For
                                each=move || analysis_result.get().map(|r| r.functions).unwrap_or_default()
                                key=|func| func.id
                                children=move |func| {
                                    let func_id = func.id;
                                    let is_current = function_id() == func_id;
                                    view! {
                                        <li>
                                            <A 
                                                href=format!("/function/{}", func_id)
                                                class=format!("function-link {}", if is_current { "active" } else { "" })
                                            >
                                                {func.name} " (" {func.instruction_count} " instructions)"
                                            </A>
                                        </li>
                                    }
                                }
                            />
                        </ul>
                    </Show>
                </nav>

                <main class="function-content">
                    <Show when=move || analysis_result.get().is_some()>
                        {move || {
                            let result = analysis_result.get().unwrap();
                            let current_function = result.functions.iter()
                                .find(|f| f.id == function_id())
                                .cloned();
                            
                            match current_function {
                                Some(func) => view! {
                                    <div class="function-header">
                                        <h2>{func.name.clone()}</h2>
                                        <div class="view-controls">
                                            <button 
                                                class=format!("btn-secondary {}", if show_ssa.get() { "active" } else { "" })
                                                on:click=move |_| set_show_ssa.set(true)
                                            >"Folded SSA"</button>
                                            <button 
                                                class=format!("btn-secondary {}", if !show_ssa.get() { "active" } else { "" })
                                                on:click=move |_| set_show_ssa.set(false)
                                            >"HLR View"</button>
                                        </div>
                                    </div>

                                    <div class="code-view">
                                        <pre class="code-block">
                                            <code>
                                                {if show_ssa.get() { 
                                                    func.ssa_code 
                                                } else { 
                                                    func.hlr_code 
                                                }}
                                            </code>
                                        </pre>
                                    </div>

                                    <div class="function-stats">
                                        <div class="stat">
                                            <span class="stat-label">"Instructions:"</span>
                                            <span class="stat-value">{func.instruction_count}</span>
                                        </div>
                                    </div>
                                }.into_view(),
                                None => view! {
                                    <div class="error-message">
                                        "Function " {function_id} " not found"
                                    </div>
                                }.into_view()
                            }
                        }}
                    </Show>
                    
                    <Show when=move || loading.get()>
                        <div class="loading-message">
                            "Loading analysis from server..."
                        </div>
                    </Show>
                    
                    <Show when=move || error.get().is_some()>
                        <div class="error-message">
                            "Error: " {move || error.get().unwrap_or_default()}
                        </div>
                    </Show>
                </main>
            </div>
        </div>
    }
}