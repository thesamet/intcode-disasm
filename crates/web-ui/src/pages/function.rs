use crate::analysis::{AnalysisResult, FunctionInfo};
use leptos::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;
use web_sys::Response;

async fn fetch_analysis_from_server() -> Result<AnalysisResult, String> {
    let window = web_sys::window().unwrap();

    // Determine API URL based on current port
    let api_url = "/api/analysis";

    let resp_value = wasm_bindgen_futures::JsFuture::from(window.fetch_with_str(api_url))
        .await
        .map_err(|_| "Failed to fetch analysis")?;

    let resp: Response = resp_value.dyn_into().unwrap();
    let text = wasm_bindgen_futures::JsFuture::from(resp.text().unwrap())
        .await
        .map_err(|_| "Failed to read response")?;

    let text_str = text.as_string().unwrap();

    // Parse the JSON response
    #[derive(serde::Deserialize)]
    struct ServerResponse {
        result: web_bridge::WebAnalysisResult,
    }

    let server_response: ServerResponse =
        serde_json::from_str(&text_str).map_err(|e| format!("Failed to parse JSON: {e}"))?;

    // Convert to UI format
    let functions = server_response
        .result
        .functions
        .into_iter()
        .map(|web_func| FunctionInfo {
            id: web_func.id,
            name: web_func.name,
            ssa_code: web_func.ssa_folded_code.clone(),
            hlr_code: web_func.hlr_code.clone(),
            instruction_count: web_func.instruction_count,
        })
        .collect();

    Ok(AnalysisResult {
        functions,
        globals: server_response.result.globals,
        type_variables: vec![], // TODO: Add real type variable data
        constraints: vec![],    // TODO: Add real constraint data
    })
}

#[component]
pub fn FunctionPage() -> impl IntoView {
    let (analysis_result, set_analysis_result) = create_signal(None::<AnalysisResult>);
    let (show_ssa, set_show_ssa) = create_signal(false); // Default to HLR view
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

    // Function to scroll to a specific function
    let scroll_to_function = move |func_id: u32| {
        if let Some(window) = web_sys::window() {
            if let Some(document) = window.document() {
                if let Some(element) = document.get_element_by_id(&format!("function-{func_id}")) {
                    element.scroll_into_view();
                }
            }
        }
    };

    view! {
        <div class="container">
            <h1>"All Functions"</h1>
            <p>"Current view: " {move || if show_ssa.get() { "SSA" } else { "HLR" }}</p>

            <div class="function-layout">
                <nav class="function-nav">
                    <h3>"Jump to Function"</h3>
                    <div class="view-controls" style="margin-bottom: 1rem; display: flex; gap: 0.5rem;">
                        <button
                            class=move || format!("btn-secondary {}", if show_ssa.get() { "active" } else { "" })
                            on:click=move |_| {
                                log::info!("SSA button clicked");
                                set_show_ssa.set(true);
                            }
                        >"Folded SSA"</button>
                        <button
                            class=move || format!("btn-secondary {}", if !show_ssa.get() { "active" } else { "" })
                            on:click=move |_| {
                                log::info!("HLR button clicked");
                                set_show_ssa.set(false);
                            }
                        >"HLR View"</button>
                    </div>
                    <Show when=move || analysis_result.get().is_some()>
                        <ul class="function-list">
                            <For
                                each=move || analysis_result.get().map(|r| r.functions).unwrap_or_default()
                                key=|func| func.id
                                children=move |func| {
                                    let func_id = func.id;
                                    view! {
                                        <li>
                                            <a
                                                href="#"
                                                class="function-link"
                                                on:click=move |e| {
                                                    e.prevent_default();
                                                    scroll_to_function(func_id);
                                                }
                                            >
                                                {func.name}
                                            </a>
                                        </li>
                                    }
                                }
                            />
                        </ul>
                    </Show>
                </nav>

                <main class="function-content">
                    <Show when=move || analysis_result.get().is_some()>
                        // Show globals section first
                        <div class="globals-section">
                            <h2>"Global Variables"</h2>
                            <div class="code-view">
                                <pre class="code-block">
                                    <code inner_html=move || analysis_result.get().map(|r| r.globals.clone()).unwrap_or_default()>
                                    </code>
                                </pre>
                            </div>
                        </div>
                        
                        <div class="all-functions">
                            <For
                                each=move || analysis_result.get().map(|r| r.functions).unwrap_or_default()
                                key=|func| func.id
                                children=move |func| {
                                    view! {
                                        <div class="function-section" id=format!("function-{}", func.id)>
                                            <div class="function-header">
                                                <h2>{func.name.clone()}</h2>
                                            </div>

                                            <div class="code-view">
                                                <pre class="code-block">
                                                    <code inner_html=move || if show_ssa.get() {
                                                        func.ssa_code.clone()
                                                    } else {
                                                        func.hlr_code.clone()
                                                    }>
                                                    </code>
                                                </pre>
                                            </div>
                                        </div>
                                    }
                                }
                            />
                        </div>
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

