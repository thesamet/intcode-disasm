use leptos::*;

#[component]
pub fn TypesPage() -> impl IntoView {
    let (selected_var, set_selected_var) = create_signal(None::<String>);

    view! {
        <div class="container">
            <h1>"Type Inference Explorer"</h1>
            
            <div class="types-layout">
                <div class="type-variables-panel">
                    <h2>"Type Variables"</h2>
                    <div class="filters">
                        <select class="filter-select">
                            <option>"All Functions"</option>
                            <option>"Function 0"</option>
                            <option>"Function 1"</option>
                        </select>
                        <select class="filter-select">
                            <option>"All Status"</option>
                            <option>"Converged"</option>
                            <option>"Bounded"</option>
                        </select>
                    </div>
                    
                    <div class="type-var-list">
                        <div class="type-var-item" 
                             on:click=move |_| set_selected_var.set(Some("v0".to_string()))>
                            <div class="var-header">
                                <span class="var-name">"v0"</span>
                                <span class="var-status converged">"✓"</span>
                            </div>
                            <div class="var-info">
                                <span class="var-type">"int"</span>
                                <span class="var-location">"fn0:inst2"</span>
                            </div>
                        </div>
                        
                        <div class="type-var-item"
                             on:click=move |_| set_selected_var.set(Some("v1".to_string()))>
                            <div class="var-header">
                                <span class="var-name">"v1"</span>
                                <span class="var-status bounded">"~"</span>
                            </div>
                            <div class="var-info">
                                <span class="var-type">"int..pointer"</span>
                                <span class="var-location">"fn0:inst5"</span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="type-details-panel">
                    <Show when=move || selected_var.get().is_some()>
                        <div class="type-details">
                            <h2>"Variable Details: " {move || selected_var.get().unwrap_or_default()}</h2>
                            
                            <div class="details-tabs">
                                <button class="tab-button active">"Current State"</button>
                                <button class="tab-button">"History"</button>
                                <button class="tab-button">"Constraints"</button>
                            </div>

                            <div class="details-content">
                                <div class="detail-section">
                                    <h3>"Type Information"</h3>
                                    <div class="type-display">
                                        <span class="type-value">"int"</span>
                                        <span class="confidence high">"High Confidence"</span>
                                    </div>
                                </div>

                                <div class="detail-section">
                                    <h3>"Location"</h3>
                                    <div class="location-info">
                                        <span class="function">"Function 0"</span>
                                        <span class="instruction">"Instruction 2"</span>
                                        <span class="role">"Assignment target"</span>
                                    </div>
                                </div>

                                <div class="detail-section">
                                    <h3>"Related Variables"</h3>
                                    <div class="related-vars">
                                        <span class="related-var">"v1"</span>
                                        <span class="related-var">"v2"</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </Show>
                    
                    <Show when=move || selected_var.get().is_none()>
                        <div class="empty-state">
                            <p>"Select a type variable to see details"</p>
                        </div>
                    </Show>
                </div>
            </div>
        </div>
    }
}