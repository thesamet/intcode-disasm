use leptos::*;
use crate::analysis::ConstraintInfo;

#[component]
pub fn ConstraintViewer(
    constraints: Vec<ConstraintInfo>,
    #[prop(optional)] filter_function: Option<u32>,
) -> impl IntoView {
    let filtered_constraints = create_memo(move |_| {
        if let Some(func_id) = filter_function {
            constraints.iter()
                .filter(|c| c.function_id == Some(func_id))
                .cloned()
                .collect::<Vec<_>>()
        } else {
            constraints.clone()
        }
    });

    view! {
        <div class="constraint-viewer">
            <div class="constraint-header">
                <h3>"Type Constraints"</h3>
                <div class="constraint-count">
                    {move || filtered_constraints.get().len()} " constraints"
                </div>
            </div>
            
            <div class="constraint-list">
                <For
                    each=move || filtered_constraints.get()
                    key=|constraint| constraint.id.clone()
                    children=|constraint| {
                        view! {
                            <div class="constraint-item">
                                <div class="constraint-relation">
                                    <span class="subtype">{constraint.subtype}</span>
                                    <span class="relation-arrow">"⊆"</span>
                                    <span class="supertype">{constraint.supertype}</span>
                                </div>
                                
                                <div class="constraint-details">
                                    <span class="constraint-reason">{constraint.reason}</span>
                                    <Show when=move || constraint.function_id.is_some()>
                                        <span class="constraint-location">
                                            "fn" {constraint.function_id.unwrap_or(0)}
                                            <Show when=move || constraint.instruction.is_some()>
                                                ":inst" {constraint.instruction.unwrap_or(0)}
                                            </Show>
                                        </span>
                                    </Show>
                                </div>
                            </div>
                        }
                    }
                />
            </div>
        </div>
    }
}