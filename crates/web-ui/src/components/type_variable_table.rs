use leptos::*;
use crate::analysis::{TypeVarInfo, TypeVarStatus};

#[component]
pub fn TypeVariableTable(
    variables: Vec<TypeVarInfo>,
    #[prop(optional)] selected_var: Option<String>,
    #[prop(optional)] on_select: Option<Callback<String>>,
) -> impl IntoView {
    view! {
        <div class="type-variable-table">
            <table class="var-table">
                <thead>
                    <tr>
                        <th>"Variable"</th>
                        <th>"Function"</th>
                        <th>"Instruction"</th>
                        <th>"Role"</th>
                        <th>"Type"</th>
                        <th>"Status"</th>
                    </tr>
                </thead>
                <tbody>
                    <For
                        each=move || variables.clone()
                        key=|var| var.id.clone()
                        children=move |var| {
                            let var_id = var.id.clone();
                            let is_selected = selected_var.as_ref() == Some(&var.id);
                            
                            view! {
                                <tr 
                                    class="var-row"
                                    class:selected=is_selected
                                    on:click=move |_| {
                                        if let Some(callback) = on_select {
                                            callback.call(var_id.clone());
                                        }
                                    }
                                >
                                    <td class="var-name">{var.id}</td>
                                    <td class="var-function">{var.function_id}</td>
                                    <td class="var-instruction">{var.instruction}</td>
                                    <td class="var-role">{var.role}</td>
                                    <td class="var-type">{var.type_info}</td>
                                    <td class="var-status">
                                        <span class={format!("status-badge {}", 
                                            match var.status {
                                                TypeVarStatus::Converged => "converged",
                                                TypeVarStatus::Bounded => "bounded", 
                                                TypeVarStatus::Unknown => "unknown",
                                            }
                                        )}>
                                            {match var.status {
                                                TypeVarStatus::Converged => "✓",
                                                TypeVarStatus::Bounded => "~",
                                                TypeVarStatus::Unknown => "?",
                                            }}
                                        </span>
                                    </td>
                                </tr>
                            }
                        }
                    />
                </tbody>
            </table>
        </div>
    }
}