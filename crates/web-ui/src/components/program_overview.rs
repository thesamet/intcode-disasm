use leptos::*;

#[component]
pub fn ProgramOverview() -> impl IntoView {
    view! {
        <div class="program-overview">
            <h2>"Program Overview"</h2>
            <div class="stats">
                <div class="stat">
                    <span class="stat-label">"Functions"</span>
                    <span class="stat-value">"3"</span>
                </div>
                <div class="stat">
                    <span class="stat-label">"Instructions"</span>
                    <span class="stat-value">"42"</span>
                </div>
                <div class="stat">
                    <span class="stat-label">"Type Variables"</span>
                    <span class="stat-value">"15"</span>
                </div>
                <div class="stat">
                    <span class="stat-label">"Constraints"</span>
                    <span class="stat-value">"28"</span>
                </div>
            </div>
        </div>
    }
}