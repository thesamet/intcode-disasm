use leptos::*;
use leptos_router::*;

#[component]
pub fn HomePage() -> impl IntoView {
    view! {
        <div class="container">
            <header class="hero">
                <h1>"Disasm Web UI"</h1>
                <p class="subtitle">"Interactive exploration of decompiled Intcode programs"</p>
            </header>

            <div class="features">
                <div class="feature-card">
                    <h3>"📁 Load Program"</h3>
                    <p>"Upload or paste Intcode bytecode to begin analysis"</p>
                    <A href="/analyze" class="btn-primary">"Start Analysis"</A>
                </div>

                <div class="feature-card">
                    <h3>"🔍 Explore Types"</h3>
                    <p>"Interactive type inference visualization"</p>
                    <A href="/types" class="btn-secondary">"View Types"</A>
                </div>

                <div class="feature-card">
                    <h3>"🏗️ Function View"</h3>
                    <p>"Navigate through decompiled functions"</p>
                    <A href="/function/0" class="btn-secondary">"Browse Functions"</A>
                </div>
            </div>

            <div class="info">
                <h2>"Key Features"</h2>
                <ul>
                    <li>"🎯 Type inference exploration with step-by-step history"</li>
                    <li>"📊 Interactive constraint graph visualization"</li>
                    <li>"🔗 Function call analysis and navigation"</li>
                    <li>"🎨 Syntax highlighting with type annotations"</li>
                    <li>"⚡ Real-time analysis powered by Rust + WebAssembly"</li>
                </ul>
            </div>
        </div>
    }
}