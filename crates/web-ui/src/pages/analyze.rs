use leptos::*;

#[component]
pub fn AnalyzePage() -> impl IntoView {

    view! {
        <div class="container">
            <h1>"Analyze Program"</h1>
            
            <div class="input-section">
                <h2>"Server Information"</h2>
                
                <div class="server-info">
                    <p>"This web UI displays analysis results for a program that was loaded when the server started."</p>
                    <p>"To analyze a different program, restart the server with:"</p>
                    <pre class="command-example">cargo run -p analysis-server &lt;your_intcode_file&gt;</pre>
                    <p>"Navigate to the Function and Types pages to explore the analysis results."</p>
                </div>
            </div>

        </div>
    }
}