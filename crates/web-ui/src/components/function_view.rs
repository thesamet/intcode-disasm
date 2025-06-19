use leptos::*;

#[component]
pub fn FunctionView(
    function_id: u32,
    #[prop(default = true)] show_ssa: bool,
) -> impl IntoView {
    view! {
        <div class="function-view">
            <div class="function-header">
                <h3>"Function " {function_id}</h3>
                <div class="view-toggle">
                    <button class="toggle-btn" class:active=show_ssa>"SSA"</button>
                    <button class="toggle-btn" class:active=move || !show_ssa>"HLR"</button>
                </div>
            </div>
            
            <div class="code-container">
                <Show when=move || show_ssa>
                    <pre class="code-block ssa">
                        <code>
                            "// SSA Form\n"
                            "v0 = input()\n"
                            "v1 = add v0, 42\n"
                            "v2 = mul v1, 2\n"
                            "output(v2)\n"
                        </code>
                    </pre>
                </Show>
                
                <Show when=move || !show_ssa>
                    <pre class="code-block hlr">
                        <code>
                            "// High-Level Representation\n"
                            "input = read_input();\n"
                            "result = (input + 42) * 2;\n"
                            "print(result);\n"
                        </code>
                    </pre>
                </Show>
            </div>
        </div>
    }
}