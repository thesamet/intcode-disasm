use leptos::*;
use leptos_meta::*;
use leptos_router::*;

mod analysis;
mod components;
mod demo;
mod pages;

use pages::*;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/web-ui.css"/>
        <Title text="Disasm Web UI"/>

        <Router>
            <main>
                <Routes>
                    <Route path="" view=FunctionPage/>
                    <Route path="/analyze" view=AnalyzePage/>
                    <Route path="/function/:id" view=FunctionPage/>
                    <Route path="/function" view=FunctionPage/>
                    <Route path="/home" view=HomePage/>
                    <Route path="/types" view=TypesPage/>
                </Routes>
            </main>
        </Router>
    }
}

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    console_log::init_with_level(log::Level::Debug).expect("error initializing logger");
    
    leptos::mount_to_body(App)
}