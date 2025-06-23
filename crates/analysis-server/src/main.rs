// Analysis server that loads a specific file and serves analysis results
use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use clap::Parser;
use serde::Serialize;
use std::sync::OnceLock;
use tower_http::{cors::CorsLayer, services::ServeDir};
use web_bridge::{analyze_program_for_web_with_symbols, WebAnalysisResult};

// Global state to hold the analysis result
static ANALYSIS_RESULT: OnceLock<WebAnalysisResult> = OnceLock::new();

#[derive(Serialize)]
struct AnalysisResponse {
    result: WebAnalysisResult,
}

async fn get_analysis() -> Result<Json<AnalysisResponse>, StatusCode> {
    match ANALYSIS_RESULT.get() {
        Some(result) => Ok(Json(AnalysisResponse { result: result.clone() })),
        None => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn health_handler() -> &'static str {
    "Analysis server is running!"
}

#[derive(Parser)]
#[command(name = "analysis-server")]
#[command(about = "Analysis server that loads an Intcode file and serves analysis results")]
struct Args {
    /// Path to the Intcode program file
    input: String,
    
    /// Path to symbols file for enhanced analysis
    #[arg(long, help = "Symbol renaming rules file")]
    symbols: Option<String>,
}

fn load_program_from_file(file_path: &str) -> Result<Vec<i128>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(file_path)?;
    let program: Vec<i128> = content
        .split(',')
        .map(|s| s.trim().parse::<i128>())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(program)
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    
    // Load and analyze the program
    println!("📂 Loading program from: {}", args.input);
    let program = match load_program_from_file(&args.input) {
        Ok(prog) => {
            println!("✅ Loaded {} instructions", prog.len());
            prog
        }
        Err(e) => {
            eprintln!("❌ Failed to load program: {e}");
            std::process::exit(1);
        }
    };
    
    // Load symbols if provided
    let symbols_content = if let Some(symbols_file) = &args.symbols {
        println!("📋 Loading symbols from: {symbols_file}");
        match std::fs::read_to_string(symbols_file) {
            Ok(content) => {
                println!("✅ Loaded symbols file");
                Some(content)
            }
            Err(e) => {
                eprintln!("❌ Failed to load symbols file: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    
    // Run analysis
    println!("🔍 Running disasm analysis...");
    let analysis_result = match analyze_program_for_web_with_symbols(program, symbols_content) {
        Ok(result) => {
            println!("✅ Analysis complete:");
            println!("   📊 Functions: {}", result.functions.len());
            println!("   📏 Program size: {}", result.program_size);
            result
        }
        Err(e) => {
            eprintln!("❌ Analysis failed: {e}");
            std::process::exit(1);
        }
    };
    
    // Store the result globally
    ANALYSIS_RESULT.set(analysis_result).unwrap();
    
    // Build our application with routes
    let serve_dir = ServeDir::new("crates/web-ui/dist")
        .fallback(tower::service_fn(|_| async {
            // Serve index.html for SPA routes
            match std::fs::read_to_string("crates/web-ui/dist/index.html") {
                Ok(content) => Ok(axum::response::Html(content).into_response()),
                Err(_) => Ok(StatusCode::NOT_FOUND.into_response()),
            }
        }));
    
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/api/analysis", get(get_analysis))
        .fallback_service(serve_dir)
        .layer(CorsLayer::permissive());

    // Run the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080")
        .await
        .unwrap();
    
    println!("🚀 Analysis server starting on http://127.0.0.1:8080");
    println!("📊 Analysis results available at /api/analysis");
    println!("🌐 Web UI served from /");
    
    axum::serve(listener, app).await.unwrap();
}