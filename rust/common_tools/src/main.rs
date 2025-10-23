mod network_utils;
mod packet_analyzer;
mod regex_matcher;
mod md5_utils;
mod web_api;

use axum::{
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

use clap::Parser;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "common_tools")]
#[command(about = "A collection of common utility tools as a web service")]
#[command(version = "0.1.0")]
struct Args {
    /// Server port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Server host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
}

#[derive(Clone)]
struct AppState {
    // 可以在这里添加共享状态
}

#[derive(Serialize, Deserialize, Debug)]
struct HealthResponse {
    status: String,
    timestamp: String,
    service: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct ApiInfoResponse {
    name: String,
    version: String,
    endpoints: serde_json::Value,
    description: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    // 设置日志级别
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }

    info!("启动开发者工具箱 Axum 服务");
    info!("服务器启动在 http://{}:{}", args.host, args.port);

    // 创建应用状态
    let app_state = Arc::new(AppState {});

    // 创建路由
    let app = create_router(app_state);

    // 启动服务器
    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    info!("服务器正在监听: {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

fn create_router(app_state: Arc<AppState>) -> Router {
    Router::new()
        // API路由
        .nest("/api", create_api_routes(app_state.clone()))
        // 健康检查
        .route("/health", get(health_check))
        // API信息
        .route("/api", get(api_info))
        // 静态文件服务
        .route("/static/*file_path", get(serve_static_file))
        // 静态页面路由
        .route("/network.html", get(serve_network_page))
        .route("/packet.html", get(serve_packet_page))
        .route("/regex.html", get(serve_regex_page))
        .route("/md5.html", get(serve_md5_page))
        // 默认路由 - 重定向到index.html
        .route("/", get(|| async {
            axum::response::Html(
                std::fs::read_to_string("static/index.html")
                    .unwrap_or_else(|_| "<h1>服务正在启动...</h1>".to_string())
            )
        }))
        .fallback(|| async {
            (StatusCode::NOT_FOUND, "页面未找到")
        })
}

fn create_api_routes(_app_state: Arc<AppState>) -> Router {
    Router::new()
        .nest("/network", web_api::create_network_routes())
        .nest("/packet", web_api::create_packet_routes())
        .nest("/regex", web_api::create_regex_routes())
        .nest("/md5", web_api::create_md5_routes())
}

async fn health_check() -> impl IntoResponse {
    let response = HealthResponse {
        status: "ok".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        service: "common_tools".to_string(),
    };
    Json(response)
}

async fn api_info() -> impl IntoResponse {
    let response = ApiInfoResponse {
        name: "开发者工具箱 Web API".to_string(),
        version: "0.1.0".to_string(),
        endpoints: serde_json::json!({
            "health": "/health",
            "network": "/api/network",
            "packet": "/api/packet",
            "regex": "/api/regex",
            "md5": "/api/md5"
        }),
        description: "A collection of common utility tools for developers".to_string(),
    };
    Json(response)
}

// 静态文件处理函数
async fn serve_static_file(Path(file_path): Path<String>) -> impl IntoResponse {
    let path = format!("static/{}", file_path);

    match std::fs::read(&path) {
        Ok(contents) => {
            let mime_type = mime_guess::from_path(&path)
                .first_or_octet_stream()
                .to_string();

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime_type)
                .header(header::CACHE_CONTROL, "no-cache")
                .body(axum::body::Body::from(contents))
                .unwrap()
        }
        Err(_) => {
            (StatusCode::NOT_FOUND, "文件未找到").into_response()
        }
    }
}

async fn serve_network_page() -> impl IntoResponse {
    match std::fs::read_to_string("static/network.html") {
        Ok(contents) => axum::response::Html(contents).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "页面未找到").into_response(),
    }
}

async fn serve_packet_page() -> impl IntoResponse {
    match std::fs::read_to_string("static/packet.html") {
        Ok(contents) => axum::response::Html(contents).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "页面未找到").into_response(),
    }
}

async fn serve_regex_page() -> impl IntoResponse {
    match std::fs::read_to_string("static/regex.html") {
        Ok(contents) => axum::response::Html(contents).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "页面未找到").into_response(),
    }
}

async fn serve_md5_page() -> impl IntoResponse {
    match std::fs::read_to_string("static/md5.html") {
        Ok(contents) => axum::response::Html(contents).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "页面未找到").into_response(),
    }
}