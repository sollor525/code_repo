//! 内嵌 Web 服务：路由 + 处理器 + 编译期嵌入的静态资源。
//!
//! 静态资源通过 `include_str!` 嵌入二进制，使桌面版成为单文件可执行程序，
//! 无需随附 static/ 目录即可运行。

use axum::{
    extract::{Path, Request},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::license;
use crate::web_api;

// ---- 编译期嵌入的前端资源（路径相对本文件：src-tauri/src/）----
const INDEX_HTML: &str = include_str!("../../static/index.html");
const NETWORK_HTML: &str = include_str!("../../static/network.html");
const PACKET_HTML: &str = include_str!("../../static/packet.html");
const REGEX_HTML: &str = include_str!("../../static/regex.html");
const MD5_HTML: &str = include_str!("../../static/md5.html");
const STRING_HTML: &str = include_str!("../../static/string.html");
const PCAPGEN_HTML: &str = include_str!("../../static/pcapgen.html");
const CRON_HTML: &str = include_str!("../../static/cron.html");
const BASE64_HTML: &str = include_str!("../../static/base64.html");
const JSON_HTML: &str = include_str!("../../static/json.html");
const PCAPEDIT_HTML: &str = include_str!("../../static/pcapedit.html");
const STYLE_CSS: &str = include_str!("../../static/style.css");
const API_MD: &str = include_str!("../../static/API.md");

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

/// 构建完整的应用路由（API + 页面 + 静态资源）。
pub fn create_router() -> Router {
    Router::new()
        .nest("/api", api_routes())
        .route("/health", get(health_check))
        .route("/api", get(api_info))
        .route("/static/*file_path", get(serve_static_file))
        .route("/network.html", get(|| async { Html(NETWORK_HTML) }))
        .route("/packet.html", get(|| async { Html(PACKET_HTML) }))
        .route("/regex.html", get(|| async { Html(REGEX_HTML) }))
        .route("/md5.html", get(|| async { Html(MD5_HTML) }))
        .route("/string.html", get(|| async { Html(STRING_HTML) }))
        .route("/pcapgen.html", get(|| async { Html(PCAPGEN_HTML) }))
        .route("/cron.html", get(|| async { Html(CRON_HTML) }))
        .route("/base64.html", get(|| async { Html(BASE64_HTML) }))
        .route("/json.html", get(|| async { Html(JSON_HTML) }))
        .route("/pcapedit.html", get(|| async { Html(PCAPEDIT_HTML) }))
        .route("/", get(|| async { Html(INDEX_HTML) }))
        .fallback(|| async { (StatusCode::NOT_FOUND, "页面未找到") })
        // 有效期拦截：过期后所有请求（页面 / 静态资源 / API）统一返回停用页
        .layer(middleware::from_fn(license_guard))
}

/// 软件有效期中间件：过期即对全部路由返回「已停用」页面。
async fn license_guard(req: Request, next: Next) -> Response {
    if license::is_expired() {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            license::expired_html(),
        )
            .into_response();
    }
    next.run(req).await
}

fn api_routes() -> Router {
    Router::new()
        .nest("/network", web_api::create_network_routes())
        .nest("/packet", web_api::create_packet_routes())
        .nest("/regex", web_api::create_regex_routes())
        .nest("/md5", web_api::create_md5_routes())
        .nest("/string", web_api::create_string_routes())
        .nest("/pcap", web_api::create_pcap_routes())
        .nest("/cron", web_api::create_cron_routes())
        .nest("/base64", web_api::create_base64_routes())
        .nest("/json", web_api::create_json_routes())
        .nest("/pcapedit", web_api::create_pcapedit_routes())
        .route("/license", get(license_info))
}

/// 授权状态（供前端展示有效期）。过期时本路由已被 license_guard 拦截。
async fn license_info() -> impl IntoResponse {
    let s = license::status();
    Json(serde_json::json!({
        "build_date": s.build_ymd(),
        "expiry_date": s.expiry_ymd(),
        "days_left": s.days_left,
        "expired": s.expired,
        "contact": license::CONTACT_EMAIL,
    }))
}

async fn health_check() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        service: "common_tools".to_string(),
    })
}

async fn api_info() -> impl IntoResponse {
    Json(ApiInfoResponse {
        name: "开发辅助工具 Web API".to_string(),
        version: "0.1.0".to_string(),
        endpoints: serde_json::json!({
            "health": "/health",
            "network": "/api/network",
            "packet": "/api/packet",
            "regex": "/api/regex",
            "md5": "/api/md5",
            "string": "/api/string",
            "pcap": "/api/pcap",
            "cron": "/api/cron",
            "base64": "/api/base64",
            "json": "/api/json",
            "pcapedit": "/api/pcapedit",
            "license": "/api/license"
        }),
        description: "A collection of common utility tools for developers".to_string(),
    })
}

/// 从嵌入资源中按名提供 /static/* 文件。
async fn serve_static_file(Path(file_path): Path<String>) -> Response {
    let content: Option<&'static str> = match file_path.as_str() {
        "style.css" => Some(STYLE_CSS),
        "API.md" => Some(API_MD),
        "index.html" => Some(INDEX_HTML),
        "network.html" => Some(NETWORK_HTML),
        "packet.html" => Some(PACKET_HTML),
        "regex.html" => Some(REGEX_HTML),
        "md5.html" => Some(MD5_HTML),
        "string.html" => Some(STRING_HTML),
        "pcapgen.html" => Some(PCAPGEN_HTML),
        "cron.html" => Some(CRON_HTML),
        "base64.html" => Some(BASE64_HTML),
        "json.html" => Some(JSON_HTML),
        "pcapedit.html" => Some(PCAPEDIT_HTML),
        _ => None,
    };

    match content {
        Some(text) => {
            let mime_type = mime_guess::from_path(&file_path)
                .first_or_octet_stream()
                .to_string();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime_type)
                .header(header::CACHE_CONTROL, "no-cache")
                .body(axum::body::Body::from(text))
                .unwrap()
        }
        None => (StatusCode::NOT_FOUND, "文件未找到").into_response(),
    }
}
