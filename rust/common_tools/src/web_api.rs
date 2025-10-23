use serde::{Deserialize, Serialize};
use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use axum::response::{AppendHeaders};
use axum::http::{header, HeaderValue};
use crate::network_utils::NetworkUtils;
use crate::packet_analyzer::PacketAnalyzer;
use crate::regex_matcher::RegexMatcher;
use crate::md5_utils::{Md5Request, process_md5_request};

#[derive(Serialize, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            timestamp: chrono::Utc::now(),
        }
    }

    fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
            timestamp: chrono::Utc::now(),
        }
    }
}

// 网络工具请求/响应结构
#[derive(Deserialize)]
struct NetworkConvertRequest {
    value: String,
    conversion_type: String, // "ip_to_network", "ip_to_host", "port_to_network", "port_to_host", "int_to_network", "int_to_host"
}

#[derive(Serialize)]
struct NetworkConvertResponse {
    input: String,
    result: String,
    conversion_type: String,
}

// 报文分析请求/响应结构
#[derive(Deserialize)]
struct PacketAnalyzeRequest {
    hex_data: String,
}

#[derive(Serialize)]
struct PacketAnalyzeResponse {
    hex_data: String,
    analysis: String,
    packet_length: usize,
}

// 正则匹配请求/响应结构
#[derive(Deserialize)]
struct RegexMatchRequest {
    pattern: String,
    test_string: String,
    case_sensitive: bool,
    multi_line: bool,
    dot_all: bool,
}

#[derive(Serialize)]
struct RegexMatchResponse {
    pattern: String,
    test_string: String,
    match_count: usize,
    matches: Vec<MatchResult>,
}

#[derive(Serialize)]
struct MatchResult {
    position: (usize, usize),
    matched_text: String,
    groups: Vec<String>,
}

pub fn create_network_routes() -> Router {
    Router::new()
        .route("/convert", post(network_convert))
}

pub fn create_packet_routes() -> Router {
    Router::new()
        .route("/analyze", post(packet_analyze))
        .route("/export", post(packet_export))
        .route("/download", post(packet_download))
}

pub fn create_regex_routes() -> Router {
    Router::new()
        .route("/match", post(regex_match))
}

pub fn create_md5_routes() -> Router {
    Router::new()
        .route("/calculate", post(md5_calculate))
}

async fn network_convert(
    Json(request): Json<NetworkConvertRequest>
) -> impl IntoResponse {
    let utils = NetworkUtils::new();
    let result = match request.conversion_type.as_str() {
        "ip_to_network" => utils.ip_to_network_order(&request.value),
        "ip_to_host" => utils.ip_to_host_order(&request.value),
        "port_to_network" => utils.port_to_network_order(&request.value),
        "port_to_host" => utils.port_to_host_order(&request.value),
        "int_to_network" => utils.int_to_network_order(&request.value),
        "int_to_host" => utils.int_to_host_order(&request.value),
        _ => "无效的转换类型".to_string(),
    };

    let response = NetworkConvertResponse {
        input: request.value,
        result,
        conversion_type: request.conversion_type,
    };

    Json(ApiResponse::success(response))
}

async fn packet_analyze(
    Json(request): Json<PacketAnalyzeRequest>
) -> impl IntoResponse {
    let mut analyzer = PacketAnalyzer::new();
    analyzer.set_hex_input(&request.hex_data);
    let analysis = analyzer.analyze_hex();

    let response = PacketAnalyzeResponse {
        hex_data: request.hex_data,
        analysis,
        packet_length: analyzer.get_packet_length(),
    };

    Json(ApiResponse::success(response))
}

async fn packet_export(
    Json(request): Json<PacketAnalyzeRequest>
) -> impl IntoResponse {
    let mut analyzer = PacketAnalyzer::new();
    analyzer.set_hex_input(&request.hex_data);

    match analyzer.export_pcap("packet.pcap") {
        Ok(_) => {
            Json(ApiResponse::success(serde_json::json!({
                "message": "PCAP 文件导出成功",
                "filename": "packet.pcap"
            })))
        }
        Err(e) => {
            Json(ApiResponse::<serde_json::Value>::error(e.to_string()))
        }
    }
}

async fn packet_download(
    Json(request): Json<PacketAnalyzeRequest>
) -> impl IntoResponse {
    let mut analyzer = PacketAnalyzer::new();
    analyzer.set_hex_input(&request.hex_data);

    match analyzer.export_pcap_bytes() {
        Ok(pcap_data) => {
            let headers = AppendHeaders([
                (header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream")),
                (header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment; filename=packet.pcap")),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
            ]);
            (headers, pcap_data).into_response()
        }
        Err(e) => {
            let error_response = ApiResponse::<serde_json::Value>::error(e.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_response)).into_response()
        }
    }
}

async fn regex_match(
    Json(request): Json<RegexMatchRequest>
) -> impl IntoResponse {
    let mut matcher = RegexMatcher::new();
    matcher.set_pattern(&request.pattern);
    matcher.set_test_string(&request.test_string);
    matcher.set_case_sensitive(request.case_sensitive);
    matcher.set_multi_line(request.multi_line);
    matcher.set_dot_all(request.dot_all);

    let results = matcher.perform_match();
    let matches: Vec<MatchResult> = results.iter().map(|(pos, text, groups)| {
        MatchResult {
            position: *pos,
            matched_text: text.clone(),
            groups: groups.clone(),
        }
    }).collect();

    let response = RegexMatchResponse {
        pattern: request.pattern,
        test_string: request.test_string,
        match_count: matches.len(),
        matches,
    };

    Json(ApiResponse::success(response))
}

async fn md5_calculate(
    Json(request): Json<Md5Request>
) -> impl IntoResponse {
    let response = process_md5_request(request);
    Json(ApiResponse::success(response))
}