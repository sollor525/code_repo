use serde::{Deserialize, Serialize};
use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use axum::response::{AppendHeaders};
use axum::http::{header, HeaderName, HeaderValue};
use crate::network_utils::NetworkUtils;
use crate::packet_analyzer::PacketAnalyzer;
use crate::pcap_generator::{generate_pcap, PcapGenParams};
use crate::regex_matcher::RegexMatcher;
use crate::md5_utils::{Md5Request, Md5Response, process_md5_request, process_md5_bytes};
use crate::string_converter::{StringConvertRequest, StringConvertResponse, process_string_conversion};

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

pub fn create_pcap_routes() -> Router {
    Router::new()
        .route("/generate", post(pcap_generate))
}

pub fn create_regex_routes() -> Router {
    Router::new()
        .route("/match", post(regex_match))
}

pub fn create_md5_routes() -> Router {
    Router::new()
        .route("/calculate", post(md5_calculate))
        // 文件 MD5：前端直接上传文件字节（浏览器拿不到本地真实路径），
        // 解除默认 2MB 请求体上限，以支持较大文件。
        .route(
            "/calculate_file",
            post(md5_calculate_file).layer(DefaultBodyLimit::disable()),
        )
}

pub fn create_string_routes() -> Router {
    Router::new()
        .route("/convert", post(string_convert))
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

// ============================  PCAP 流量生成  ============================
fn default_sessions() -> u32 { 1 }
fn default_src_ip() -> String { "10.10.1.100".to_string() }
fn default_dst_ip() -> String { "192.168.1.100".to_string() }
fn default_src_port() -> String { "30000-40000".to_string() }
fn default_dst_port() -> String { "80".to_string() }
fn default_http_host() -> String { "example.com".to_string() }
fn default_protocol() -> String { "tcp".to_string() }
fn default_tcp_mode() -> String { "handshake".to_string() }
fn default_ftp_mode() -> String { "passive".to_string() }
fn default_icmp_count() -> u32 { 1 }

#[derive(Deserialize)]
struct PcapGenerateRequest {
    #[serde(default = "default_sessions")]
    session_count: u32,
    #[serde(default = "default_src_ip")]
    src_ip: String,
    #[serde(default = "default_dst_ip")]
    dst_ip: String,
    #[serde(default = "default_src_port")]
    src_port: String,
    #[serde(default = "default_dst_port")]
    dst_port: String,
    #[serde(default = "default_protocol")]
    protocol: String,
    #[serde(default = "default_tcp_mode")]
    tcp_mode: String,
    #[serde(default = "default_http_host")]
    http_host: String,
    #[serde(default)]
    http_uris: Vec<String>,
    #[serde(default)]
    http_request: Option<String>,
    #[serde(default)]
    http_response: Option<String>,
    #[serde(default = "default_icmp_count")]
    icmp_count: u32,
    #[serde(default)]
    udp_payload: String,
    #[serde(default)]
    udp_response: bool,
    #[serde(default = "default_ftp_mode")]
    ftp_mode: String,
    #[serde(default)]
    vlan_id: Option<u16>,
    #[serde(default)]
    vlan_priority: u8,
    #[serde(default)]
    vlan_dei: bool,
    #[serde(default)]
    qinq: bool,
    #[serde(default)]
    outer_vlan: Option<u16>,
    #[serde(default)]
    inner_vlan: Option<u16>,
    #[serde(default)]
    outer_priority: u8,
    #[serde(default)]
    inner_priority: u8,
}

async fn pcap_generate(
    Json(request): Json<PcapGenerateRequest>
) -> impl IntoResponse {
    let params = PcapGenParams {
        session_count: request.session_count,
        src_ip: request.src_ip,
        dst_ip: request.dst_ip,
        src_port: request.src_port,
        dst_port: request.dst_port,
        protocol: request.protocol,
        tcp_mode: request.tcp_mode,
        http_host: request.http_host,
        http_uris: request.http_uris,
        http_request: request.http_request,
        http_response: request.http_response,
        icmp_count: request.icmp_count,
        udp_payload: request.udp_payload,
        udp_response: request.udp_response,
        ftp_mode: request.ftp_mode,
        vlan_id: request.vlan_id,
        vlan_priority: request.vlan_priority,
        vlan_dei: request.vlan_dei,
        qinq: request.qinq,
        outer_vlan: request.outer_vlan,
        inner_vlan: request.inner_vlan,
        outer_priority: request.outer_priority,
        inner_priority: request.inner_priority,
    };

    match generate_pcap(&params) {
        Ok(result) => {
            let headers = AppendHeaders([
                (header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream")),
                (header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment; filename=generated.pcap")),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
                (HeaderName::from_static("x-session-count"),
                 HeaderValue::from_str(&result.session_count.to_string()).unwrap()),
                (HeaderName::from_static("x-packet-count"),
                 HeaderValue::from_str(&result.packet_count.to_string()).unwrap()),
                (HeaderName::from_static("x-flow"),
                 HeaderValue::from_str(&result.flow).unwrap_or(HeaderValue::from_static(""))),
            ]);
            (headers, result.pcap).into_response()
        }
        Err(e) => {
            let error_response = ApiResponse::<serde_json::Value>::error(e);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
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

/// 文件 MD5：请求体即文件原始字节，直接对内容求 MD5。
async fn md5_calculate_file(body: Bytes) -> impl IntoResponse {
    if body.is_empty() {
        return Json(ApiResponse::<Md5Response>::error("未接收到文件内容".to_string()));
    }
    Json(ApiResponse::success(process_md5_bytes(&body)))
}

async fn string_convert(
    Json(request): Json<StringConvertRequest>
) -> impl IntoResponse {
    match process_string_conversion(request) {
        Ok(response) => Json(ApiResponse::success(response)).into_response(),
        Err(error) => {
            let error_response = ApiResponse::<StringConvertResponse>::error(error);
            (StatusCode::BAD_REQUEST, Json(error_response)).into_response()
        }
    }
}