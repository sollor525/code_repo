use serde::{Deserialize, Serialize};
use warp::Filter;
use crate::network_utils::NetworkUtils;
use crate::packet_analyzer::PacketAnalyzer;
use crate::regex_matcher::RegexMatcher;

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

pub fn create_routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let network_routes = create_network_routes();
    let packet_routes = create_packet_routes();
    let regex_routes = create_regex_routes();

    network_routes.or(packet_routes).or(regex_routes)
}

fn create_network_routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let network_convert = warp::path!("api" / "network" / "convert")
        .and(warp::post())
        .and(warp::body::json::<NetworkConvertRequest>())
        .map(|request: NetworkConvertRequest| {
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

            warp::reply::json(&ApiResponse::success(response))
        });

    network_convert
}

fn create_packet_routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let packet_analyze = warp::path!("api" / "packet" / "analyze")
        .and(warp::post())
        .and(warp::body::json::<PacketAnalyzeRequest>())
        .map(|request: PacketAnalyzeRequest| {
            let mut analyzer = PacketAnalyzer::new();
            analyzer.set_hex_input(&request.hex_data);
            let analysis = analyzer.analyze_hex();

            let response = PacketAnalyzeResponse {
                hex_data: request.hex_data,
                analysis,
                packet_length: analyzer.get_packet_length(),
            };

            warp::reply::json(&ApiResponse::success(response))
        });

    let packet_export = warp::path!("api" / "packet" / "export")
        .and(warp::post())
        .and(warp::body::json::<PacketAnalyzeRequest>())
        .map(|request: PacketAnalyzeRequest| {
            let mut analyzer = PacketAnalyzer::new();
            analyzer.set_hex_input(&request.hex_data);

            match analyzer.export_pcap("packet.pcap") {
                Ok(_) => {
                    warp::reply::json(&ApiResponse::success(serde_json::json!({
                        "message": "PCAP 文件导出成功",
                        "filename": "packet.pcap"
                    })))
                }
                Err(e) => {
                    warp::reply::json(&ApiResponse::<serde_json::Value>::error(e.to_string()))
                }
            }
        });

    let packet_download = warp::path!("api" / "packet" / "download")
        .and(warp::post())
        .and(warp::body::json::<PacketAnalyzeRequest>())
        .map(|request: PacketAnalyzeRequest| {
            let mut analyzer = PacketAnalyzer::new();
            analyzer.set_hex_input(&request.hex_data);

            match analyzer.export_pcap_bytes() {
                Ok(pcap_data) => {
                    // 使用 Box<dyn warp::Reply> 来处理不同类型
                    let response: Box<dyn warp::Reply> = Box::new(
                        warp::reply::with_header(
                            warp::reply::with_header(
                                warp::reply::with_header(pcap_data, "content-type", "application/octet-stream"),
                                "content-disposition", "attachment; filename=packet.pcap"
                            ),
                            "cache-control", "no-cache"
                        )
                    );
                    response
                }
                Err(e) => {
                    let error_response = warp::reply::json(&ApiResponse::<serde_json::Value>::error(e.to_string()));
                    let response: Box<dyn warp::Reply> = Box::new(
                        warp::reply::with_status(error_response, warp::http::StatusCode::INTERNAL_SERVER_ERROR)
                    );
                    response
                }
            }
        });

    packet_analyze.or(packet_export).or(packet_download)
}

fn create_regex_routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let regex_match = warp::path!("api" / "regex" / "match")
        .and(warp::post())
        .and(warp::body::json::<RegexMatchRequest>())
        .map(|request: RegexMatchRequest| {
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

            warp::reply::json(&ApiResponse::success(response))
        });

    regex_match
}