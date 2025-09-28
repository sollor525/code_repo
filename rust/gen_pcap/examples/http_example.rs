use gen_pcap::{
    HttpRequest, HttpResponse, HttpMethod, HttpVersion, HttpStatusCode,
    build_http_get_packet, build_http_post_packet, build_http_response_packet_simple,
    build_http_request_packet, build_http_response_packet
};
use pnet::packet::tcp::TcpFlags;
use std::net::Ipv4Addr;

fn main() {
    // 网络配置
    const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const DST_MAC: [u8; 6] = [0xe2, 0xc9, 0xfc, 0xf5, 0x9e, 0x3c];
    const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 10, 1, 100);
    const DST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const SRC_PORT: u16 = 12345;
    const DST_PORT: u16 = 8080;

    println!("=== HTTP 报文构造示例 ===\n");

    // 示例1: 构建简单的GET请求
    println!("1. 构建简单的GET请求:");
    let get_packet = build_http_get_packet(
        SRC_MAC, DST_MAC, SRC_IP, DST_IP,
        SRC_PORT, DST_PORT,
        1000, 2000, TcpFlags::ACK,
        "/api/users", "api.example.com"
    );
    println!("   GET包大小: {} 字节", get_packet.len());

    // 示例2: 构建POST请求
    println!("\n2. 构建POST请求:");
    let post_data = b"{\"name\": \"Alice\", \"age\": 30}";
    let post_packet = build_http_post_packet(
        SRC_MAC, DST_MAC, SRC_IP, DST_IP,
        SRC_PORT, DST_PORT,
        1000, 2000, TcpFlags::ACK,
        "/api/users", "api.example.com",
        "application/json", post_data
    );
    println!("   POST包大小: {} 字节", post_packet.len());

    // 示例3: 构建HTTP响应
    println!("\n3. 构建HTTP响应:");
    let response_packet = build_http_response_packet_simple(
        DST_MAC, SRC_MAC, DST_IP, SRC_IP,
        DST_PORT, SRC_PORT,
        2000, 1000, TcpFlags::ACK,
        HttpStatusCode::Ok,
        "application/json",
        b"{\"status\": \"success\", \"data\": []}"
    );
    println!("   响应包大小: {} 字节", response_packet.len());

    // 示例4: 使用高级API构建自定义请求
    println!("\n4. 构建自定义HTTP请求:");
    let custom_request = HttpRequest::new(HttpMethod::PUT, "/api/users/123".to_string())
        .with_version(HttpVersion::Http1_1)
        .add_header("Host".to_string(), "api.example.com".to_string())
        .add_header("Authorization".to_string(), "Bearer token123".to_string())
        .add_header("Content-Type".to_string(), "application/json".to_string())
        .with_body(b"{\"name\": \"Bob\", \"email\": \"bob@example.com\"}".to_vec());

    let custom_packet = build_http_request_packet(
        SRC_MAC, DST_MAC, SRC_IP, DST_IP,
        SRC_PORT, DST_PORT,
        1000, 2000, TcpFlags::ACK,
        &custom_request
    );
    println!("   自定义请求包大小: {} 字节", custom_packet.len());

    // 示例5: 构建自定义响应
    println!("\n5. 构建自定义HTTP响应:");
    let custom_response = HttpResponse::new(HttpStatusCode::NotFound)
        .with_version(HttpVersion::Http1_1)
        .add_header("Server".to_string(), "nginx/1.18.0".to_string())
        .add_header("Content-Type".to_string(), "text/html".to_string())
        .with_body(b"<html><body><h1>404 Not Found</h1></body></html>".to_vec());

    let custom_response_packet = build_http_response_packet(
        DST_MAC, SRC_MAC, DST_IP, SRC_IP,
        DST_PORT, SRC_PORT,
        2000, 1000, TcpFlags::ACK,
        &custom_response
    );
    println!("   自定义响应包大小: {} 字节", custom_response_packet.len());

    // 示例6: 显示HTTP报文内容
    println!("\n6. HTTP GET请求内容:");
    let http_data = custom_request.to_bytes();
    if let Ok(http_str) = std::str::from_utf8(&http_data) {
        println!("{}", http_str);
    }

    println!("\n7. HTTP响应内容:");
    let response_data = custom_response.to_bytes();
    if let Ok(response_str) = std::str::from_utf8(&response_data) {
        println!("{}", response_str);
    }

    println!("\n=== 示例完成 ===");
}
