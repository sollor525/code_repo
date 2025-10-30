// HTTP流量实现

use crate::core::session::TcpSession;
use crate::tcp::build_tcp_packet_with_data;
use crate::tcp::packet::TcpPacketWithDataParams;
use super::request::{HttpRequest, HttpMethod};
use super::response::{HttpResponse, HttpStatusCode};
use std::net::Ipv4Addr;

// HTTP流量实现的具体逻辑
pub struct HttpFlowImplementation;

impl HttpFlowImplementation {
    pub fn generate_packets(uris: &[String], host: &str, session: &TcpSession) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();

        // 首先生成TCP三次握手包
        let (handshake_packets, mut conn) = crate::tcp::build_tcp_handshake_packets(
            session.connection.src_mac,
            session.connection.dst_mac,
            session.connection.src_ip,
            session.connection.dst_ip,
            session.connection.src_port,
            session.connection.dst_port,
            session.isn
        );
        packets.extend(handshake_packets);

        // 使用握手后的连接状态继续生成HTTP流量

        for (i, uri) in uris.iter().enumerate() {
            // HTTP GET请求
            let (client_seq, client_ack) = conn.get_seq_ack(true);
            let http_get = build_http_get_packet(
                session.connection.src_mac, session.connection.dst_mac,
                session.connection.src_ip, session.connection.dst_ip,
                session.connection.src_port, session.connection.dst_port,
                client_seq, client_ack,
                pnet::packet::tcp::TcpFlags::PSH,
                uri, host
            );
            let get_data_len = http_get.len() as u32 - 54;
            packets.push(http_get);
            conn.update_seq(true, get_data_len);

            // HTTP GET响应
            let (server_seq, server_ack) = conn.get_seq_ack(false);
            let response_body = format!(r#"{{"request": "{}", "session_id": "{}"}}"#, uri, i).into_bytes();
            let http_response = build_http_response_packet_simple(
                session.connection.dst_mac, session.connection.src_mac,
                session.connection.dst_ip, session.connection.src_ip,
                session.connection.dst_port, session.connection.src_port,
                server_seq, server_ack,
                pnet::packet::tcp::TcpFlags::ACK | pnet::packet::tcp::TcpFlags::PSH,
                HttpStatusCode::Ok, "application/json", &response_body
            );
            let response_data_len = http_response.len() as u32 - 54;
            packets.push(http_response);
            conn.update_seq(false, response_data_len);
            conn.update_ack(false, get_data_len);
        }
        packets
    }
}

// 便利函数：构建简单的HTTP GET请求包
#[allow(clippy::too_many_arguments)]
pub fn build_http_get_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    uri: &str,
    host: &str,
) -> Vec<u8> {
    let request = HttpRequest::new(HttpMethod::GET, uri.to_string())
        .add_header("Host".to_string(), host.to_string())
        .add_header("Connection".to_string(), "close".to_string());

    build_http_request_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, &request)
}

// 便利函数：构建简单的HTTP POST请求包
#[allow(clippy::too_many_arguments)]
pub fn build_http_post_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    uri: &str,
    host: &str,
    content_type: &str,
    body: &[u8],
) -> Vec<u8> {
    let request = HttpRequest::new(HttpMethod::POST, uri.to_string())
        .add_header("Host".to_string(), host.to_string())
        .add_header("Content-Type".to_string(), content_type.to_string())
        .add_header("Connection".to_string(), "close".to_string())
        .with_body(body.to_vec());

    build_http_request_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, &request)
}

// 便利函数：构建HTTP响应包
#[allow(clippy::too_many_arguments)]
pub fn build_http_response_packet_simple(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    status_code: HttpStatusCode,
    content_type: &str,
    body: &[u8],
) -> Vec<u8> {
    let response = HttpResponse::new(status_code)
        .add_header("Content-Type".to_string(), content_type.to_string())
        .add_header("Connection".to_string(), "close".to_string())
        .with_body(body.to_vec());

    build_http_response_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, &response)
}

// 构建包含HTTP请求的TCP包
#[allow(clippy::too_many_arguments)]
pub fn build_http_request_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    http_request: &HttpRequest,
) -> Vec<u8> {
    let http_data = http_request.to_bytes();
    build_tcp_packet_with_data(TcpPacketWithDataParams::new(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, http_data
    ))
}

// 构建包含HTTP响应的TCP包
#[allow(clippy::too_many_arguments)]
pub fn build_http_response_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u16,
    http_response: &HttpResponse,
) -> Vec<u8> {
    let http_data = http_response.to_bytes();
    build_tcp_packet_with_data(TcpPacketWithDataParams::new(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, http_data
    ))
}