//! YAML模板引擎
//!
//! 负责根据解析的YAML模板生成实际的网络数据包

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use pnet::packet::tcp::TcpFlags;
use anyhow::{Result, Context, anyhow};
use crate::core::{NetworkConnection, ApplicationFlow, ApplicationFlowType};
use crate::{TcpSession, HttpRequest, HttpResponse, HttpMethod, HttpVersion, HttpStatusCode, SessionTemplate};
use crate::tcp::{build_tcp_handshake_packets};
use crate::session::{TcpSessionConfig, SessionFactory};
use super::{YamlTemplate, TemplateConfig, TemplateError};

/// 模板引擎
pub struct TemplateEngine {
    config: TemplateConfig,
    session_factory: SessionFactory,
}

impl TemplateEngine {
    pub fn new(config: TemplateConfig) -> Self {
        let session_factory = SessionFactory::new();

        if let Some(src_mac) = &config.template.network.src_mac {
            let src_mac = TemplateEngine::parse_mac_address(src_mac)?;
            let dst_mac = config.template.network.dst_mac.as_ref()
                .map(|s| TemplateEngine::parse_mac_address(s).unwrap())
                .unwrap_or_else(|| TemplateEngine::parse_mac_address("e2:c9:fc:f5:9e:3c").unwrap());
            session_factory.with_macs(src_mac, dst_mac);
        }

        Self {
            config,
            session_factory,
        }
    }

    /// 生成所有会话的数据包
    pub fn generate_packets(&self) -> Result<Vec<Vec<u8>>, TemplateError> {
        let mut all_packets = Vec::new();

        for session_template in &self.config.template.sessions {
            let repeat_count = session_template.repeat.unwrap_or(1);

            for i in 0..repeat_count {
                let session = self.create_session(session_template, i)?;
                let packets = self.generate_session_packets(session, session_template)?;
                all_packets.extend(packets);
            }
        }

        Ok(all_packets)
    }

    /// 创建单个会话
    fn create_session(&self, template: &SessionTemplate, index: usize) -> Result<TcpSession, TemplateError> {
        // 处理源地址
        let src_ip = self.resolve_address(&template.connection.src, "src", &template.name, index)?;
        let src_port = self.resolve_port(&template.connection.src, &template.name, index)?;
        let src_mac = self.resolve_mac_address(&template.connection.src, &template.name, index)?;

        // 处理目标地址
        let dst_ip = self.resolve_address(&template.connection.dst, "dst", &template.name, index)?;
        let dst_port = self.resolve_port(&template.connection.dst, &template.name, index)?;
        let dst_mac = self.resolve_mac_address(&template.connection.dst, &template.name, index)?;

        let connection = NetworkConnection::new(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port);
        let isn = (index + 1) as u32 * 1000; // 简单的ISN生成策略

        Ok(TcpSession::new(connection, isn))
    }

    /// 解析IP地址
    fn resolve_address(&self, config: &Option<super::AddressConfig>,
                       field: &str, session_name: &str, index: usize) -> Result<IpAddr, TemplateError> {
        if let Some(config) = config {
            if let Some(ip_str) = &config.ip {
                // 解析IP地址
                Self::parse_ip_address(ip_str)
            } else {
                // 根据会话名称和索引生成IP
                Self::generate_ip_address(session_name, field, index)
            }
        } else {
            // 使用默认策略生成IP
            Self::generate_ip_address(session_name, field, index)
        }
    }

    /// 解析端口
    fn resolve_port(&self, config: &Option<super::AddressConfig>,
                      session_name: &str, index: usize) -> Result<u16, TemplateError> {
        if let Some(config) = config {
            if let Some(port) = config.port {
                // 验证端口
                if port == 0 || port > 65535 {
                    return Err(TemplateError::PortError(format!("无效的端口: {}", port)));
                }
                port
            } else {
                // 根据会话名称和索引生成端口
                Self::generate_port(session_name, index)
            }
        } else {
            // 使用默认策略生成端口
            Self::generate_port(session_name, index)
        }
    }

    /// 解析MAC地址
    fn resolve_mac_address(&self, config: &Option<super::AddressConfig>,
                            session_name: &str, index: usize) -> Result<[u8; 6], TemplateError> {
        if let Some(config) = config {
            if let Some(mac_str) = &config.mac {
                // 解析MAC地址
                TemplateEngine::parse_mac_address(mac_str)
            } else {
                // 使用工厂提供的MAC地址
                    // 这里可以扩展为从MAC池中选择
                    let macs = self.session_factory.get_src_macs();
                    if !macs.is_empty() {
                        let mac_index = index % macs.len();
                        macs[mac_index]
                    } else {
                        // 返回一个默认MAC地址
                        TemplateEngine::parse_mac_address("00:11:22:33:44:55")?
                    }
            }
        } else {
            // 使用工厂提供的MAC地址
            self.session_factory.get_src_mac()
        }
    }

    /// 生成单个会话的数据包
    fn generate_session_packets(&self, session: TcpSession, template: &SessionTemplate) -> Result<Vec<Vec<u8>>, TemplateError> {
        match &template.session_type {
            super::SessionType::Tcp { ports: _, duration_ms: _ } => {
                match &template.application {
                    Some(super::ApplicationConfig::Http { requests, responses, timing: _ }) => {
                        self.generate_http_packets(session, requests, responses)
                    }
                    Some(super::ApplicationConfig::Tcp { data_size, flags }) => {
                        self.generate_tcp_packets(session, data_size, flags)
                    }
                    None => {
                        // 默认TCP三次握手
                        let flow = ApplicationFlowType::TcpOnly;
                        Ok(session.generate_packets(&flow))
                    }
                }
            }
            super::SessionType::Udp { .. } => {
                Err(TemplateError::ConfigError("UDP协议尚未实现".to_string()))
            }
        }
    }

    /// 生成HTTP流量数据包
    fn generate_http_packets(&self, session: TcpSession,
                                requests: &[super::HttpRequestConfig],
                                responses: &[super::HttpResponseConfig]) -> Result<Vec<Vec<u8>>, TemplateError> {
        let mut packets = Vec::new();

        // 生成TCP三次握手
        let (handshake_packets, _) = build_tcp_handshake_packets(
            session.connection.src_mac,
            session.connection.dst_mac,
            session.connection.src_ip,
            session.connection.dst_ip,
            session.connection.src_port,
            session.connection.dst_port,
            session.isn
        );
        packets.extend(handshake_packets);

        // 生成HTTP请求
        for (i, request_config) in requests.iter().enumerate() {
            let uri = request_config.uri.as_deref().unwrap_or("/");
            let host = request_config.headers
                .as_ref()
                .and_then(|h| h.get("Host"))
                .map(|s| s.as_str())
                .unwrap_or("example.com");

            let request_packet = crate::http::flow::build_http_get_packet(
                session.connection.src_mac,
                session.connection.dst_mac,
                session.connection.src_ip,
                session.connection.dst_ip,
                session.connection.src_port,
                session.connection.dst_port,
                session.isn + (i as u32 * 1000),
                0, // 将在生成时更新
                TcpFlags::ACK | TcpFlags::PSH,
                uri,
                host,
            );
            packets.push(request_packet);
        }

        // 生成HTTP响应
        for (i, response_config) in responses.iter().enumerate() {
            let status_code = response_config.status_code.unwrap_or(200);
            let status = HttpStatusCode::Custom(status_code);
            let content_type = response_config.headers
                .as_ref()
                .and_then(|h| h.get("Content-Type"))
                .map(|s| s.as_str())
                .unwrap_or("text/html");
            let body = response_config.body.as_ref().map(|s| s.as_bytes()).unwrap_or(b"OK");

            let response_packet = crate::http::flow::build_http_response_packet_simple(
                session.connection.dst_mac,
                session.connection.src_mac,
                session.connection.dst_ip,
                session.connection.src_ip,
                session.connection.dst_port,
                session.connection.src_port,
                1001 + (i as u32 * 1000), // 将在生成时更新
                session.isn + 1000,
                TcpFlags::ACK | TcpFlags::PSH,
                status,
                content_type,
                body,
            );
            packets.push(response_packet);
        }

        Ok(packets)
    }

    /// 生成原始TCP数据包
    fn generate_tcp_packets(&self, session: TcpSession,
                            data_size: Option<usize>,
                            flags: Option<&[String]>) -> Result<Vec<Vec<u8>>, TemplateError> {
        let mut packets = Vec::new();

        // 生成TCP三次握手
        let (handshake_packets, _) = build_tcp_handshake_packets(
            session.connection.src_mac,
            session.connection.dst_mac,
            session.connection.src_ip,
            session.connection.dst_ip,
            session.connection.src_port,
            session.connection.dst_port,
            session.isn
        );
        packets.extend(handshake_packets);

        // 如果需要，生成数据包
        if let Some(size) = data_size {
            let data = vec![0u8; size]; // 简单的填充数据
            let packet_flags = TemplateEngine::parse_tcp_flags(flags.unwrap_or(&["ACK".to_string(), "PSH".to_string()]))?;

            let packet = crate::tcp::packet::build_tcp_packet_with_data(
                crate::tcp::packet::TcpPacketWithDataParams::new(
                    session.connection.src_mac,
                    session.connection.dst_mac,
                    session.connection.src_ip,
                    session.connection.dst_ip,
                    session.connection.src_port,
                    session.connection.dst_port,
                    session.isn + 1000,
                    0,
                    packet_flags,
                    data
                )
            );
            packets.push(packet);
        }

        Ok(packets)
    }

    /// 构建HTTP请求
    fn build_http_request(&self, config: &super::HttpRequestConfig, connection: &NetworkConnection) -> Result<HttpRequest, TemplateError> {
        let method = Self::parse_http_method(&config.method.clone().unwrap_or("GET".to_string()))?;
        let uri = config.uri.as_deref().unwrap_or("/");
        let mut request = HttpRequest::new(method, uri.to_string());

        // 添加默认头部
        request = request.with_version(HttpVersion::Http1_1)
            .add_header("Host".to_string(), format!("{}:{}", connection.dst_ip, connection.dst_port))
            .add_header("User-Agent".to_string(), "gen_pcap/1.0".to_string());

        // 添加自定义头部
        if let Some(headers) = &config.headers {
            for (key, value) in headers {
                request = request.add_header(key.clone(), value.clone());
            }
        }

        // 添加请求体
        if let Some(body) = &config.body {
            request = request.with_body(body.as_bytes().to_vec());
        }

        Ok(request)
    }

    /// 构建HTTP响应
    fn build_http_response(&self, config: &super::HttpResponseConfig, connection: &NetworkConnection) -> Result<HttpResponse, TemplateError> {
        let status_code = config.status_code.unwrap_or(200);
        let status = config.status_text.as_deref()
            .unwrap_or(&Self::get_status_text(status_code));
        let status = HttpStatusCode::Custom(status_code);

        let mut response = HttpResponse::new(status)
            .with_version(HttpVersion::Http1_1)
            .add_header("Server".to_string(), "gen_pcap/1.0".to_string())
            .add_header("Connection".to_string(), "close".to_string());

        // 添加自定义头部
        if let Some(headers) = &config.headers {
            for (key, value) in headers {
                response = response.add_header(key.clone(), value.clone());
            }
        }

        // 添加响应体
        if let Some(body) = &config.body {
            response = response.with_body(body.as_bytes().to_vec());
        }

        Ok(response)
    }

    /// 解析MAC地址
    fn parse_mac_address(mac_str: &str) -> Result<[u8; 6], TemplateError> {
        let parts: Vec<&str> = mac_str.split(':').collect();
        if parts.len() != 6 {
            return Err(TemplateError::MacAddressError(format!(
                "无效的MAC地址格式: {}. 期望格式: XX:XX:XX:XX:XX:XX", mac_str
            )));
        }

        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16)
                .map_err(|_| TemplateError::MacAddressError("无效的MAC地址".to_string()))?;
        }
        Ok(mac)
    }

    /// 解析IP地址（支持 IPv4 和 IPv6）
    fn parse_ip_address(ip_str: &str) -> Result<IpAddr, TemplateError> {
        // 先尝试解析 IPv4
        if let Ok(ip_v4) = ip_str.parse::<Ipv4Addr>() {
            return Ok(IpAddr::V4(ip_v4));
        }

        // 再尝试解析 IPv6
        if let Ok(ip_v6) = ip_str.parse::<Ipv6Addr>() {
            return Ok(IpAddr::V6(ip_v6));
        }

        Err(TemplateError::AddressError(format!("无效的IP地址: {}", ip_str)))
    }

    /// 解析HTTP方法
    fn parse_http_method(method: &str) -> Result<HttpMethod, TemplateError> {
        match method.to_uppercase().as_str() {
            "GET" => Ok(HttpMethod::GET),
            "POST" => Ok(HttpMethod::POST),
            "PUT" => Ok(HttpMethod::PUT),
            "DELETE" => Ok(HttpMethod::DELETE),
            "HEAD" => Ok(HttpMethod::HEAD),
            "OPTIONS" => Ok(HttpMethod::OPTIONS),
            "PATCH" => Ok(HttpMethod::PATCH),
            _ => Err(TemplateError::HttpConfigError(format!("不支持的HTTP方法: {}", method))),
        }
    }

    /// 解析TCP标志
    fn parse_tcp_flags(flags: &[String]) -> Result<u16, TemplateError> {
        let mut result = 0u16;
        for flag in flags {
            match flag.to_uppercase().as_str() {
                "FIN" => result |= pnet::packet::tcp::TcpFlags::FIN,
                "SYN" => result |= pnet::packet::tcp::TcpFlags::SYN,
                "RST" => result |= pnet::packet::tcp::TcpFlags::RST,
                "PSH" => result |= pnet::packet::tcp::TcpFlags::PSH,
                "ACK" => result |= pnet::packet::tcp::TcpFlags::ACK,
                "URG" => result |= pnet::packet::tcp::TcpFlags::URG,
                "ECE" => result |= pnet::packet::tcp::TcpFlags::ECE,
                "CWR" => result |= pnet::packet::tcp::TcpFlags::CWR,
                "NS" => result |= pnet::packet::tcp::TcpFlags::NS,
                _ => return Err(TemplateError::ConfigError(format!("不支持的TCP标志: {}", flag))),
            }
        }
        Ok(result)
    }

    /// 生成IP地址（支持生成 IPv4 和 IPv6）
    fn generate_ip_address(session_name: &str, field: &str, index: usize) -> IpAddr {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // 基于会话名称和字段生成确定性IP
        let seed = format!("{}-{}-{}", session_name, field, index);
        let digest = md5::compute(seed.as_bytes());
        let hash = format!("{:x}", digest);

        // 从哈希值生成 IP 地址
        let hash_u32 = u32::from_str_radix(&hash[..8], 16).unwrap_or(0);

        // 80% 概率生成 IPv4，20% 概率生成 IPv6（向后兼容优先）
        if hash_u32 % 5 < 4 {
            // 生成 IPv4 地址
            let a = (hash_u32 >> 24) % 224 + 1;
            let b = (hash_u32 >> 16) % 256;
            let c = (hash_u32 >> 8) % 256;
            let d = hash_u32 % 255 + 1;
            IpAddr::V4(Ipv4Addr::new(a as u8, b as u8, c as u8, d as u8))
        } else {
            // 生成 IPv6 地址（全局单播地址 2000::/3）
            let hash_u128 = u128::from_str_radix(&hash[..32.min(hash.len())], 16).unwrap_or(0);
            let segments = [
                0x2000 + ((hash_u128 >> 112) % 0x1000) as u16,
                ((hash_u128 >> 96) % 0xFFFF) as u16,
                ((hash_u128 >> 80) % 0xFFFF) as u16,
                ((hash_u128 >> 64) % 0xFFFF) as u16,
                ((hash_u128 >> 48) % 0xFFFF) as u16,
                ((hash_u128 >> 32) % 0xFFFF) as u16,
                ((hash_u128 >> 16) % 0xFFFF) as u16,
                (hash_u128 % 0xFFFF) as u16,
            ];
            IpAddr::V6(Ipv6Addr::new(
                segments[0], segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7]
            ))
        }
    }

    /// 生成端口号
    fn generate_port(session_name: &str, index: usize) -> u16 {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // 基于会话名称和索引生成确定性端口
        let seed = format!("{}-{}", session_name, index);
        let digest = md5::compute(seed.as_bytes());
        let hash = format!("{:x}", digest);

        // 从哈希值生成端口
        let hash_u32 = u32::from_str_radix(&hash[..8], 16).unwrap_or(0);
        ((hash_u32 % 60000) + 1024) as u16 // 1024-61023 范围
    }

    /// 获取状态码对应的文本
    fn get_status_text(code: u16) -> &'static str {
        match code {
            200 => "OK",
            201 => "Created",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            _ => "Unknown",
        }
    }
}

