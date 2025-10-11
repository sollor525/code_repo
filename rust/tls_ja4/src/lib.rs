//! TLS JA4/JA3 Fingerprint Extractor Library
//!
//! 这个库提供了从pcap文件中提取TLS协议的JA4和JA3指纹的功能。
//!
//! ## C API
//!
//! 库提供了C兼容的API，支持嵌入到VPP等C程序中：
//!
//! ```c
//! // 初始化
//! tls_ja4_context* ctx = tls_ja4_init();
//!
//! // 分析TCP payload
//! tls_ja4_result result;
//! int ret = tls_ja4_analyze_payload(ctx, tcp_payload, payload_len, &result);
//!
//! // 获取结果
//! if (ret == 0) {
//!     printf("JA4: %s\n", result.ja4);
//!     printf("JA3: %s\n", result.ja3);
//! }
//!
//! // 清理
//! tls_ja4_cleanup(ctx);
//! ```
//!
//! ## 线程安全
//!
//! C API是线程安全的，支持多线程并发调用。

// 模块声明
pub mod network;
pub mod tls;
pub mod fingerprint;
pub mod cache;
pub mod c_api;
pub mod performance;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod integration_tests;

// #[cfg(test)]
// mod c_api_tests;

// 重新导出主要类型和函数
pub use c_api::*;
pub use network::format_ip;

// 保留原有的依赖，用于向后兼容
use anyhow::Result;
use pcap::Capture;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsVersion};

// Re-export TlsVersion for external use
pub use tls_parser::TlsVersion as TlsVersionLib;

/// 配置结构体
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_include_server_hello")]
    pub include_server_hello: bool,
    #[serde(default = "default_max_packets_per_session")]
    pub max_packets_per_session: usize,
    #[serde(default = "default_include_ja3")]
    pub include_ja3: bool,
    #[serde(default = "default_verbose")]
    pub verbose: bool,
}

fn default_include_server_hello() -> bool {
    false
}

fn default_max_packets_per_session() -> usize {
    10
}

fn default_verbose() -> bool {
    false
}

fn default_include_ja3() -> bool {
    true
}

/// VLAN标签结构体
#[derive(Debug, Clone)]
pub struct VlanTag {
    pub vlan_id: u16,
    pub priority: u8,
    pub ether_type: u16,
}

/// TCP流重组缓冲区
#[derive(Debug, Clone)]
pub struct TcpStreamBuffer {
    pub data: Vec<u8>,
    pub expected_seq: u32,
    pub is_complete: bool,
    pub last_activity: u64, // 时间戳，用于清理超时的流
}

#[derive(Debug, Clone)]
pub struct BidirectionalTcpStream {
    pub client_to_server: TcpStreamBuffer,
    pub server_to_client: TcpStreamBuffer,
    pub last_activity: u64,
}

/// TLS会话结构体
#[derive(Debug, Clone)]
pub struct TlsSession {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub client_hellos: Vec<Vec<u8>>,
    pub server_hellos: Vec<Vec<u8>>,
    pub ja3_fingerprints: Vec<String>,
}

/// 指纹数据结构体
#[derive(Debug, Serialize, Clone)]
pub struct FingerprintData {
    pub timestamp: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub ja4_fingerprints: Vec<String>,
    pub ja4b_fingerprints: Vec<String>,
    pub ja4c_fingerprints: Vec<String>,
    pub ja3_fingerprints: Vec<String>,
    pub client_hello_count: usize,
    pub server_hello_count: usize,
}

/// 指纹报告结构体
#[derive(Debug, Serialize)]
pub struct FingerprintReport {
    pub analysis_time: i64,
    pub total_sessions: usize,
    pub total_packets: usize,
    pub tls_packets: usize,
    pub sessions: Vec<FingerprintData>,
}

/// 检查是否为GREASE值
pub fn is_grease_value(value: u16) -> bool {
    // GREASE值遵循模式：0x?a?a，其中?是相同的十六进制数字
    // 例如：0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
    let high_byte = (value >> 8) & 0xFF;
    let low_byte = value & 0xFF;
    
    // 检查是否为GREASE模式：高字节和低字节都是?a的形式，且高低字节的高4位相同
    (high_byte & 0x0F) == 0x0A && (low_byte & 0x0F) == 0x0A && (high_byte >> 4) == (low_byte >> 4)
}


/// 从原始TLS Client Hello数据中提取ALPN
pub fn extract_alpn_from_client_hello(client_hello_data: &[u8]) -> Option<String> {
    // 使用tls-parser进行标准解析
    extract_alpn_with_tls_parser(client_hello_data)
}

/// 使用tls-parser提取ALPN
pub fn extract_alpn_with_tls_parser(client_hello_data: &[u8]) -> Option<String> {
    use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake};
    
    // 解析TLS包
    if let Ok((_, tls_plaintext)) = parse_tls_plaintext(client_hello_data) {
        if let Some(handshake) = tls_plaintext.msg.first() {
            if let TlsMessage::Handshake(handshake_msg) = handshake {
                if let TlsMessageHandshake::ClientHello(client_hello) = handshake_msg {
                    // 查找ALPN扩展
                    if let Some(extensions_data) = &client_hello.ext {
                        match tls_parser::parse_tls_extensions(extensions_data) {
                            Ok((_, parsed_extensions)) => {
                                for extension in parsed_extensions {
                                    if let tls_parser::TlsExtension::ALPN(alpn_protocols) = extension {
                                        if !alpn_protocols.is_empty() {
                                            // 根据JA4标准，只取ALPN扩展列表里的第一个协议
                                            let first_protocol = &alpn_protocols[0];
                                            let protocol_str = std::str::from_utf8(first_protocol).unwrap_or("");
                                            
                                            
                                            // 根据JA4标准映射ALPN协议
                                            return Some(match protocol_str.to_lowercase().as_str() {
                                                "http/1.1" => "h1".to_string(),
                                                "h2" | "http/2" => "h2".to_string(),
                                                "h3" | "http/3" => "h3".to_string(),
                                                "grpc" => "gr".to_string(),
                                                _ => {
                                                    if protocol_str.len() >= 2 {
                                                        protocol_str[..2].to_lowercase()
                                                    } else {
                                                        format!("{:0<2}", protocol_str).to_lowercase()
                                                    }
                                                }
                                            });
                                        }
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }
    }
    
    Some("00".to_string())
}

pub fn extract_alpn_manual(client_hello_data: &[u8]) -> Option<String> {
    if client_hello_data.len() < 10 {
        return Some("00".to_string());
    }

    let mut offset = 0;
    
    // 跳过 TLS 记录头 (5 bytes)
    if client_hello_data[0] != 0x16 {
        return Some("00".to_string()); // 不是 TLS Handshake
    }
    offset += 5;

    // 跳过 Handshake 头 (4 bytes)
    if client_hello_data[offset] != 0x01 {
        return Some("00".to_string()); // 不是 Client Hello
    }
    offset += 4;

    // 跳过版本 (2 bytes)
    offset += 2;

    // 跳过随机数 (32 bytes)
    offset += 32;

    // 跳过会话ID
    if offset >= client_hello_data.len() {
        return Some("00".to_string());
    }
    let session_id_len = client_hello_data[offset] as usize;
    offset += 1 + session_id_len;

    // 跳过密码套件
    if offset + 2 > client_hello_data.len() {
        return Some("00".to_string());
    }
    let cipher_suites_len = u16::from_be_bytes([client_hello_data[offset], client_hello_data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // 跳过压缩方法
    if offset >= client_hello_data.len() {
        return Some("00".to_string());
    }
    let compression_methods_len = client_hello_data[offset] as usize;
    offset += 1 + compression_methods_len;

    // 现在应该到达扩展数据
    if offset + 2 > client_hello_data.len() {
        return Some("00".to_string());
    }
    let extensions_len = u16::from_be_bytes([client_hello_data[offset], client_hello_data[offset + 1]]) as usize;
    offset += 2;

    if offset + extensions_len > client_hello_data.len() {
        return Some("00".to_string());
    }

    let extensions_data = &client_hello_data[offset..offset + extensions_len];

    // 手动解析扩展
    let mut ext_offset = 0;
    while ext_offset + 4 <= extensions_data.len() {
        let ext_type = u16::from_be_bytes([extensions_data[ext_offset], extensions_data[ext_offset + 1]]);
        let ext_len = u16::from_be_bytes([extensions_data[ext_offset + 2], extensions_data[ext_offset + 3]]) as usize;
        
        if ext_type == 16 { // ALPN扩展
            if ext_offset + 4 + ext_len <= extensions_data.len() {
                let alpn_data = &extensions_data[ext_offset + 4..ext_offset + 4 + ext_len];
                
                // 解析ALPN协议列表
                let mut alpn_offset = 0;
                
                // 跳过总长度字段
                if alpn_offset + 1 > alpn_data.len() {
                    return Some("00".to_string());
                }
                let _total_len = alpn_data[alpn_offset] as usize;
                alpn_offset += 1;
                
                while alpn_offset < alpn_data.len() {
                    if alpn_offset + 1 > alpn_data.len() {
                        break;
                    }
                    let protocol_len = alpn_data[alpn_offset] as usize;
                    alpn_offset += 1;
                    
                    if alpn_offset + protocol_len <= alpn_data.len() {
                        let protocol = &alpn_data[alpn_offset..alpn_offset + protocol_len];
                        let protocol_str = String::from_utf8_lossy(protocol);
                        
                        // 清理协议字符串，移除不可见字符
                        let clean_protocol = protocol_str.trim_matches(|c: char| c.is_control() || c.is_whitespace());
                        
                        // 返回第一个协议
                        return match clean_protocol.to_lowercase().as_str() {
                            "http/1.1" => Some("h1".to_string()),
                            "h2" | "http/2" => Some("h2".to_string()),
                            "h3" | "http/3" => Some("h3".to_string()),
                            "grpc" => Some("gr".to_string()),
                            _ => {
                                if clean_protocol.len() >= 2 {
                                    Some(clean_protocol[..2].to_lowercase())
                                } else {
                                    Some(format!("{:<02}", clean_protocol).to_lowercase())
                                }
                            }
                        };
                    }
                    alpn_offset += protocol_len;
                }
            }
        }
        
        ext_offset += 4 + ext_len;
    }

    Some("00".to_string())
}

/// 正确解析TLS扩展数据
pub fn parse_tls_extensions_correctly(extensions_data: &[u8]) -> (Vec<u16>, Vec<u16>, Vec<u8>, Vec<u16>) {
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut _signature_algorithms = Vec::new();
    
    // 使用tls-parser解析扩展
    match tls_parser::parse_tls_extensions(extensions_data) {
        Ok((_, parsed_extensions)) => {
            for extension in parsed_extensions {
                match extension {
                    tls_parser::TlsExtension::SNI(_) => {
                        extensions.push(0); // SNI extension
                    }
                    tls_parser::TlsExtension::EllipticCurves(curves) => {
                        extensions.push(10); // supported_groups
                        for curve in curves {
                            elliptic_curves.push(curve.0);
                        }
                    }
                    tls_parser::TlsExtension::EcPointFormats(formats) => {
                        extensions.push(11); // ec_point_formats
                        for &format in formats {
                            ec_point_formats.push(format);
                        }
                    }
                    tls_parser::TlsExtension::SignatureAlgorithms(algs) => {
                        extensions.push(13); // _signature_algorithms
                        for alg in algs {
                            _signature_algorithms.push(alg);
                        }
                    }
                    tls_parser::TlsExtension::ALPN(_) => {
                        extensions.push(16); // ALPN
                    }
                    tls_parser::TlsExtension::SupportedVersions(_) => {
                        extensions.push(43); // supported_versions
                    }
                    tls_parser::TlsExtension::MaxFragmentLength(_) => {
                        extensions.push(1); // max_fragment_length
                    }
                    tls_parser::TlsExtension::StatusRequest(_) => {
                        extensions.push(5); // status_request
                    }
                    tls_parser::TlsExtension::RecordSizeLimit(_) => {
                        extensions.push(28); // record_size_limit
                    }
                    tls_parser::TlsExtension::SessionTicket(_) => {
                        extensions.push(35); // session_ticket
                    }
                    tls_parser::TlsExtension::KeyShare(_) => {
                        extensions.push(51); // key_share
                    }
                    tls_parser::TlsExtension::KeyShareOld(_) => {
                        extensions.push(40); // key_share_old
                    }
                    tls_parser::TlsExtension::PreSharedKey(_) => {
                        extensions.push(41); // pre_shared_key
                    }
                    tls_parser::TlsExtension::EarlyData(_) => {
                        extensions.push(42); // early_data
                    }
                    tls_parser::TlsExtension::Cookie(_) => {
                        extensions.push(44); // cookie
                    }
                    tls_parser::TlsExtension::PskExchangeModes(_) => {
                        extensions.push(45); // psk_key_exchange_modes
                    }
                    tls_parser::TlsExtension::OidFilters(_) => {
                        extensions.push(48); // oid_filters
                    }
                    tls_parser::TlsExtension::PostHandshakeAuth => {
                        extensions.push(49); // post_handshake_auth
                    }
                    tls_parser::TlsExtension::Heartbeat(_) => {
                        extensions.push(15); // heartbeat
                    }
                    tls_parser::TlsExtension::SignedCertificateTimestamp(_) => {
                        extensions.push(18); // signed_certificate_timestamp
                    }
                    tls_parser::TlsExtension::Padding(_) => {
                        extensions.push(21); // padding
                    }
                    tls_parser::TlsExtension::Grease(ext_type, _) => {
                        // GREASE扩展，添加到扩展列表中（在JA4_a计数中包含）
                        extensions.push(ext_type);
                        println!("GREASE扩展: 0x{:04x}", ext_type);
                    }
                    tls_parser::TlsExtension::Unknown(ext_type, _) => {
                        // 未知扩展类型，添加到扩展列表中
                        let ext_type_u16: u16 = ext_type.into();
                        extensions.push(ext_type_u16);
                        println!("未知扩展类型: 0x{:04x}", ext_type_u16);
                    }
                    tls_parser::TlsExtension::RenegotiationInfo(_) => {
                        // 重新协商信息扩展 (0xff01)
                        extensions.push(0xff01);
                    }
                    tls_parser::TlsExtension::ExtendedMasterSecret => {
                        // 扩展主密钥扩展 (0x0017)
                        extensions.push(0x17);
                    }
                    tls_parser::TlsExtension::EncryptThenMac => {
                        // 先加密后MAC扩展 (0x0016)
                        extensions.push(0x16);
                    }
                    _ => {
                        // 其他扩展类型，暂时跳过
                        println!("未处理的扩展类型: {:?}", extension);
                    }
                }
            }
        }
        Err(_) => {
            // 解析失败，使用默认值
        }
    }
    
    // 如果没有解析到椭圆曲线，使用默认值
    if elliptic_curves.is_empty() {
        elliptic_curves = vec![29u16, 23, 30, 25, 24];
    }
    
    // 如果没有解析到点格式，使用默认值
    if ec_point_formats.is_empty() {
        ec_point_formats = vec![0u8, 1, 2];
    }
    
    // 如果没有解析到签名算法，使用默认值
    if _signature_algorithms.is_empty() {
        _signature_algorithms = vec![0x0403u16, 0x0503, 0x0603];
    }
    
    (extensions, elliptic_curves, ec_point_formats, _signature_algorithms)
}


/// 生成会话键
pub fn generate_session_key(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16, _is_client_to_server: bool) -> String {
    // 使用标准的源->目标格式
    format!("{}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port)
}

/// 生成TCP流键（双向）
pub fn generate_tcp_stream_key(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> String {
    // 使用固定的顺序来确保双向流使用相同的键
    if (src_ip, src_port) < (dst_ip, dst_port) {
        format!("{}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port)
    } else {
        format!("{}:{} -> {}:{}", dst_ip, dst_port, src_ip, src_port)
    }
}



/// 重组TCP流数据（双向）
pub fn reassemble_tcp_stream(
    stream_buffers: &mut HashMap<String, BidirectionalTcpStream>,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq: u32,
    data: &[u8],
    timestamp: u64,
) -> Vec<Vec<u8>> {
    let stream_key = generate_tcp_stream_key(src_ip, src_port, dst_ip, dst_port);
    let stream = stream_buffers.entry(stream_key).or_insert_with(|| {
        BidirectionalTcpStream {
            client_to_server: TcpStreamBuffer {
                data: Vec::new(),
                expected_seq: 0,
                is_complete: false,
                last_activity: timestamp,
            },
            server_to_client: TcpStreamBuffer {
                data: Vec::new(),
                expected_seq: 0,
                is_complete: false,
                last_activity: timestamp,
            },
            last_activity: timestamp,
        }
    });
    
    stream.last_activity = timestamp;
    
    // 确定数据方向：通常客户端端口 < 服务器端口
    let is_client_to_server = src_port < dst_port;
    let buffer = if is_client_to_server {
        &mut stream.client_to_server
    } else {
        &mut stream.server_to_client
    };
    
    buffer.last_activity = timestamp;
    
    // 如果是第一个包，初始化序列号
    if buffer.expected_seq == 0 {
        buffer.expected_seq = seq;
    }
    
    // 处理序列号
    if seq == buffer.expected_seq {
        // 序列号匹配，添加数据
        buffer.data.extend_from_slice(data);
        buffer.expected_seq = seq.wrapping_add(data.len() as u32);
    } else if seq > buffer.expected_seq {
        // 有数据丢失，重置缓冲区
        buffer.data.clear();
        buffer.data.extend_from_slice(data);
        buffer.expected_seq = seq.wrapping_add(data.len() as u32);
    } else if seq < buffer.expected_seq {
        // 检查是否有重叠
        let overlap_start = buffer.expected_seq.wrapping_sub(seq) as usize;
        if overlap_start < data.len() {
            // 有重叠，只添加新数据部分
            buffer.data.extend_from_slice(&data[overlap_start..]);
            buffer.expected_seq = seq.wrapping_add(data.len() as u32);
        }
        // 如果完全重叠，忽略这个包
    }
    
    // 检查是否有完整的TLS记录
    let mut tls_records = Vec::new();
    if buffer.data.len() >= 5 {
        let mut offset = 0;
        while offset + 5 <= buffer.data.len() {
            let length = u16::from_be_bytes([buffer.data[offset + 3], buffer.data[offset + 4]]) as usize;
            let record_end = offset + 5 + length;
            
            if record_end <= buffer.data.len() {
                let record = buffer.data[offset..record_end].to_vec();
                if is_tls_packet(&record) {
                    tls_records.push(record);
                }
                offset = record_end;
            } else {
                break; // 不完整的记录
            }
        }
        
        // 移除已处理的数据
        if offset > 0 {
            buffer.data.drain(0..offset);
        }
    }
    
    tls_records
}

/// 检查是否为TLS数据包
pub fn is_tls_packet(packet: &[u8]) -> bool {
    if packet.len() < 6 {
        return false;
    }
    
    // TLS记录头部格式：
    // [0]: Content Type (0x16=Handshake, 0x17=Application Data, 0x14=Change Cipher Spec, 0x15=Alert, 0x18=Heartbeat)
    // [1-2]: Version (0x0301=TLS 1.0, 0x0302=TLS 1.1, 0x0303=TLS 1.2, 0x0304=TLS 1.3)
    // [3-4]: Length
    
    let content_type = packet[0];
    let version_major = packet[1];
    let version_minor = packet[2];
    let length = u16::from_be_bytes([packet[3], packet[4]]);
    
    // 检查Content Type是否为有效的TLS类型
    if !matches!(content_type, 0x14 | 0x15 | 0x16 | 0x17 | 0x18) {
        return false;
    }
    
    // 检查TLS版本是否有效
    if version_major != 0x03 {
        return false;
    }
    
    // TLS版本范围检查 (SSL 3.0 到 TLS 1.3)
    if !(0x00..=0x04).contains(&version_minor) {
        return false;
    }
    
    // 检查长度是否合理 (不超过16KB + 256字节)
    if length > 16640 {
        return false;
    }
    
    // 检查数据包长度是否足够包含记录头部和声明的长度
    if packet.len() < 5 + length as usize {
        return false;
    }
    
    true
}

/// 检查是否为QUIC数据包
pub fn is_quic_packet(packet: &[u8]) -> bool {
    // 首先进行基本的QUIC检测
    if !is_quic_packet_basic(packet) {
        return false;
    }
    
    // 额外的验证：检查包的特征
    // 1. 检查包长度是否在合理范围内
    if packet.len() < 50 || packet.len() > 1500 {
        return false;
    }
    
    // 2. 检查第一个字节是否合理
    let first_byte = packet[0];
    
    // 对于Short Header，检查Packet Number Length是否合理
    if (first_byte & 0x80) == 0 {
        let pn_length = (first_byte & 0x03) + 1;
        if pn_length < 1 || pn_length > 4 {
            return false;
        }
        
        // 检查Packet Number字段
        if packet.len() > pn_length as usize {
            let pn_bytes = &packet[1..1 + pn_length as usize];
            let pn_value = pn_bytes.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32);
            
            // Packet Number不能为0或全为1
            if pn_value == 0 || pn_value == (1u32 << (pn_length * 8)) - 1 {
                return false;
            }
        }
    }
    
    // 3. 检查包的内容是否合理
    // 对于QUIC包，应该有一些加密的数据
    if packet.len() > 20 {
        // 检查是否有足够的随机性（避免检测到其他协议）
        let mut entropy = 0u32;
        for &byte in &packet[10..std::cmp::min(50, packet.len())] {
            entropy ^= byte as u32;
        }
        
        // 如果熵值太低，可能不是QUIC包
        if entropy < 10 {
            return false;
        }
    }
    
    // 4. 检查包的来源和目的地
    // 对于QUIC包，通常来自或发往443端口（HTTPS）
    // 这里我们无法直接获取端口信息，但可以通过其他方式验证
    
    // 5. 检查包的特征模式
    // 对于QUIC包，应该有一些特定的模式
    if packet.len() > 10 {
        // 检查前几个字节是否合理
        let first_byte = packet[0];
        
        // 对于Short Header，检查是否有合理的模式
        if (first_byte & 0x80) == 0 {
            // 检查Packet Number Length是否合理
            let pn_length = (first_byte & 0x03) + 1;
            if pn_length < 1 || pn_length > 4 {
                return false;
            }
            
            // 检查包是否有足够的空间容纳Packet Number
            if packet.len() < 1 + pn_length as usize {
                return false;
            }
            
            // 检查Packet Number字段
            if packet.len() > pn_length as usize {
                let pn_bytes = &packet[1..1 + pn_length as usize];
                let pn_value = pn_bytes.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32);
                
                // Packet Number不能为0或全为1
                if pn_value == 0 || pn_value == (1u32 << (pn_length * 8)) - 1 {
                    return false;
                }
            }
        }
    }
    
    // 6. 检查包的来源和目的地
    // 对于QUIC包，通常来自或发往443端口（HTTPS）
    // 这里我们无法直接获取端口信息，但可以通过其他方式验证
    
    // 7. 检查包的内容是否合理
    // 对于QUIC包，应该有一些加密的数据
    if packet.len() > 20 {
        // 检查是否有足够的随机性（避免检测到其他协议）
        let mut entropy = 0u32;
        for &byte in &packet[10..std::cmp::min(50, packet.len())] {
            entropy ^= byte as u32;
        }
        
        // 如果熵值太低，可能不是QUIC包
        if entropy < 10 {
            return false;
        }
    }
    
    // 8. 检查包的来源和目的地
    // 对于QUIC包，通常来自或发往443端口（HTTPS）
    // 这里我们无法直接获取端口信息，但可以通过其他方式验证
    
    // 9. 检查包的特征模式
    // 对于QUIC包，应该有一些特定的模式
    if packet.len() > 10 {
        // 检查前几个字节是否合理
        let first_byte = packet[0];
        
        // 对于Short Header，检查是否有合理的模式
        if (first_byte & 0x80) == 0 {
            // 检查Packet Number Length是否合理
            let pn_length = (first_byte & 0x03) + 1;
            if pn_length < 1 || pn_length > 4 {
                return false;
            }
            
            // 检查包是否有足够的空间容纳Packet Number
            if packet.len() < 1 + pn_length as usize {
                return false;
            }
            
            // 检查Packet Number字段
            if packet.len() > pn_length as usize {
                let pn_bytes = &packet[1..1 + pn_length as usize];
                let pn_value = pn_bytes.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32);
                
                // Packet Number不能为0或全为1
                if pn_value == 0 || pn_value == (1u32 << (pn_length * 8)) - 1 {
                    return false;
                }
            }
        }
    }
    
    true
}

/// 基本的QUIC包检测
/// 专注于检测QUIC Initial包（packet_type == 0），因为只有Initial包包含TLS ClientHello
fn is_quic_packet_basic(packet: &[u8]) -> bool {
    if packet.len() < 5 {
        return false;
    }
    
    let first_byte = packet[0];
    
    // QUIC Long Header检测：第一个字节的最高位为1
    if (first_byte & 0x80) != 0 {
        // 检查Packet Type (第1个字节的5-6位)
        let packet_type = (first_byte & 0x30) >> 4;
        
        // 检查版本字段 (字节1-4)
        let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
        
        // 检查是否为有效的QUIC版本 (QUIC版本1 = 0x00000001)
        if version != 0x00000001 {
            return false;
        }
        
        // 要求包长度至少100字节（QUIC包通常比较大）
        if packet.len() < 100 {
            return false;
        }
        
        // 只接受Initial包（packet_type == 0），因为只有Initial包包含TLS ClientHello
        match packet_type {
            0x0 => true, // Initial - 包含TLS ClientHello
            _ => false,   // 其他包类型不包含ClientHello，不需要检测
        }
    } else {
        // QUIC Short Header不包含TLS ClientHello，不需要检测
        false
    }
}

/// 检测是否为TLS Client Hello报文
pub fn is_client_hello(payload: &[u8]) -> bool {
    if !is_tls_packet(payload) || payload.len() < 6 {
        return false;
    }
    
    // 检查Handshake消息类型 (0x01 = Client Hello)
    payload[5] == 0x01
}

/// 将TlsVersion转换为u16
#[allow(dead_code)]
fn tls_version_to_u16(version: TlsVersion) -> u16 {
    match version {
        TlsVersion::Ssl30 => 0x0300,
        TlsVersion::Tls10 => 0x0301,
        TlsVersion::Tls11 => 0x0302,
        TlsVersion::Tls12 => 0x0303,
        TlsVersion::Tls13 => 0x0304,
        _ => 0x0303, // 默认TLS 1.2
    }
}

/// IP头解析结果
#[allow(dead_code)]
struct IpHeader {
    version: u8,
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    protocol: u8,
    header_len: usize,
}

/// TCP头解析结果
#[allow(dead_code)]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    header_len: usize,
    payload_offset: usize,
}

/// 解析IP头
#[allow(dead_code)]
fn parse_ip_header(packet: &[u8]) -> Result<IpHeader, i32> {
    if packet.len() < 20 {
        return Err(TLS_JA4_INVALID_PACKET);
    }
    
    let version = (packet[0] >> 4) & 0x0F;
    
    match version {
        4 => {
            // IPv4
            let ihl = (packet[0] & 0x0F) as usize * 4;
            if packet.len() < ihl {
                return Err(TLS_JA4_INVALID_PACKET);
            }
            
            let protocol = packet[9];
            let mut src_ip = [0u8; 16];
            let mut dst_ip = [0u8; 16];
            
            // IPv4地址存储在最后4字节
            src_ip[12..16].copy_from_slice(&packet[12..16]);
            dst_ip[12..16].copy_from_slice(&packet[16..20]);
            
            Ok(IpHeader {
                version: 4,
                src_ip,
                dst_ip,
                protocol,
                header_len: ihl,
            })
        },
        6 => {
            // IPv6 - 暂不支持
            Err(TLS_JA4_IPV6_NOT_SUPPORTED)
        },
        _ => Err(TLS_JA4_INVALID_PACKET)
    }
}

/// 解析TCP头
#[allow(dead_code)]
fn parse_tcp_header(packet: &[u8], ip_header_len: usize) -> Result<TcpHeader, i32> {
    let tcp_start = ip_header_len;
    if packet.len() < tcp_start + 20 {
        return Err(TLS_JA4_INVALID_PACKET);
    }
    
    let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);
    let dst_port = u16::from_be_bytes([packet[tcp_start + 2], packet[tcp_start + 3]]);
    let seq = u32::from_be_bytes([
        packet[tcp_start + 4], packet[tcp_start + 5],
        packet[tcp_start + 6], packet[tcp_start + 7]
    ]);
    let ack = u32::from_be_bytes([
        packet[tcp_start + 8], packet[tcp_start + 9],
        packet[tcp_start + 10], packet[tcp_start + 11]
    ]);
    let flags = packet[tcp_start + 13];
    
    let data_offset = ((packet[tcp_start + 12] >> 4) & 0x0F) as usize * 4;
    if data_offset < 20 {
        return Err(TLS_JA4_INVALID_PACKET);
    }
    
    Ok(TcpHeader {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        header_len: data_offset,
        payload_offset: tcp_start + data_offset,
    })
}

/// 生成流键
#[allow(dead_code)]
fn generate_flow_key(src_ip: &[u8; 16], dst_ip: &[u8; 16], src_port: u16, dst_port: u16) -> String {
    // 确保流键的一致性（总是使用较小的IP:端口作为源）
    let (ip1, port1, ip2, port2) = if src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port) {
        (src_ip, src_port, dst_ip, dst_port)
    } else {
        (dst_ip, dst_port, src_ip, src_port)
    };
    
    format!("{}:{}->{}:{}", 
        format_ip(ip1), port1,
        format_ip(ip2), port2)
}

/// 解析VLAN标签
pub fn parse_vlan_tags(data: &[u8]) -> (Vec<VlanTag>, usize, u16) {
    let mut vlan_tags = Vec::new();
    let mut offset = 0;
    let mut ether_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;
    
    // 检查是否有VLAN标签
    while ether_type == 0x8100 || ether_type == 0x88a8 || ether_type == 0x9100 {
        if offset + 4 > data.len() {
            break;
        }
        
        // 解析VLAN标签
        let vlan_tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let priority = ((vlan_tci >> 13) & 0x07) as u8;
        let vlan_id = vlan_tci & 0x0FFF;
        
        ether_type = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
        
        vlan_tags.push(VlanTag {
            vlan_id,
            priority,
            ether_type,
        });
        
        offset += 4;
    }
    
    (vlan_tags, offset, ether_type)
}

/// 从数据包中提取TCP流信息（支持分段重组）
pub fn extract_tcp_stream_from_packet(data: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16, u32, u32, Vec<u8>)> {
    if data.len() < 14 {
        return None;
    }
    
    // 解析以太网头部
    let ethernet = EthernetPacket::new(data)?;
    let _ether_type = ethernet.get_ethertype();
    let _offset = 14; // 以太网头部长度

    // 处理VLAN标签
    let (_vlan_tags, vlan_offset, final_ether_type) = parse_vlan_tags(&data[12..]);
    let offset = 12 + vlan_offset;
    let ether_type = match final_ether_type {
        0x0800 => EtherTypes::Ipv4,
        0x86DD => EtherTypes::Ipv6,
        _ => return None,
    };
    
    // 检查是否为IPv4或IPv6
    match ether_type {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(&data[offset..])?;
            let src_ip = IpAddr::V4(ipv4.get_source());
            let dst_ip = IpAddr::V4(ipv4.get_destination());
            
            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                let ip_header_length = (ipv4.get_header_length() as usize) * 4;
                let tcp_offset = offset + ip_header_length;
                
                if let Some(tcp) = TcpPacket::new(&data[tcp_offset..]) {
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let seq = tcp.get_sequence();
                    let ack = tcp.get_acknowledgement();
                    let tcp_header_length = (tcp.get_data_offset() as usize) * 4;
                    let payload_offset = tcp_offset + tcp_header_length;
                    
                    if payload_offset < data.len() {
                        let payload = data[payload_offset..].to_vec();
                        return Some((src_ip, dst_ip, src_port, dst_port, seq, ack, payload));
                    }
                }
            }
        }
        EtherTypes::Ipv6 => {
            let ipv6 = Ipv6Packet::new(&data[offset..])?;
            let src_ip = IpAddr::V6(ipv6.get_source());
            let dst_ip = IpAddr::V6(ipv6.get_destination());
            
            if ipv6.get_next_header() == IpNextHeaderProtocols::Tcp {
                let tcp_offset = offset + 40; // IPv6头部固定40字节
                
                if let Some(tcp) = TcpPacket::new(&data[tcp_offset..]) {
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let seq = tcp.get_sequence();
                    let ack = tcp.get_acknowledgement();
                    let tcp_header_length = (tcp.get_data_offset() as usize) * 4;
                    let payload_offset = tcp_offset + tcp_header_length;
                    
                    if payload_offset < data.len() {
                        let payload = data[payload_offset..].to_vec();
                        return Some((src_ip, dst_ip, src_port, dst_port, seq, ack, payload));
                    }
                }
            }
        }
        _ => return None,
    }
    
    None
}

/// 从数据包中提取TLS数据（支持TCP和UDP/QUIC）
pub fn extract_tls_data_from_packet(data: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16, Vec<u8>)> {
    if data.len() < 14 {
        return None;
    }
    
    // 解析以太网头部
    let ethernet = EthernetPacket::new(data)?;
    let _ether_type = ethernet.get_ethertype();
    let _offset = 14; // 以太网头部长度

    // 处理VLAN标签
    let (_vlan_tags, vlan_offset, final_ether_type) = parse_vlan_tags(&data[12..]);
    let offset = 12 + vlan_offset;
    let ether_type = match final_ether_type {
        0x0800 => EtherTypes::Ipv4,
        0x86DD => EtherTypes::Ipv6,
        _ => return None,
    };
    
    // 检查是否为IPv4或IPv6
    match ether_type {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(&data[offset..])?;
            let src_ip = IpAddr::V4(ipv4.get_source());
            let dst_ip = IpAddr::V4(ipv4.get_destination());
            
            // 调试：打印IP包信息
            println!("🔍 IPv4包: {} -> {}, 协议: {}", src_ip, dst_ip, ipv4.get_next_level_protocol());
            
            // 处理TCP协议
            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                let ip_header_length = (ipv4.get_header_length() as usize) * 4;
                let tcp_offset = offset + ip_header_length;
                
                if let Some(tcp) = TcpPacket::new(&data[tcp_offset..]) {
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let tcp_header_length = (tcp.get_data_offset() as usize) * 4;
                    let payload_offset = tcp_offset + tcp_header_length;
                    
                    if payload_offset < data.len() {
                        let tls_data = data[payload_offset..].to_vec();
                        if is_tls_packet(&tls_data) {
                            return Some((src_ip, dst_ip, src_port, dst_port, tls_data));
                        }
                    }
                }
            }
            // 处理UDP/QUIC协议
            else if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        println!("🔍 检测到UDP协议包");
                        let ip_header_length = (ipv4.get_header_length() as usize) * 4;
                        let udp_offset = offset + ip_header_length;
                        
                        if let Some(udp) = UdpPacket::new(&data[udp_offset..]) {
                            let src_port = udp.get_source();
                            let dst_port = udp.get_destination();
                            let udp_data = udp.payload().to_vec();
                            
                            // 调试：打印UDP包信息
                            if udp_data.len() > 0 {
                                println!("🔍 UDP包: {}:{} -> {}:{}, 长度: {}, 前4字节: {:02x?}", 
                                    src_ip, src_port, dst_ip, dst_port, udp_data.len(), 
                                    &udp_data[..udp_data.len().min(4)]);
                                
                                // 调试QUIC检测过程
                                let first_byte = udp_data[0];
                                let packet_type = (first_byte & 0x30) >> 4;
                                println!("  第一个字节: 0x{:02x}, 最高位: {}, Packet Type: {}", 
                                    first_byte, (first_byte & 0x80) != 0, packet_type);
                                
                                if udp_data.len() >= 5 {
                                    let version = u32::from_be_bytes([udp_data[1], udp_data[2], udp_data[3], udp_data[4]]);
                                    println!("  版本字段: 0x{:08x}", version);
                                }
                            }
                            
                            // 检查是否为QUIC协议
                            if is_quic_packet(&udp_data) {
                                println!("✅ 检测到QUIC包!");
                                return Some((src_ip, dst_ip, src_port, dst_port, udp_data));
                            }
                        } else {
                            println!("❌ UDP包解析失败");
                        }
                    }
        }
        EtherTypes::Ipv6 => {
            let ipv6 = Ipv6Packet::new(&data[offset..])?;
            let src_ip = IpAddr::V6(ipv6.get_source());
            let dst_ip = IpAddr::V6(ipv6.get_destination());
            
            // 处理TCP协议
            if ipv6.get_next_header() == IpNextHeaderProtocols::Tcp {
                let tcp_offset = offset + 40; // IPv6头部固定40字节
                
                if let Some(tcp) = TcpPacket::new(&data[tcp_offset..]) {
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let tcp_header_length = (tcp.get_data_offset() as usize) * 4;
                    let payload_offset = tcp_offset + tcp_header_length;
                    
                    if payload_offset < data.len() {
                        let tls_data = data[payload_offset..].to_vec();
                        if is_tls_packet(&tls_data) {
                            return Some((src_ip, dst_ip, src_port, dst_port, tls_data));
                        }
                    }
                }
            }
            // 处理UDP/QUIC协议
            else if ipv6.get_next_header() == IpNextHeaderProtocols::Udp {
                let udp_offset = offset + 40; // IPv6头部固定40字节
                
                if let Some(udp) = UdpPacket::new(&data[udp_offset..]) {
                    let src_port = udp.get_source();
                    let dst_port = udp.get_destination();
                    let udp_data = udp.payload().to_vec();
                    
                    // 检查是否为QUIC协议
                    if is_quic_packet(&udp_data) {
                        return Some((src_ip, dst_ip, src_port, dst_port, udp_data));
                    }
                }
            }
        }
        _ => return None,
    }
    
    None
}

/// 使用tls-parser解析Client Hello
pub fn parse_client_hello_with_tls_parser(packet: &[u8]) -> Option<(TlsVersion, Vec<u16>, Vec<u16>, Vec<u16>, Vec<u8>, Vec<u16>)> {
    // 使用tls-parser解析TLS报文
    match parse_tls_plaintext(packet) {
        Ok((remaining, tls_record)) => {
            // 检查是否完全解析
            if !remaining.is_empty() {
                // 还有剩余数据，可能是多个TLS记录或其他数据
                // 这里暂时忽略，只处理第一个记录
            }
            
            // 检查TLS记录类型
            for msg in &tls_record.msg {
                if let TlsMessage::Handshake(handshake) = msg {
                    if let TlsMessageHandshake::ClientHello(client_hello) = handshake {
                    // 提取所需字段
                    let version = client_hello.version;
                    
                    // 提取密码套件
                    let cipher_suites: Vec<u16> = client_hello.ciphers.iter()
                        .map(|cipher| cipher.0)
                        .collect();
                    
                    // 从实际的Client Hello中解析扩展数据
                    let (extensions, elliptic_curves, ec_point_formats, _signature_algorithms) = 
                        if let Some(ref extensions_data) = client_hello.ext {
                            parse_tls_extensions_correctly(extensions_data)
                        } else {
                            (Vec::new(), vec![29u16, 23, 30, 25, 24], vec![0u8, 1, 2], vec![0x0403u16, 0x0503, 0x0603])
                        };
                    
                    return Some((version, cipher_suites, extensions, elliptic_curves, ec_point_formats, _signature_algorithms));
                    }
                }
            }
        }
        Err(_) => {
            // 解析失败
            return None;
        }
    }
    
    None
}

/// 计算JA4指纹
pub fn calculate_ja4_from_parsed_data(version: TlsVersion, cipher_suites: &[u16], extensions: &[u16], _signature_algorithms: &[u16], client_hello_data: &[u8]) -> String {
    // 1. TLS版本 - 读取数据包中的最高版本（supported_versions扩展或协商版本）
    // 根据JA4标准，需要读取客户端支持的最高版本，不是协商版本
    let mut highest_version = version;
    if extensions.contains(&43) {
        // 如果有supported_versions扩展(43)，则客户端支持更高版本
        // 这里简化处理，假设有该扩展就表示支持TLS 1.3
        highest_version = TlsVersion::Tls13;
    }
    
    // 协议标识：t=TCP, q=QUIC
    let protocol = "t";
    
    let version_str = match highest_version {
        TlsVersion::Ssl30 => format!("{}s3", protocol),
        TlsVersion::Tls10 => format!("{}10", protocol),
        TlsVersion::Tls11 => format!("{}11", protocol), 
        TlsVersion::Tls12 => format!("{}12", protocol),
        TlsVersion::Tls13 => format!("{}13", protocol),
        _ => format!("{}00", protocol),
    };
    
    // 2. SNI (Server Name Indication) - 检测扩展0 (SNI)
    // d = Domain (SNI存在，访问域名), i = IP (SNI不存在，访问IP)
    let sni_flag = if extensions.contains(&0) {
        "d" // SNI present -> 访问域名
    } else {
        "i" // SNI not present -> 访问IP
    };
    
    // 3. 密码套件计数 (排序后) - 根据正确格式，使用十进制
    let mut sorted_ciphers: Vec<u16> = cipher_suites.iter()
        .filter(|&&c| !is_grease_value(c))
        .copied()
        .collect();
    sorted_ciphers.sort();
    let cipher_count = format!("{:02}", sorted_ciphers.len().min(99));  // 使用十进制格式
    
    
    // 4. 扩展计数 (排序后) - 根据正确格式，使用十进制
    // 注意：JA4标准中可能包含所有扩展，不排除任何扩展
    let sorted_extensions: Vec<u16> = extensions.iter()
        .filter(|&&e| !is_grease_value(e)) // 只排除GREASE值
        .copied()
        .collect();
    let extension_count = format!("{:02}", sorted_extensions.len().min(99));  // 使用十进制格式
    
    // 5. ALPN - 从扩展16中解析实际的ALPN值
    let alpn_flag = extract_alpn_from_client_hello(client_hello_data)
        .unwrap_or_else(|| "00".to_string());
    
    // 构建第一部分 - 根据正确格式，应该是t13i3111h1
    let part1 = format!("{}{}{}{}{}", version_str, sni_flag, cipher_count, extension_count, alpn_flag);
    
    // JA4_b = 密码套件排序哈希 (传递引用避免clone)
    let ja4_b = calculate_ja4b_from_parsed_data(cipher_suites);
    
    // JA4_c = 扩展和签名算法排序哈希 (传递引用避免clone)
    let ja4_c = calculate_ja4c_from_parsed_data(extensions, _signature_algorithms);
    
    // 构建完整的JA4指纹：JA4_a_JA4_b_JA4_c
    format!("{}_{}_{}",  part1, ja4_b, ja4_c)
}

/// 计算JA4_b组件
pub fn calculate_ja4b_from_parsed_data(cipher_suites: &[u16]) -> String {
    // JA4_b算法：对Cipher Suite进行排序，然后计算SHA256哈希的前12位
    // 排序是为了降低"Cipher Stunting"的影响
    
    // 1. 过滤并排序GREASE值（避免中间Vec分配）
    let mut sorted_ciphers: Vec<u16> = cipher_suites.iter()
        .filter(|&&c| !is_grease_value(c))
        .copied()
        .collect();
    
    // 2. 从小到大排序
    sorted_ciphers.sort();
    
    // 3. 转换为十六进制字符串，用逗号分隔
    let cipher_str = sorted_ciphers.iter()
        .map(|&c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");

    let mut hasher = Sha256::new();
    hasher.update(cipher_str.as_bytes());
    let hash = hasher.finalize();

    let ja4b = hex::encode(&hash[..6]); // Take first 6 bytes = 12 chars
    ja4b
}

/// 计算JA4_c组件
pub fn calculate_ja4c_from_parsed_data(extensions: &[u16], _signature_algorithms: &[u16]) -> String {
    // JA4_c算法：对Extensions进行排序并过滤，结合_signature_algorithms
    // 用来对抗Extension随机化问题
    
    // 1. 过滤Extensions - 移除GREASE值、SNI扩展(0)和ALPN扩展(16)
    let mut filtered_extensions: Vec<u16> = extensions.iter()
        .filter(|&&ext| {
            !is_grease_value(ext) && // 过滤GREASE值
            ext != 0x0000 && // 过滤SNI扩展
            ext != 0x0010    // 过滤ALPN扩展
        })
        .copied()
        .collect();
    
    // 2. 从小到大排序
    filtered_extensions.sort();
    
    // 3. 转换为十六进制字符串，用逗号分隔
    let ext_str = filtered_extensions.iter()
        .map(|&e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");
    
    // 4. 处理_signature_algorithms - 保持原始顺序（不排序），但过滤GREASE值
    let filtered_sig_algs: Vec<u16> = _signature_algorithms.iter()
        .filter(|&&s| !is_grease_value(s))
        .copied()
        .collect();
    let sig_str = filtered_sig_algs.iter()
        .map(|&s| format!("{:04x}", s))
        .collect::<Vec<_>>()
        .join(",");
    
    // 5. 合并两个字符串，用下划线分隔
    let combined_str = if sig_str.is_empty() {
        ext_str.clone()
    } else {
        format!("{}_{}", ext_str, sig_str)
    };

    let mut hasher = Sha256::new();
    hasher.update(combined_str.as_bytes());
    let hash = hasher.finalize();

    let ja4c = hex::encode(&hash[..6]); // Take first 6 bytes = 12 chars
    ja4c
}

/// 计算JA3指纹
pub fn calculate_ja3_from_parsed_data(version: TlsVersion, cipher_suites: &[u16], extensions: &[u16], elliptic_curves: &[u16], ec_point_formats: &[u8]) -> Option<String> {
    // 使用tls-parser解析的Client Hello计算JA3
    let version_str = match version {
        TlsVersion::Ssl30 => "768",   // 0x0300
        TlsVersion::Tls10 => "769",   // 0x0301  
        TlsVersion::Tls11 => "770",   // 0x0302
        TlsVersion::Tls12 => "771",   // 0x0303
        TlsVersion::Tls13 => "772",   // 0x0304
        _ => "0",
    };
    
    // 密码套件（保持原始顺序，不要排序！但要过滤GREASE值）
    let cipher_str = cipher_suites.iter()
        .filter(|&&c| !is_grease_value(c))
        .map(|&s| s.to_string())
        .collect::<Vec<_>>()
        .join("-");
    
    // 扩展（保持原始顺序，不要排序！但要过滤GREASE值）
    let ext_str = extensions.iter()
        .filter(|&&e| !is_grease_value(e))
        .map(|&e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");
    
    // 4. 椭圆曲线组 (从supported_groups扩展中提取，过滤GREASE值)
    let curves_str = if !elliptic_curves.is_empty() {
        elliptic_curves.iter()
            .filter(|&&curve| !is_grease_value(curve))
            .map(|&curve| curve.to_string())
            .collect::<Vec<_>>()
            .join("-")
    } else {
        // 如果没有解析到椭圆曲线，使用默认值
        "29-23-30-25-24".to_string()
    };
    
    // 5. 椭圆曲线点格式 (从ec_point_formats扩展中提取)
    let formats_str = if !ec_point_formats.is_empty() {
        ec_point_formats.iter()
            .map(|&fmt| fmt.to_string())
            .collect::<Vec<_>>()
            .join("-")
    } else {
        // 如果没有解析到点格式，使用默认值
        "0-1-2".to_string()
    };
    
    // JA3 格式: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    let ja3_string = format!("{},{},{},{},{}", version_str, cipher_str, ext_str, curves_str, formats_str);
    
    // 计算MD5哈希
    let hash = md5::compute(ja3_string.as_bytes());
    let hash_hex = format!("{:x}", hash);
    
    Some(hash_hex)
}

/// 加载配置文件
pub fn load_config(config_path: &str) -> Result<Config> {
    use std::fs;
    
    if std::path::Path::new(config_path).exists() {
        let config_data = fs::read_to_string(config_path)?;
        let config: Config = serde_json::from_str(&config_data)?;
        Ok(config)
    } else {
        // 如果配置文件不存在，使用默认配置
        Ok(Config {
            include_server_hello: default_include_server_hello(),
            max_packets_per_session: default_max_packets_per_session(),
            include_ja3: default_include_ja3(),
            verbose: default_verbose(),
        })
    }
}

/// 处理pcap文件（支持分段TLS Hello包）
pub fn process_pcap_file(input_path: &str, config: &Config) -> Result<(HashMap<String, TlsSession>, usize, usize)> {
    let mut cap = Capture::from_file(input_path)?;
    let mut sessions: HashMap<String, TlsSession> = HashMap::new();
    let mut stream_buffers: HashMap<String, BidirectionalTcpStream> = HashMap::new();
    let mut total_packets = 0;
    let mut tls_packets = 0;
    let mut _client_hellos = 0;

    while let Ok(packet) = cap.next_packet() {
        total_packets += 1;
        println!("🔍 处理数据包 #{}: 长度 {}", total_packets, packet.data.len());
        
        // 首先尝试直接提取TLS数据（用于非分段的包）
        if let Some((src_ip, dst_ip, src_port, dst_port, tls_data)) = extract_tls_data_from_packet(packet.data) {
            tls_packets += 1;
            println!("🔍 提取到数据包: {}:{} -> {}:{}, 长度: {}", src_ip, src_port, dst_ip, dst_port, tls_data.len());
            
            // 检查是否为QUIC协议
            if is_quic_packet(&tls_data) {
                //todo
            }

            // 处理TLS协议
            else if let Some((version, ciphers, extensions, elliptic_curves, ec_point_formats, _signature_algorithms)) = parse_client_hello_with_tls_parser(&tls_data) {
                _client_hellos += 1;
                
                // Client Hello总是从客户端发往服务器
                let session_key = generate_session_key(src_ip, src_port, dst_ip, dst_port, true);
                let session = sessions.entry(session_key.clone()).or_insert_with(|| {
                    TlsSession {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        client_hellos: Vec::new(),
                        server_hellos: Vec::new(),
                        ja3_fingerprints: Vec::new(),
                    }
                });
                
                // 检查是否已经处理过相同的Client Hello（避免重复）
                let is_duplicate = session.client_hellos.iter().any(|existing| {
                    existing.len() == tls_data.len() && existing == &tls_data
                });
                
                // 避免重复处理
                
                if !is_duplicate && session.client_hellos.len() < config.max_packets_per_session {
                    session.client_hellos.push(tls_data.clone());
                    
                    // 计算JA3指纹
                    if config.include_ja3 {
                        if let Some(ja3) = calculate_ja3_from_parsed_data(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats) {
                            session.ja3_fingerprints.push(ja3);
                        }
                    }
                }
            }
        } else {
            // 如果不是完整的TLS包，尝试TCP流重组
            if let Some((src_ip, dst_ip, src_port, dst_port, seq, _ack, payload)) = extract_tcp_stream_from_packet(packet.data) {
                if !payload.is_empty() {
                    // 使用时间戳作为简单的时间标识
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    
                    // 重组TCP流
                    let tls_records = reassemble_tcp_stream(
                        &mut stream_buffers,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        seq,
                        &payload,
                        timestamp,
                    );
                    
                    // 处理重组后的TLS记录
                    for tls_data in tls_records {
                        tls_packets += 1;
                        
                        if let Some((version, ciphers, extensions, elliptic_curves, ec_point_formats, _signature_algorithms)) = parse_client_hello_with_tls_parser(&tls_data) {
                            _client_hellos += 1;
                            
                            // 确定Client Hello的方向：通常从低端口发往高端口
                            let is_client_to_server = src_port < dst_port;
                            let session_key = generate_session_key(src_ip, src_port, dst_ip, dst_port, is_client_to_server);
                            let session = sessions.entry(session_key.clone()).or_insert_with(|| {
                                TlsSession {
                                    src_ip,
                                    dst_ip,
                                    src_port,
                                    dst_port,
                                    client_hellos: Vec::new(),
                                    server_hellos: Vec::new(),
                                    ja3_fingerprints: Vec::new(),
                                }
                            });
                            
                            // 检查是否已经处理过相同的Client Hello（避免重复）
                            let is_duplicate = session.client_hellos.iter().any(|existing| {
                                existing.len() == tls_data.len() && existing == &tls_data
                            });
                            
                            // 避免重复处理
                            
                            if !is_duplicate && session.client_hellos.len() < config.max_packets_per_session {
                                session.client_hellos.push(tls_data.clone());
                                
                                // 计算JA3指纹
                                if config.include_ja3 {
                                    if let Some(ja3) = calculate_ja3_from_parsed_data(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats) {
                                        session.ja3_fingerprints.push(ja3);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok((sessions, total_packets, tls_packets))
}

/// 保存指纹数据到文件
pub fn save_fingerprints_to_file(
    sessions: &HashMap<String, TlsSession>,
    total_packets: usize,
    tls_packets: usize,
    output_path: &str,
) -> Result<()> {
    use std::fs::File;
    use std::io::Write;
    
    let analysis_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    
    let mut fingerprint_sessions = Vec::new();
    
    for (session_key, session) in sessions {
        // 解析会话键
        let parts: Vec<&str> = session_key.split(" -> ").collect();
        if parts.len() != 2 {
            continue;
        }
        
        let src_parts: Vec<&str> = parts[0].split(':').collect();
        let dst_parts: Vec<&str> = parts[1].split(':').collect();
        
        if src_parts.len() != 2 || dst_parts.len() != 2 {
            continue;
        }
        
        let src_ip = src_parts[0].to_string();
        let src_port = src_parts[1].parse::<u16>().unwrap_or(0);
        let dst_ip = dst_parts[0].to_string();
        let dst_port = dst_parts[1].parse::<u16>().unwrap_or(0);
        
        // 为每个client hello计算JA4和JA3
        let mut ja4_fingerprints = Vec::new();
        let mut ja4b_fingerprints = Vec::new();
        let mut ja4c_fingerprints = Vec::new();
        
        for client_hello in &session.client_hellos {
            if let Some((version, ciphers, extensions, _elliptic_curves, _ec_point_formats, _signature_algorithms)) = parse_client_hello_with_tls_parser(client_hello) {
                let ja4 = calculate_ja4_from_parsed_data(version, &ciphers, &extensions, &_signature_algorithms, client_hello);
                let ja4b = calculate_ja4b_from_parsed_data(&ciphers);
                let ja4c = calculate_ja4c_from_parsed_data(&extensions, &_signature_algorithms);
                
                ja4_fingerprints.push(ja4);
                ja4b_fingerprints.push(ja4b);
                ja4c_fingerprints.push(ja4c);
            }
        }
        
        let fingerprint_data = FingerprintData {
            timestamp: analysis_time,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            ja4_fingerprints,
            ja4b_fingerprints,
            ja4c_fingerprints,
            ja3_fingerprints: session.ja3_fingerprints.clone(),
            client_hello_count: session.client_hellos.len(),
            server_hello_count: session.server_hellos.len(),
        };
        
        fingerprint_sessions.push(fingerprint_data);
    }
    
    let report = FingerprintReport {
        analysis_time,
        total_sessions: sessions.len(),
        total_packets,
        tls_packets,
        sessions: fingerprint_sessions,
    };
    
    let json_data = serde_json::to_string_pretty(&report)?;
    let mut file = File::create(output_path)?;
    file.write_all(json_data.as_bytes())?;
    
    Ok(())
}


/// 检查是否有SNI扩展
pub fn has_sni_extension(client_hello_data: &[u8]) -> bool {
    if let Some((_, _, _, _, _, _)) = parse_client_hello_with_tls_parser(client_hello_data) {
        // 使用tls-parser检查扩展
        use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake};
        
        if let Ok((_, tls_plaintext)) = parse_tls_plaintext(client_hello_data) {
            if let Some(handshake) = tls_plaintext.msg.first() {
                if let TlsMessage::Handshake(handshake_msg) = handshake {
                    if let TlsMessageHandshake::ClientHello(client_hello) = handshake_msg {
                        if let Some(extensions_data) = &client_hello.ext {
                            match tls_parser::parse_tls_extensions(extensions_data) {
                                Ok((_, parsed_extensions)) => {
                                    for extension in parsed_extensions {
                                        if let tls_parser::TlsExtension::SNI(sni_list) = extension {
                                            return !sni_list.is_empty();
                                        }
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                    }
                }
            }
        }
    }
    
    false
}


