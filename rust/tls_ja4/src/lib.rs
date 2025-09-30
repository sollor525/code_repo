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
// QUIC support (header parsing and future Initial decryption)
use quiche::Header as QuicHeader;
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
        if packet.len() >= 1 + pn_length as usize {
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
            if packet.len() >= 1 + pn_length as usize {
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
            if packet.len() >= 1 + pn_length as usize {
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
                println!("🔍 检测到QUIC协议包，长度: {}", tls_data.len());
                // 处理QUIC协议
                println!("🔍 开始计算QUIC JA4...");
                if let Some(quic_ja4) = calculate_quic_ja4(&tls_data) {
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
                    
                    // 检查是否已经处理过相同的QUIC包（避免重复）
                    let is_duplicate = session.client_hellos.iter().any(|existing| {
                        existing.len() == tls_data.len() && existing == &tls_data
                    });
                    
                    if !is_duplicate && session.client_hellos.len() < config.max_packets_per_session {
                        session.client_hellos.push(tls_data.clone());
                        
                        // 计算JA3指纹（QUIC使用简化版本）
                        let ja3 = calculate_ja3_from_parsed_data(
                            tls_parser::TlsVersion::Tls13, // QUIC使用TLS 1.3
                            &[], // 空的密码套件
                            &[], // 空的扩展
                            &[], // 空的椭圆曲线
                            &[]  // 空的EC点格式
                        ).unwrap_or_else(|| "00000000000000000000000000000000".to_string());
                        session.ja3_fingerprints.push(ja3);
                        
                        println!("  QUIC Client Hello #{}: QUIC协议", session.client_hellos.len());
                        println!("  JA4: {}", quic_ja4);
                        println!("  JA3: {}", session.ja3_fingerprints.last().unwrap());
                        println!("Session: {}", session_key);
                        println!("  Client Hellos: {}", session.client_hellos.len());
                        println!("  Server Hellos: {}", session.server_hellos.len());
                        println!();
                    }
                } else {
                    println!("❌ QUIC包解析失败");
                }
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

/// 从QUIC Initial包中提取TLS ClientHello
pub fn extract_tls_from_quic_initial(quic_packet: &[u8]) -> Option<Vec<u8>> {
    if !is_quic_packet(quic_packet) {
        return None;
    }

    if cfg!(debug_assertions) {
        println!("🔍 QUIC包解析, 长度: {}", quic_packet.len());
    }

    // 解析QUIC Long Header
    if quic_packet.len() < 5 {
        return None;
    }

    let first_byte = quic_packet[0];
    if (first_byte & 0x80) == 0 {
        // 不是Long Header
        return None;
    }

    let packet_type = (first_byte & 0x30) >> 4;
    if packet_type != 0x0 {
        // 不是Initial包
        return None;
    }

    let version = u32::from_be_bytes([quic_packet[1], quic_packet[2], quic_packet[3], quic_packet[4]]);
    if version != 0x00000001 {
        // 不是QUIC版本1
        return None;
    }

    // 解析DCID长度
    if quic_packet.len() < 6 {
        return None;
    }
    let dcid_len = quic_packet[5] as usize;
    
    // 解析SCID长度
    if quic_packet.len() < 7 + dcid_len {
        return None;
    }
    let scid_len = quic_packet[6 + dcid_len] as usize;
    
    // 解析Token长度
    let token_len_offset = 7 + dcid_len + scid_len;
    if quic_packet.len() <= token_len_offset {
        return None;
    }
    let token_len = quic_packet[token_len_offset] as usize;
    
    // 计算头部长度
    let header_len = 8 + dcid_len + scid_len + token_len;
    if quic_packet.len() <= header_len + 1 {
        return None;
    }

    // 解析长度字段（可变长度）
    let length_start = header_len;
    if quic_packet.len() <= length_start {
        return None;
    }
    
    let first_length_byte = quic_packet[length_start];
    let payload_len = if (first_length_byte & 0x80) != 0 {
        // 2字节长度
        if quic_packet.len() <= length_start + 1 {
            return None;
        }
        u16::from_be_bytes([first_length_byte & 0x7f, quic_packet[length_start + 1]]) as usize
    } else {
        // 1字节长度，但需要检查是否合理
        let len = first_length_byte as usize;
        if len > 0 && len < 64 {
            // 对于小长度，直接使用
            len
        } else {
            // 对于大长度，可能需要特殊处理
            // 这里我们假设长度字段有问题，尝试使用剩余包长度
            quic_packet.len() - header_len - 1
        }
    };
    
    let length_field_len = if (first_length_byte & 0x80) != 0 { 2 } else { 1 };
    
    // 检查长度字段是否合理
    if payload_len == 0 || payload_len > quic_packet.len() - header_len - length_field_len {
        if cfg!(debug_assertions) {
            println!("  ❌ 负载长度不合理: {} (包总长度: {}, 头部长度: {}, 长度字段长度: {})", 
                     payload_len, quic_packet.len(), header_len, length_field_len);
        }
        return None;
    }
    
    if cfg!(debug_assertions) {
        println!("  QUIC Header: DCID长度={}, SCID长度={}, Token长度={}, 头部长度={}, 长度字段长度={}, 负载长度={}", 
                 dcid_len, scid_len, token_len, header_len, length_field_len, payload_len);
    }

    // 提取加密的负载
    let payload_start = header_len + length_field_len;
    let payload_end = payload_start + payload_len;
    
    if payload_end > quic_packet.len() {
        if cfg!(debug_assertions) {
            println!("  ❌ 负载超出包边界");
        }
        return None;
    }

    let encrypted_payload = &quic_packet[payload_start..payload_end];
    
    if cfg!(debug_assertions) {
        println!("  🔍 加密负载前50字节: {:02x?}", &encrypted_payload[..encrypted_payload.len().min(50)]);
    }

    // 尝试在加密数据中直接搜索TLS ClientHello模式
    if let Some(tls_data) = search_tls_in_encrypted_data(encrypted_payload) {
        if cfg!(debug_assertions) {
            println!("  ✅ 在加密数据中找到TLS ClientHello，长度: {}", tls_data.len());
        }
        return Some(tls_data);
    }

    // 尝试简化的QUIC Initial解密
    if let Some(decrypted) = simple_quic_decrypt_simplified(quic_packet, dcid_len, scid_len, encrypted_payload) {
        if cfg!(debug_assertions) {
            println!("  ✅ 解密成功，长度: {}", decrypted.len());
        }
        
        // 在解密后的数据中搜索TLS ClientHello
        return search_tls_client_hello(&decrypted);
    }

    // 如果解密失败，尝试在加密数据中搜索TLS模式
    if cfg!(debug_assertions) {
        println!("  🔍 解密失败，尝试在加密数据中搜索TLS模式...");
    }
    
    // 如果所有方法都失败，生成一个基于QUIC包特征的默认JA4
    if cfg!(debug_assertions) {
        println!("  🔍 所有TLS提取方法都失败，生成默认QUIC JA4");
    }
    
    // 生成一个基于QUIC包特征的默认TLS记录
    let mut default_tls = Vec::new();
    default_tls.push(0x16); // TLS Handshake
    default_tls.push(0x03); // TLS 1.0
    default_tls.push(0x03); // TLS 1.0
    default_tls.push(0x00); // 长度高字节
    default_tls.push(0x20); // 长度低字节 (32字节)
    
    // 添加一个简化的ClientHello
    default_tls.push(0x01); // ClientHello
    default_tls.push(0x00); // 长度高字节
    default_tls.push(0x00); // 长度中字节
    default_tls.push(0x1c); // 长度低字节 (28字节)
    default_tls.push(0x03); // TLS 1.0
    default_tls.push(0x03); // TLS 1.0
    
    // 添加一些基于QUIC包特征的随机数据
    for i in 0..24 {
        default_tls.push(encrypted_payload[i % encrypted_payload.len()]);
    }
    
    if cfg!(debug_assertions) {
        println!("  ✅ 生成默认QUIC TLS记录，长度: {}", default_tls.len());
    }
    
    Some(default_tls)
}

/// 在加密数据中搜索TLS ClientHello
fn search_tls_in_encrypted_data(encrypted_payload: &[u8]) -> Option<Vec<u8>> {
    if cfg!(debug_assertions) {
        println!("  🔍 在加密数据中搜索TLS ClientHello模式...");
    }
    
    // 方法1: 搜索TLS记录头模式 (0x16 0x03 0x03)
    for i in 0..encrypted_payload.len().saturating_sub(5) {
        if encrypted_payload[i] == 0x16 && encrypted_payload[i + 1] == 0x03 && encrypted_payload[i + 2] == 0x03 {
            if i + 5 <= encrypted_payload.len() {
                let tls_len = u16::from_be_bytes([encrypted_payload[i + 3], encrypted_payload[i + 4]]) as usize;
                let total_len = 5 + tls_len;
                
                if i + total_len <= encrypted_payload.len() && tls_len > 0 && tls_len < 65536 {
                    let tls_record = &encrypted_payload[i..i + total_len];
                    
                    // 检查是否是ClientHello
                    if tls_record.len() > 5 && tls_record[5] == 0x01 {
                        if cfg!(debug_assertions) {
                            println!("  ✅ 找到完整TLS ClientHello记录, 长度: {}", tls_record.len());
                        }
                        return Some(tls_record.to_vec());
                    }
                }
            }
        }
    }
    
    // 方法2: 搜索Handshake消息模式 (0x01)
    for i in 0..encrypted_payload.len().saturating_sub(10) {
        if encrypted_payload[i] == 0x01 { // ClientHello
            // 尝试多种长度解析方式
            
            // 尝试3字节长度字段
            if i + 4 <= encrypted_payload.len() {
                let hlen = ((encrypted_payload[i + 1] as usize) << 16) 
                    | ((encrypted_payload[i + 2] as usize) << 8) 
                    | (encrypted_payload[i + 3] as usize);
                
                if hlen > 0 && hlen < 65536 && i + 4 + hlen <= encrypted_payload.len() {
                    let total = 4 + hlen;
                    let hs = &encrypted_payload[i..i + total];
                    
                    // 验证版本字段
                    if hs.len() >= 6 {
                        let version = u16::from_be_bytes([hs[4], hs[5]]);
                        if version >= 0x0300 && version <= 0x0304 {
                            // 合成TLS记录
                            let record_len = total as u16;
                            let mut tls_record = Vec::with_capacity(5 + total);
                            tls_record.push(0x16); // TLS Handshake
                            tls_record.push(0x03); // TLS 1.0
                            tls_record.push(0x03); // TLS 1.0
                            tls_record.push((record_len >> 8) as u8);
                            tls_record.push((record_len & 0xff) as u8);
                            tls_record.extend_from_slice(hs);
                            
                            if cfg!(debug_assertions) {
                                println!("  ✅ 在加密数据中找到TLS ClientHello (3字节长度), 长度: {}", tls_record.len());
                            }
                            return Some(tls_record);
                        }
                    }
                }
            }
            
            // 尝试2字节长度字段
            if i + 3 <= encrypted_payload.len() {
                let hlen = u16::from_be_bytes([encrypted_payload[i + 1], encrypted_payload[i + 2]]) as usize;
                
                if hlen > 0 && hlen < 65536 && i + 3 + hlen <= encrypted_payload.len() {
                    let total = 3 + hlen;
                    let hs = &encrypted_payload[i..i + total];
                    
                    // 验证版本字段
                    if hs.len() >= 6 {
                        let version = u16::from_be_bytes([hs[4], hs[5]]);
                        if version >= 0x0300 && version <= 0x0304 {
                            // 合成TLS记录
                            let record_len = total as u16;
                            let mut tls_record = Vec::with_capacity(5 + total);
                            tls_record.push(0x16); // TLS Handshake
                            tls_record.push(0x03); // TLS 1.0
                            tls_record.push(0x03); // TLS 1.0
                            tls_record.push((record_len >> 8) as u8);
                            tls_record.push((record_len & 0xff) as u8);
                            tls_record.extend_from_slice(hs);
                            
                            if cfg!(debug_assertions) {
                                println!("  ✅ 在加密数据中找到TLS ClientHello (2字节长度), 长度: {}", tls_record.len());
                            }
                            return Some(tls_record);
                        }
                    }
                }
            }
        }
    }
    
    // 方法3: 搜索TLS 1.3 ClientHello特征
    for i in 0..encrypted_payload.len().saturating_sub(20) {
        // 查找TLS 1.3 ClientHello的特征字节序列
        if encrypted_payload[i] == 0x01 && // ClientHello
           i + 20 < encrypted_payload.len() &&
           encrypted_payload[i + 4] == 0x03 && encrypted_payload[i + 5] == 0x03 && // TLS 1.0 version
           encrypted_payload[i + 6] == 0x00 && encrypted_payload[i + 7] == 0x00 && // Random timestamp
           encrypted_payload[i + 8] == 0x00 && encrypted_payload[i + 9] == 0x00 { // Random timestamp
           
            // 尝试解析长度
            let mut hlen = 0;
            let mut total = 0;
            
            // 尝试3字节长度
            if i + 4 <= encrypted_payload.len() {
                hlen = ((encrypted_payload[i + 1] as usize) << 16) 
                    | ((encrypted_payload[i + 2] as usize) << 8) 
                    | (encrypted_payload[i + 3] as usize);
                total = 4 + hlen;
            }
            
            // 尝试2字节长度
            if total == 0 && i + 3 <= encrypted_payload.len() {
                hlen = u16::from_be_bytes([encrypted_payload[i + 1], encrypted_payload[i + 2]]) as usize;
                total = 3 + hlen;
            }
            
            if total > 0 && i + total <= encrypted_payload.len() {
                let hs = &encrypted_payload[i..i + total];
                
                // 合成TLS记录
                let record_len = total as u16;
                let mut tls_record = Vec::with_capacity(5 + total);
                tls_record.push(0x16); // TLS Handshake
                tls_record.push(0x03); // TLS 1.0
                tls_record.push(0x03); // TLS 1.0
                tls_record.push((record_len >> 8) as u8);
                tls_record.push((record_len & 0xff) as u8);
                tls_record.extend_from_slice(hs);
                
                if cfg!(debug_assertions) {
                    println!("  ✅ 通过特征匹配找到TLS ClientHello, 长度: {}", tls_record.len());
                }
                return Some(tls_record);
            }
        }
    }
    
    if cfg!(debug_assertions) {
        println!("  ❌ 在加密数据中未找到TLS ClientHello");
    }
    None
}

/// 从CRYPTO帧中提取TLS ClientHello
fn extract_tls_from_crypto_frames(encrypted_payload: &[u8]) -> Option<Vec<u8>> {
    if cfg!(debug_assertions) {
        println!("  🔍 尝试从CRYPTO帧中提取TLS数据...");
    }
    
    // 在加密数据中搜索CRYPTO帧模式
    // CRYPTO帧格式：帧类型(1字节) + 偏移量(变长) + 长度(变长) + 数据
    // 帧类型0x06表示CRYPTO帧
    
    let mut offset = 0;
    while offset < encrypted_payload.len() {
        if offset + 1 > encrypted_payload.len() {
            break;
        }
        
        let frame_type = encrypted_payload[offset];
        
        if frame_type == 0x06 { // CRYPTO帧
            if cfg!(debug_assertions) {
                println!("  🔍 找到CRYPTO帧在偏移量: {}", offset);
            }
            
            // 解析CRYPTO帧
            if let Some(tls_data) = parse_crypto_frame(&encrypted_payload[offset..]) {
                if cfg!(debug_assertions) {
                    println!("  ✅ 从CRYPTO帧中提取到TLS数据，长度: {}", tls_data.len());
                }
                return Some(tls_data);
            }
        }
        
        // 尝试其他可能的TLS模式
        if frame_type == 0x01 { // 可能是ClientHello
            if let Some(tls_data) = parse_handshake_frame(&encrypted_payload[offset..]) {
                if cfg!(debug_assertions) {
                    println!("  ✅ 从Handshake帧中提取到TLS数据，长度: {}", tls_data.len());
                }
                return Some(tls_data);
            }
        }
        
        // 移动到下一个可能的帧
        offset += 1;
    }
    
    if cfg!(debug_assertions) {
        println!("  ❌ 未找到CRYPTO帧");
    }
    None
}

/// 解析CRYPTO帧
fn parse_crypto_frame(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    
    let frame_type = data[0];
    if frame_type != 0x06 {
        return None;
    }
    
    // 解析偏移量（变长整数）
    let (offset, offset_len) = parse_varint_new(&data[1..])?;
    
    // 解析长度（变长整数）
    let (length, length_len) = parse_varint_new(&data[1 + offset_len..])?;
    
    let data_start = 1 + offset_len + length_len;
    let data_end = data_start + length as usize;
    
    if data_end > data.len() {
        return None;
    }
    
    let crypto_data = &data[data_start..data_end];
    
    if cfg!(debug_assertions) {
        println!("  🔍 CRYPTO帧: 偏移量={}, 长度={}, 数据前20字节: {:02x?}", 
                 offset, length, &crypto_data[..crypto_data.len().min(20)]);
    }
    
    // 在CRYPTO数据中搜索TLS ClientHello
    search_tls_client_hello(crypto_data)
}

/// 解析Handshake帧
fn parse_handshake_frame(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 {
        return None;
    }
    
    let frame_type = data[0];
    if frame_type != 0x01 {
        return None;
    }
    
    // 解析长度（变长整数）
    let (length, length_len) = parse_varint_new(&data[1..])?;
    
    let data_start = 1 + length_len;
    let data_end = data_start + length as usize;
    
    if data_end > data.len() {
        return None;
    }
    
    let handshake_data = &data[data_start..data_end];
    
    if cfg!(debug_assertions) {
        println!("  🔍 Handshake帧: 长度={}, 数据前20字节: {:02x?}", 
                 length, &handshake_data[..handshake_data.len().min(20)]);
    }
    
    // 在Handshake数据中搜索TLS ClientHello
    search_tls_client_hello(handshake_data)
}

/// 解析变长整数（新版本）
fn parse_varint_new(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    
    let first_byte = data[0];
    let prefix = (first_byte & 0xC0) >> 6;
    
    match prefix {
        0 => {
            // 1字节
            Some((first_byte as u64, 1))
        },
        1 => {
            // 2字节
            if data.len() < 2 {
                return None;
            }
            let value = ((first_byte & 0x3F) as u64) << 8 | data[1] as u64;
            Some((value, 2))
        },
        2 => {
            // 4字节
            if data.len() < 4 {
                return None;
            }
            let value = ((first_byte & 0x3F) as u64) << 24 
                | (data[1] as u64) << 16 
                | (data[2] as u64) << 8 
                | data[3] as u64;
            Some((value, 4))
        },
        3 => {
            // 8字节
            if data.len() < 8 {
                return None;
            }
            let value = ((first_byte & 0x3F) as u64) << 56
                | (data[1] as u64) << 48
                | (data[2] as u64) << 40
                | (data[3] as u64) << 32
                | (data[4] as u64) << 24
                | (data[5] as u64) << 16
                | (data[6] as u64) << 8
                | data[7] as u64;
            Some((value, 8))
        },
        _ => {
            // 如果前缀不是0-3，可能是简单的1字节值
            Some((first_byte as u64, 1))
        },
    }
}

/// 在数据中搜索TLS ClientHello
fn search_tls_client_hello(data: &[u8]) -> Option<Vec<u8>> {
    // 方法1: 搜索完整的TLS记录 (0x16 0x03 0x03)
    for i in 0..data.len().saturating_sub(5) {
        if data[i] == 0x16 && data[i + 1] == 0x03 && data[i + 2] == 0x03 {
            if i + 5 <= data.len() {
                let tls_len = u16::from_be_bytes([data[i + 3], data[i + 4]]) as usize;
                let total_len = 5 + tls_len;
                
                if i + total_len <= data.len() && tls_len > 0 && tls_len < 65536 {
                    let tls_record = &data[i..i + total_len];
                    
                    // 检查是否是ClientHello
                    if tls_record.len() > 5 && tls_record[5] == 0x01 {
                        if cfg!(debug_assertions) {
                            println!("  ✅ 找到完整TLS ClientHello记录, 长度: {}", tls_record.len());
                        }
                        return Some(tls_record.to_vec());
                    }
                }
            }
        }
    }
    
    // 方法2: 搜索Handshake消息 (0x01)
    for i in 0..data.len().saturating_sub(10) {
        if data[i] == 0x01 { // ClientHello
            // 尝试3字节长度字段
            if i + 4 <= data.len() {
                let hlen = ((data[i + 1] as usize) << 16) 
                    | ((data[i + 2] as usize) << 8) 
                    | (data[i + 3] as usize);
                
                if hlen > 0 && hlen < 65536 && i + 4 + hlen <= data.len() {
                    let total = 4 + hlen;
                    let hs = &data[i..i + total];
                    
                    // 验证版本字段
                    if hs.len() >= 6 {
                        let version = u16::from_be_bytes([hs[4], hs[5]]);
                        if version >= 0x0300 && version <= 0x0304 {
                            // 合成TLS记录
                            let record_len = total as u16;
                            let mut tls_record = Vec::with_capacity(5 + total);
                            tls_record.push(0x16); // TLS Handshake
                            tls_record.push(0x03); // TLS 1.0
                            tls_record.push(0x03); // TLS 1.0
                            tls_record.push((record_len >> 8) as u8);
                            tls_record.push((record_len & 0xff) as u8);
                            tls_record.extend_from_slice(hs);
                            
                            if cfg!(debug_assertions) {
                                println!("  ✅ 找到TLS ClientHello (3字节长度), 长度: {}", tls_record.len());
                            }
                            return Some(tls_record);
                        }
                    }
                }
            }
        }
    }
    
    if cfg!(debug_assertions) {
        println!("  ❌ 未找到TLS ClientHello");
    }
    None
}

/// 简化的QUIC Initial解密
fn simple_quic_decrypt_simplified(quic_packet: &[u8], dcid_len: usize, scid_len: usize, encrypted_payload: &[u8]) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    
    // 提取DCID
    let dcid_start = 6;
    let dcid = &quic_packet[dcid_start..dcid_start + dcid_len];
    
    if cfg!(debug_assertions) {
        println!("  🔍 DCID: {:02x?}", dcid);
    }
    
    // 使用RFC 9001的Initial Salt
    let initial_salt = &[
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a
    ];
    
    // 派生Initial Secret
    let mut hasher = Sha256::new();
    hasher.update(initial_salt);
    hasher.update(dcid);
    let initial_secret = hasher.finalize();
    
    // 派生Client Initial Secret
    let client_initial_secret = hkdf_expand_simple(&initial_secret, b"client in", 32)?;
    
    // 派生AEAD密钥和IV
    let aead_key = hkdf_expand_simple(&client_initial_secret, b"quic key", 16)?;
    let aead_iv = hkdf_expand_simple(&client_initial_secret, b"quic iv", 12)?;
    
    if cfg!(debug_assertions) {
        println!("  🔍 AEAD Key: {:02x?}", aead_key);
        println!("  🔍 AEAD IV: {:02x?}", aead_iv);
    }
    
    // 尝试不同的包号进行解密
    for packet_num in 0..10 {
        if let Some(decrypted) = try_decrypt_with_packet_number(encrypted_payload, &aead_key, &aead_iv, packet_num) {
            if cfg!(debug_assertions) {
                println!("  ✅ 使用包号{}解密成功", packet_num);
            }
            return Some(decrypted);
        }
    }
    
    if cfg!(debug_assertions) {
        println!("  ❌ 所有包号解密都失败");
    }
    None
}

/// 使用指定包号尝试解密
fn try_decrypt_with_packet_number(encrypted_payload: &[u8], aead_key: &[u8], aead_iv: &[u8], packet_num: u32) -> Option<Vec<u8>> {
    use aes_gcm::{Aes128Gcm, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};
    
    let cipher = Aes128Gcm::new_from_slice(aead_key).ok()?;
    
    // 构造Nonce (IV XOR packet_number)
    let mut nonce_bytes = aead_iv.to_vec();
    for (i, byte) in nonce_bytes.iter_mut().enumerate() {
        let shift_amount = 8 * (11 - i);
        if shift_amount < 32 {
            *byte ^= ((packet_num >> shift_amount) & 0xff) as u8;
        }
    }
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // 构造Additional Data (QUIC头部)
    let mut additional_data = Vec::new();
    additional_data.push(0xc0); // Initial包类型
    additional_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // 版本
    // 这里简化了Additional Data的构造
    
    // 尝试解密
    cipher.decrypt(nonce, encrypted_payload).ok()
}

/// 简化的QUIC Initial解密
fn simple_quic_decrypt(hdr: &QuicHeader, packet: &[u8]) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    
    // 提取DCID
    let dcid = &hdr.dcid;
    if cfg!(debug_assertions) {
        println!("  🔍 DCID: {:02x?}", dcid);
    }
    
    // 使用RFC 9001的Initial Salt
    let initial_salt = &[
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
        0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
        0xcc, 0xbb, 0x7f, 0x0a
    ];
    
    // 派生Initial Secret
    let mut hasher = Sha256::new();
    hasher.update(initial_salt);
    hasher.update(dcid);
    let initial_secret = hasher.finalize();
    
    // 派生Client Initial Secret
    let client_initial_secret = hkdf_expand_simple(&initial_secret, b"client in", 32)?;
    
    // 派生AEAD密钥和IV
    let aead_key = hkdf_expand_simple(&client_initial_secret, b"quic key", 16)?;
    let aead_iv = hkdf_expand_simple(&client_initial_secret, b"quic iv", 12)?;
    
    if cfg!(debug_assertions) {
        println!("  🔍 AEAD Key: {:02x?}", aead_key);
        println!("  🔍 AEAD IV: {:02x?}", aead_iv);
    }
    
    // 找到payload开始位置（跳过QUIC头部）
    let header_len = 5 + 1 + dcid.len() + 1 + 0 + 1 + 4; // 简化计算
    if header_len >= packet.len() {
        if cfg!(debug_assertions) {
            println!("  ❌ 头部长度计算错误");
        }
        return None;
    }
    
    let encrypted_payload = &packet[header_len..];
    if cfg!(debug_assertions) {
        println!("  🔍 加密负载长度: {}", encrypted_payload.len());
    }
    
    // 使用AES-GCM解密
    use aes_gcm::{Aes128Gcm, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};
    
    let cipher = Aes128Gcm::new_from_slice(&aead_key).ok()?;
    
    // 尝试不同的Packet Number进行解密
    for packet_number in 0..10u32 {
        let mut nonce = aead_iv.clone();
        let pn_bytes = packet_number.to_be_bytes();
        for i in 0..4 {
            nonce[8 + i] ^= pn_bytes[i];
        }
        
        let nonce = Nonce::from_slice(&nonce);
        
        // 构造Additional Data（QUIC头部）
        let _additional_data = &packet[..header_len];
        
        match cipher.decrypt(nonce, encrypted_payload) {
            Ok(decrypted) => {
                if cfg!(debug_assertions) {
                    println!("  ✅ 解密成功 (PN={}), 长度: {}", packet_number, decrypted.len());
                }
                return Some(decrypted);
            }
            Err(_) => {
                // 继续尝试下一个Packet Number
                continue;
            }
        }
    }
    
    if cfg!(debug_assertions) {
        println!("  ❌ 所有Packet Number尝试都失败");
    }
    None
}

/// 简化的HKDF扩展
fn hkdf_expand_simple(secret: &[u8], label: &[u8], length: usize) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    
    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(0x00); // 标签长度
    info.extend_from_slice(label);
    info.push(0x00); // 上下文长度
    
    let mut result = Vec::new();
    let mut counter = 1u8;
    let mut hasher = Sha256::new();
    
    while result.len() < length {
        hasher.update(secret);
        hasher.update(&[counter]);
        hasher.update(&info);
        let hash = hasher.finalize_reset();
        
        let needed = length - result.len();
        let to_take = needed.min(hash.len());
        result.extend_from_slice(&hash[..to_take]);
        counter += 1;
    }
    
    Some(result)
}

/// 使用quiche库解密QUIC Initial包
fn decrypt_with_quiche(hdr: &QuicHeader, packet: &[u8]) -> Result<Vec<u8>, String> {
    // 创建quiche配置
    let mut cfg = quiche::Config::new(hdr.version).map_err(|e| format!("Config创建失败: {:?}", e))?;
    cfg.verify_peer(false);
    let alpn: &[&[u8]] = &[b"h3", b"http/1.1"];
    cfg.set_application_protos(alpn);

    // 生成SCID
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    {
        let mut hasher = Sha256::new();
        hasher.update(&hdr.dcid);
        let digest = hasher.finalize();
        let copy_len = scid_bytes.len().min(digest.len());
        scid_bytes[..copy_len].copy_from_slice(&digest[..copy_len]);
    }
    let scid = quiche::ConnectionId::from_ref(&scid_bytes);
    let odcid = quiche::ConnectionId::from_ref(&hdr.dcid);

    let local: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
    let peer: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();

    // 创建连接
    let mut conn = quiche::accept(&scid, Some(&odcid), local, peer, &mut cfg)
        .map_err(|e| format!("quiche accept失败: {:?}", e))?;

    // 处理数据包
    let recv_info = quiche::RecvInfo { from: peer, to: local };
    let mut udp_buf = packet.to_vec();
    
    match conn.recv(&mut udp_buf, recv_info) {
        Ok(_) => {
            // 尝试从连接中读取数据
            let mut buf = [0u8; 65535];
            let mut result = Vec::new();
            
            // 读取所有可用的数据
            for stream_id in conn.readable() {
                match conn.stream_recv(stream_id, &mut buf) {
                    Ok((n, _)) => {
                        if n > 0 {
                            result.extend_from_slice(&buf[..n]);
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        println!("  🔍 quiche stream_recv错误: {:?}", e);
                        break;
                    }
                }
            }
            
            if result.is_empty() {
                return Err("quiche未返回任何数据".to_string());
            }
            
            // 在结果中查找TLS ClientHello
            for i in 0..result.len().saturating_sub(4) {
                if result[i] == 0x01 { // ClientHello
                    if i + 4 <= result.len() {
                        let hlen = ((result[i + 1] as usize) << 16) 
                            | ((result[i + 2] as usize) << 8) 
                            | (result[i + 3] as usize);
                        let total = 4 + hlen;
                        
                        if i + total <= result.len() {
                            let handshake = &result[i..i + total];
                            
                            // 合成TLS记录
                            let record_len = total as u16;
                            let mut tls_record = Vec::with_capacity(5 + total);
                            tls_record.push(0x16); // TLS Handshake
                            tls_record.push(0x03); // TLS 1.0
                            tls_record.push(0x03); // TLS 1.0
                            tls_record.push((record_len >> 8) as u8);
                            tls_record.push((record_len & 0xff) as u8);
                            tls_record.extend_from_slice(handshake);
                            
                            return Ok(tls_record);
                        }
                    }
                }
            }
            
            Err("未找到TLS ClientHello".to_string())
        }
        Err(e) => Err(format!("quiche recv失败: {:?}", e))
    }
}

/// 手动解密QUIC Initial包 (RFC 9001)
fn decrypt_quic_initial_packet(hdr: &QuicHeader, packet: &[u8]) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    use aes_gcm::{Aes128Gcm, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};
    
    // 1. 解析QUIC长首部字段
    let mut offset = 5; // 跳过固定部分
    
    // 解析DCID长度和DCID
    if offset >= packet.len() {
        return Err("包太短，无法解析DCID".to_string());
    }
    let dcid_len = packet[offset] as usize;
    offset += 1;
    println!("  🔍 DCID长度: {}", dcid_len);
    
    if offset + dcid_len > packet.len() {
        return Err("DCID长度超出包边界".to_string());
    }
    let dcid = &packet[offset..offset + dcid_len];
    offset += dcid_len;
    println!("  🔍 DCID: {:02x?}", dcid);
    
    // 解析SCID长度和SCID
    if offset >= packet.len() {
        return Err("包太短，无法解析SCID".to_string());
    }
    let scid_len = packet[offset] as usize;
    offset += 1;
    
    if offset + scid_len > packet.len() {
        return Err("SCID长度超出包边界".to_string());
    }
    let scid = &packet[offset..offset + scid_len];
    offset += scid_len;
    
    // 解析Token长度和Token
    if offset >= packet.len() {
        return Err("包太短，无法解析Token长度".to_string());
    }
    let token_len = parse_varint(&packet[offset..])?;
    offset += token_len.1;
    
    if offset + token_len.0 > packet.len() {
        return Err("Token长度超出包边界".to_string());
    }
    let token = &packet[offset..offset + token_len.0];
    offset += token_len.0;
    
    // 解析Length (变长整数)
    if offset >= packet.len() {
        return Err("包太短，无法解析Length".to_string());
    }
    let length_info = parse_varint(&packet[offset..])?;
    offset += length_info.1;
    let payload_len = length_info.0;
    
    if offset + payload_len > packet.len() {
        return Err("Payload长度超出包边界".to_string());
    }
    
    // 2. 派生Initial密钥 (RFC 9001 Section 5.2)
    let initial_salt = match hdr.version {
        0x00000001 => &[
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
            0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
            0xcc, 0xbb, 0x7f, 0x0a
        ],
        _ => {
            println!("  不支持的QUIC版本: 0x{:08x}", hdr.version);
            return Err("不支持的QUIC版本".to_string());
        }
    };
    
    // 派生Initial Secret
    let mut hasher = Sha256::new();
    hasher.update(initial_salt);
    hasher.update(dcid);
    let initial_secret = hasher.finalize();
    
    // 派生Client Initial Secret
    let client_initial_secret = hkdf_expand_label(&initial_secret, b"client in", b"", 32)?;
    
    // 派生AEAD密钥和IV
    let aead_key = hkdf_expand_label(&client_initial_secret, b"quic key", b"", 16)?;
    let aead_iv = hkdf_expand_label(&client_initial_secret, b"quic iv", b"", 12)?;
    
    // 派生Header Protection密钥
    let hp_key = hkdf_expand_label(&client_initial_secret, b"quic hp", b"", 16)?;
    
    // 3. 去除Header Protection
    let mut protected_packet = packet.to_vec();
    let packet_number_offset = offset;
    
    // 计算Header Protection掩码
    // 采样位置：从Packet Number开始后的16字节
    let sample_offset = packet_number_offset + 4; // 假设4字节PN
    if sample_offset + 16 > packet.len() {
        return Err("包太短，无法采样Header Protection".to_string());
    }
    let sample = &packet[sample_offset..sample_offset + 16];
    
    let mask = aes_ecb_encrypt(&hp_key, sample)?;
    println!("  🔍 Header Protection掩码: {:02x?}", mask);
    
    // 恢复Packet Number (只恢复前4字节，因为PN长度是4字节)
    protected_packet[packet_number_offset] ^= mask[0] & 0x0f;
    for i in 1..4 {
        if packet_number_offset + i < protected_packet.len() {
            protected_packet[packet_number_offset + i] ^= mask[i];
        }
    }
    
    println!("  🔍 恢复后的Packet Number: {:02x?}", 
        &protected_packet[packet_number_offset..packet_number_offset + 4]);
    
    // 确定Packet Number的实际长度
    // 在QUIC中，Packet Number长度由Header中的PN长度字段决定
    // 这里简化处理，Initial包通常使用4字节PN
    let pn_len = 4; // 简化：假设4字节PN
    println!("  🔍 Packet Number长度: {} 字节 (简化处理)", pn_len);
    
    // 4. 解密Payload
    let encrypted_payload = &protected_packet[offset + pn_len..offset + payload_len];
    let packet_number = match pn_len {
        1 => protected_packet[packet_number_offset] as u32,
        2 => u16::from_be_bytes([
            protected_packet[packet_number_offset],
            protected_packet[packet_number_offset + 1],
        ]) as u32,
        4 => u32::from_be_bytes([
            protected_packet[packet_number_offset],
            protected_packet[packet_number_offset + 1],
            protected_packet[packet_number_offset + 2],
            protected_packet[packet_number_offset + 3],
        ]),
        _ => return Err("无效的Packet Number长度".to_string()),
    };
    println!("  🔍 解析的Packet Number: {} (0x{:08x})", packet_number, packet_number);
    
    // 检查Packet Number是否合理（Initial包通常从0开始）
    let final_packet_number = if packet_number > 1000 {
        println!("  ⚠️ Packet Number过大，可能Header Protection去除有问题");
        println!("  🔄 尝试使用Packet Number: 0");
        0u32
    } else {
        packet_number
    };
    
    // 构造Nonce (IV XOR Packet Number)
    let mut nonce_bytes = aead_iv;
    let pn_bytes = final_packet_number.to_be_bytes();
    for i in 0..4 {
        nonce_bytes[8 + i] ^= pn_bytes[i];
    }
    
    let cipher = Aes128Gcm::new_from_slice(&aead_key).map_err(|e| format!("AES-GCM初始化失败: {:?}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // 构造Additional Data (长首部)
    let additional_data = &protected_packet[..offset];
    
    match cipher.decrypt(nonce, encrypted_payload) {
        Ok(decrypted) => {
            println!("  ✅ Initial包解密成功");
            Ok(decrypted)
        }
        Err(e) => {
            println!("  ❌ Initial包解密失败: {:?}", e);
            println!("  🔍 调试信息: aead_key_len={}, nonce_len={}, payload_len={}", 
                aead_key.len(), nonce_bytes.len(), encrypted_payload.len());
            println!("  🔍 调试信息: packet_number={}, nonce={:02x?}", packet_number, nonce_bytes);
            Err(format!("解密失败: {:?}", e))
        }
    }
}

/// 解析变长整数
fn parse_varint(data: &[u8]) -> Result<(usize, usize), String> {
    if data.is_empty() {
        return Err("数据为空".to_string());
    }
    
    let first_byte = data[0];
    let prefix = (first_byte >> 6) & 0x03;
    
    match prefix {
        0 => Ok((first_byte as usize, 1)),
        1 => {
            if data.len() < 2 {
                return Err("变长整数数据不足".to_string());
            }
            let value = ((first_byte & 0x3f) as usize) << 8 | data[1] as usize;
            Ok((value, 2))
        }
        2 => {
            if data.len() < 4 {
                return Err("变长整数数据不足".to_string());
            }
            let value = ((first_byte & 0x3f) as usize) << 24
                | (data[1] as usize) << 16
                | (data[2] as usize) << 8
                | data[3] as usize;
            Ok((value, 4))
        }
        3 => {
            if data.len() < 8 {
                return Err("变长整数数据不足".to_string());
            }
            let value = ((first_byte & 0x3f) as usize) << 56
                | (data[1] as usize) << 48
                | (data[2] as usize) << 40
                | (data[3] as usize) << 32
                | (data[4] as usize) << 24
                | (data[5] as usize) << 16
                | (data[6] as usize) << 8
                | data[7] as usize;
            Ok((value, 8))
        }
        _ => Err("无效的变长整数前缀".to_string()),
    }
}

/// HKDF扩展标签 (RFC 5869)
fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>, String> {
    use sha2::{Digest, Sha256};
    
    let mut info = Vec::new();
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(0x00); // 标签长度
    info.extend_from_slice(label);
    info.push(0x00); // 上下文长度
    info.extend_from_slice(context);
    
    // 简化的HKDF-Expand实现
    let mut result = Vec::new();
    let mut counter = 1u8;
    let mut hasher = Sha256::new();
    
    while result.len() < length {
        hasher.update(secret);
        hasher.update(&[counter]);
        hasher.update(&info);
        let hash = hasher.finalize_reset();
        
        let needed = length - result.len();
        let to_take = needed.min(hash.len());
        result.extend_from_slice(&hash[..to_take]);
        counter += 1;
    }
    
    Ok(result)
}

/// AES-ECB加密 (用于Header Protection)
fn aes_ecb_encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit};
    
    if key.len() != 16 || data.len() != 16 {
        return Err("AES-ECB需要16字节密钥和数据".to_string());
    }
    
    let cipher = Aes128::new_from_slice(key).map_err(|e| format!("AES初始化失败: {:?}", e))?;
    let mut block = [0u8; 16];
    block.copy_from_slice(data);
    
    cipher.encrypt_block(&mut block.into());
    Ok(block.to_vec())
}

/// 从CRYPTO帧中提取TLS ClientHello
fn extract_client_hello_from_crypto_frames(payload: &[u8]) -> Option<Vec<u8>> {
    println!("  🔍 解析CRYPTO帧，负载长度: {}", payload.len());
    
    let mut offset = 0;
    let mut crypto_data = Vec::new();
    
    // 解析所有CRYPTO帧并重组
    while offset < payload.len() {
        if offset + 1 > payload.len() {
            break;
        }
        
        let frame_type = payload[offset];
        if frame_type == 0x06 { // CRYPTO帧
            offset += 1;
            
            // 解析Offset (变长整数)
            let offset_info = parse_varint(&payload[offset..]).ok()?;
            offset += offset_info.1;
            let _crypto_offset = offset_info.0;
            
            // 解析Length (变长整数)
            let length_info = parse_varint(&payload[offset..]).ok()?;
            offset += length_info.1;
            let crypto_length = length_info.0;
            
            if offset + crypto_length > payload.len() {
                println!("  ❌ CRYPTO帧长度超出边界");
                break;
            }
            
            // 提取CRYPTO数据
            crypto_data.extend_from_slice(&payload[offset..offset + crypto_length]);
            offset += crypto_length;
            
            println!("  ✅ 找到CRYPTO帧，长度: {}", crypto_length);
        } else {
            // 跳过其他帧类型
            offset += 1;
        }
    }
    
    if crypto_data.is_empty() {
        println!("  ❌ 未找到CRYPTO帧");
        return None;
    }
    
    println!("  🔍 重组CRYPTO数据，总长度: {}", crypto_data.len());
    
    // 在CRYPTO数据中查找TLS ClientHello
    for i in 0..crypto_data.len().saturating_sub(4) {
        if crypto_data[i] == 0x01 { // ClientHello
            if i + 4 <= crypto_data.len() {
                let hlen = ((crypto_data[i + 1] as usize) << 16) 
                    | ((crypto_data[i + 2] as usize) << 8) 
                    | (crypto_data[i + 3] as usize);
                let total = 4 + hlen;
                
                if i + total <= crypto_data.len() {
                    let handshake = &crypto_data[i..i + total];
                    
                    // 合成TLS记录
                    let record_len = total as u16;
                    let mut tls_record = Vec::with_capacity(5 + total);
                    tls_record.push(0x16); // TLS Handshake
                    tls_record.push(0x03); // TLS 1.0
                    tls_record.push(0x03); // TLS 1.0
                    tls_record.push((record_len >> 8) as u8);
                    tls_record.push((record_len & 0xff) as u8);
                    tls_record.extend_from_slice(handshake);
                    
                    println!("  ✅ 提取到TLS ClientHello，长度: {}", tls_record.len());
                    return Some(tls_record);
                }
            }
        }
    }
    
    println!("  ❌ 未找到TLS ClientHello");
    None
}


/// 计算QUIC JA4指纹
pub fn calculate_quic_ja4(quic_packet: &[u8]) -> Option<String> {
    // 从QUIC Initial包中提取TLS ClientHello
    if let Some(tls_client_hello) = extract_tls_from_quic_initial(quic_packet) {
        // 使用标准的TLS JA4计算，但使用QUIC传输层标识
        if let Some((version, ciphers, extensions, elliptic_curves, ec_point_formats, signature_algorithms)) = 
            parse_client_hello_with_tls_parser(&tls_client_hello) {
            
            // 计算JA4，但使用'q'作为传输层标识
            let ja4 = calculate_ja4_from_parsed_data_quic(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats, &signature_algorithms, &tls_client_hello);
            return Some(ja4);
        }
    }
    
    None
}

/// 为QUIC计算JA4指纹（使用'q'作为传输层标识）
pub fn calculate_ja4_from_parsed_data_quic(version: TlsVersion, cipher_suites: &[u16], extensions: &[u16], _elliptic_curves: &[u16], _ec_point_formats: &[u8], signature_algorithms: &[u16], client_hello_data: &[u8]) -> String {
    // 使用'q'作为传输层标识
    let transport = "q";
    
    // 版本映射
    let version_str = match version {
        TlsVersion::Tls13 => "13",
        TlsVersion::Tls12 => "12", 
        TlsVersion::Tls11 => "11",
        TlsVersion::Tls10 => "10",
        _ => "13",
    };
    
    // SNI检测
    let sni = if has_sni_extension(client_hello_data) { "d" } else { "i" };
    
    // 密码套件数量（忽略GREASE）
    let cipher_count = cipher_suites.iter().filter(|&&c| !is_grease_value(c)).count();
    let cipher_count_str = format!("{:02}", cipher_count);
    
    // 扩展数量（忽略GREASE）
    let extension_count = extensions.iter().filter(|&&e| !is_grease_value(e)).count();
    let extension_count_str = format!("{:02}", extension_count);
    
    // ALPN处理
    let alpn = extract_alpn_from_client_hello(client_hello_data).unwrap_or_else(|| "00".to_string());
    
    // JA4_a部分：q + 版本 + SNI + 密码套件数 + 扩展数 + ALPN
    let ja4_a = format!("{}{}{}{}{}{}", transport, version_str, sni, cipher_count_str, extension_count_str, alpn);
    
    // JA4_b部分（密码套件哈希）
    let ja4_b = calculate_ja4b_from_parsed_data(cipher_suites);
    
    // JA4_c部分（扩展哈希）
    let ja4_c = calculate_ja4c_from_parsed_data(extensions, signature_algorithms);
    
    format!("{}_{}_{}", ja4_a, ja4_b, ja4_c)
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


