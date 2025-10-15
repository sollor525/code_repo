//! 核心TLS分析功能模块
//!
//! 提供TLS包解析、指纹计算等核心功能

use crate::errors::{TlsJa4Error, TlsJa4Result};
use crate::fingerprint::{calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data};
use crate::tls::{is_tls_packet, is_client_hello, parse_client_hello_with_tls_parser};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// TLS会话信息
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

/// 指纹分析结果
#[derive(Debug, Clone, Serialize)]
pub struct FingerprintResult {
    pub timestamp: i64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub ja4_fingerprint: Option<String>,
    pub ja3_fingerprint: Option<String>,
    pub tls_version: Option<u16>,
    pub cipher_count: Option<u16>,
    pub extension_count: Option<u16>,
    pub is_match: bool,
}

/// TLS分析器
pub struct TlsAnalyzer {
    config: AnalyzerConfig,
}

/// 分析器配置
#[derive(Debug, Clone, Deserialize)]
pub struct AnalyzerConfig {
    pub include_server_hello: bool,
    pub max_packets_per_session: usize,
    pub include_ja3: bool,
    pub verbose: bool,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            include_server_hello: false,
            max_packets_per_session: 10,
            include_ja3: true,
            verbose: false,
        }
    }
}

impl TlsAnalyzer {
    /// 创建新的TLS分析器
    pub fn new(config: AnalyzerConfig) -> Self {
        Self { config }
    }

    /// 创建默认配置的分析器
    pub fn new_default() -> Self {
        Self::new(AnalyzerConfig::default())
    }

    /// 分析单个TLS数据包
    pub fn analyze_packet(&self, packet_data: &[u8]) -> TlsJa4Result<FingerprintResult> {
        // 基本验证
        if packet_data.is_empty() {
            return Err(TlsJa4Error::InsufficientData);
        }

        // 检查是否为TLS包
        if !is_tls_packet(packet_data) {
            return Err(TlsJa4Error::NotTls);
        }

        // 检查是否为Client Hello
        if !is_client_hello(packet_data) {
            return Err(TlsJa4Error::NotClientHello);
        }

        // 解析Client Hello
        let (version, ciphers, extensions, elliptic_curves, ec_point_formats, signature_algorithms) =
            parse_client_hello_with_tls_parser(packet_data)
                .ok_or(TlsJa4Error::ParseError("Failed to parse Client Hello".to_string()))?;

        // 计算指纹
        let ja4 = calculate_ja4_from_parsed_data(version, &ciphers, &extensions, &signature_algorithms, packet_data);
        let ja3 = if self.config.include_ja3 {
            calculate_ja3_from_parsed_data(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats)
        } else {
            None
        };

        // 获取当前时间戳
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Ok(FingerprintResult {
            timestamp,
            src_ip: "unknown".to_string(), // 需要从网络层获取
            dst_ip: "unknown".to_string(),
            src_port: 0,
            dst_port: 0,
            ja4_fingerprint: Some(ja4),
            ja3_fingerprint: ja3,
            tls_version: Some(self.tls_version_to_u16(version)),
            cipher_count: Some(ciphers.len() as u16),
            extension_count: Some(extensions.len() as u16),
            is_match: false, // 将在外部设置
        })
    }

    /// 批量分析多个数据包
    pub fn analyze_packets(&self, packets: &[&[u8]]) -> Vec<TlsJa4Result<FingerprintResult>> {
        packets
            .iter()
            .map(|packet| self.analyze_packet(packet))
            .collect()
    }

  
    /// 将TlsVersion转换为u16
    fn tls_version_to_u16(&self, version: tls_parser::TlsVersion) -> u16 {
        use tls_parser::TlsVersion;
        match version {
            TlsVersion::Ssl30 => 0x0300,
            TlsVersion::Tls10 => 0x0301,
            TlsVersion::Tls11 => 0x0302,
            TlsVersion::Tls12 => 0x0303,
            TlsVersion::Tls13 => 0x0304,
            _ => 0x0303,
        }
    }
}

/// 检查是否为GREASE值
pub fn is_grease_value(value: u16) -> bool {
    let high_byte = (value >> 8) & 0xFF;
    let low_byte = value & 0xFF;
    (high_byte & 0x0F) == 0x0A && (low_byte & 0x0F) == 0x0A && (high_byte >> 4) == (low_byte >> 4)
}

/// 生成会话键
pub fn generate_session_key(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> String {
    format!("{}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port)
}