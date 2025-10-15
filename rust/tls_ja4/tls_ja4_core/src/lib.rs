//! TLS JA4/JA3 Core Fingerprint Extractor Library
//!
//! 高性能的TLS指纹提取核心库，支持JA4和JA3指纹计算，包含C API接口。
//! 专门用于直接处理流量数据包，不包含PCAP解析功能。
//!
//! # 特性
//!
//! - **高性能**: 优化的字符串处理和内存管理
//! - **线程安全**: C API支持多线程并发调用
//! - **缓存优化**: 内置TLS解析缓存，避免重复计算
//! - **C API兼容**: 可嵌入到VPP等C程序中使用
//! - **模块化设计**: 清晰的模块分离，便于维护
//!

#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::needless_return)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::manual_range_patterns)]
#![allow(clippy::len_zero)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::new_without_default)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_find)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::manual_flatten)]

// 模块声明
pub mod tls;
pub mod fingerprint;
pub mod performance;
pub mod c_api;
pub mod errors;
pub mod utils;
pub mod core;
pub mod result_handler;

// 重新导出性能优化模块
pub use performance::tls_cache::*;

// 重新导出主要类型和函数
pub use core::*;
pub use errors::{TlsJa4Error, TlsJa4Result};
pub use c_api::types::*;
pub use result_handler::CResultHandler;

// 重新导出TLS检测函数
pub use tls::{is_tls_packet, is_quic_packet};

// Re-export TlsVersion for external use
pub use tls_parser::TlsVersion as TlsVersionLib;

// 性能优化的重新导出
pub use performance::optimized_fingerprint::*;
pub use performance::optimized_strings::*;

// 导入必要的依赖
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// Type aliases to reduce complexity
pub type ClientHelloResult = Option<(tls_parser::TlsVersion, Vec<u16>, Vec<u16>, Vec<u16>, Vec<u8>, Vec<u16>)>;

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

/// 加载配置文件
pub fn load_config(config_path: &str) -> anyhow::Result<Config> {
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

/// 分析原始TLS数据包数据（核心功能）
pub fn analyze_tls_packet(packet_data: &[u8]) -> TlsJa4Result<FingerprintData> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // 解析Client Hello
    if let Some((version, ciphers, extensions, elliptic_curves, ec_point_formats, signature_algorithms)) =
        tls::parse_client_hello_with_tls_parser(packet_data) {

        // 计算JA4指纹
        let ja4 = fingerprint::calculate_ja4_from_parsed_data(
            version, &ciphers, &extensions, &signature_algorithms, packet_data
        );

        // 计算JA3指纹
        let ja3 = fingerprint::calculate_ja3_from_parsed_data(
            version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats
        );

        Ok(FingerprintData {
            timestamp,
            src_ip: "unknown".to_string(),
            dst_ip: "unknown".to_string(),
            src_port: 0,
            dst_port: 0,
            ja4_fingerprints: vec![ja4],
            ja4b_fingerprints: vec![],
            ja4c_fingerprints: vec![],
            ja3_fingerprints: ja3.into_iter().collect(),
            client_hello_count: 1,
            server_hello_count: 0,
        })
    } else {
        Err(TlsJa4Error::InvalidParameter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_loading() {
        let config = load_config("non_existent_config.json").unwrap();
        assert_eq!(config.include_server_hello, false);
        assert_eq!(config.max_packets_per_session, 10);
        assert_eq!(config.include_ja3, true);
        assert_eq!(config.verbose, false);
    }
}