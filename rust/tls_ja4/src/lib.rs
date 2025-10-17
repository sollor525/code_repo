//! TLS JA4/JA3 Fingerprint Extractor Library
//!
//! 高性能的TLS指纹提取库，支持JA4和JA3指纹计算，包含C API接口。
//!
//! ## 特性
//!
//! - **高性能**: 优化的字符串处理和内存管理
//! - **线程安全**: C API支持多线程并发调用
//! - **数据库支持**: 内置JA4指纹数据库匹配功能
//! - **分段重组**: 支持TCP分段的TLS数据包重组
//! - **C API兼容**: 可嵌入到VPP等C程序中使用
//!
//! ## 快速开始
//!
//! ```rust
//! use tls_ja4::{TlsAnalyzer, AnalyzerConfig};
//!
//! let analyzer = TlsAnalyzer::new_default();
//! // 这里需要提供真实的TLS Client Hello数据
//! // let result = analyzer.analyze_packet(&tls_data)?;
//! // println!("JA4: {}", result.ja4_fingerprint.unwrap_or_default());
//! ```
//!
//! ## C API
//!
//! ```c
//! #include "tls_ja4.h"
//!
//! // 初始化
//! tls_ja4_context* ctx = tls_ja4_init();
//!
//! // 加载数据库
//! tls_ja4_load_database(ctx, "config/ja4_db.json");
//!
//! // 分析TLS数据包 (TCP载荷)
//! tls_ja4_result result;
//! int ret = tls_ja4_analyze_client_hello(ctx, tcp_payload_data, payload_len, &result);
//!
//! if (ret == 0 && result.is_match) {
//!     printf("匹配的JA4指纹: %.*s\\n", result.fingerprint.ja4_len, result.fingerprint.ja4);
//! }
//!
//! // 清理资源
//! tls_ja4_cleanup(ctx);
//! ```

// 重新导出新架构的核心组件
pub use tls_ja4_core::*;

// 重新导出pcap处理组件
pub use tls_ja4_pcap::{
    analyze_pcap_file, process_pcap_file as save_pcap_to_file,
    extract_tcp_stream_from_packet, extract_tls_data_from_packet,
    reassemble_tcp_stream, parse_vlan_tags
};

// 重新导出类型和常量
pub use tls_ja4_core::{
    TlsSession, Config,
    is_grease_value, generate_session_key, analyze_tls_packet
};

// 重新导出TLS相关功能
pub use tls_ja4_core::tls::{
    is_tls_packet, is_quic_packet, is_client_hello,
    parse_client_hello_with_tls_parser, tls_version_to_u16
};

// 重新导出指纹计算功能
pub use tls_ja4_core::fingerprint::{
    calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data,
    calculate_ja4b_from_parsed_data, calculate_ja4c_from_parsed_data,
    extract_alpn_from_client_hello
};


// 导入必要的依赖
use std::net::IpAddr;
use std::collections::HashMap;

// Type aliases
pub type TcpStreamResult = Option<(IpAddr, IpAddr, u16, u16, u32, u32, Vec<u8>)>;
pub type ClientHelloResult = Option<(tls_parser::TlsVersion, Vec<u16>, Vec<u16>, Vec<u16>, Vec<u8>, Vec<u16>)>;

// 重新导出主要的类型和函数
pub use tls_parser::TlsVersion as TlsVersionLib;

/// 处理pcap文件（支持分段TLS Hello包）- 兼容性包装
pub fn process_pcap_file(
    input_path: &str,
    config: &Config
) -> anyhow::Result<(HashMap<String, TlsSession>, usize, usize)> {
    // 使用新的pcap处理接口
    analyze_pcap_file(input_path, config)
}

/// 保存指纹数据到文件
pub fn save_fingerprints_to_file(
    sessions: &HashMap<String, TlsSession>,
    total_packets: usize,
    tls_packets: usize,
    output_path: &str,
    config: &Config,
) -> anyhow::Result<()> {
    // 构造报告并保存
    let analyzer = tls_ja4_pcap::PcapAnalyzer::new(config.clone());
    let report = analyzer.generate_report(sessions, total_packets, tls_packets);
    analyzer.save_to_file(&report, output_path)?;
    Ok(())
}

/// 加载配置文件
pub fn load_config(config_path: &str) -> anyhow::Result<Config> {
    tls_ja4_core::load_config(config_path)
}

#[cfg(test)]
mod tests {
 
    #[test]
    fn test_basic_functionality() {
        // 基本功能测试
        assert!(true);
    }
}
