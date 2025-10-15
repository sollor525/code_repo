//! TLS JA4/JA3 PCAP Parsing Library
//!
//! PCAP文件解析库，用于从网络包文件中提取TLS指纹。
//! 依赖于tls_ja4_core库进行指纹计算。
//!
//! # 特性
//!
//! - **PCAP解析**: 支持标准PCAP文件格式
//! - **网络层解析**: 支持IPv4/IPv6、TCP/UDP协议
//! - **TCP流重组**: 支持分段的TLS数据包重组
//! - **QUIC支持**: 支持QUIC协议的TLS指纹提取
//! - **高性能**: 利用核心库的缓存机制
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

// 导入核心库
extern crate tls_ja4_core;

use tls_ja4_core::{
    Config, TlsSession, FingerprintData, FingerprintReport,
    fingerprint
};

// 模块声明
pub mod network;
pub mod packet_processor;

// 重新导出网络相关功能
pub use network::*;
pub use packet_processor::*;

// 导入必要的依赖
use std::collections::HashMap;
use std::net::IpAddr;
use pcap::Capture;
use anyhow::Result;

/// PCAP分析器
pub struct PcapAnalyzer {
    config: Config,
}

impl PcapAnalyzer {
    /// 创建新的PCAP分析器
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// 使用默认配置创建PCAP分析器
    pub fn new_default() -> Self {
        Self::new(Config {
            include_server_hello: false,
            max_packets_per_session: 10,
            include_ja3: true,
            verbose: false,
        })
    }

    /// 分析PCAP文件
    pub fn analyze_file(&self, input_path: &str) -> Result<(HashMap<String, TlsSession>, usize, usize)> {
        let mut cap = Capture::from_file(input_path)?;
        let mut sessions: HashMap<String, TlsSession> = HashMap::new();
        let mut stream_buffers: HashMap<String, packet_processor::BidirectionalTcpStream> = HashMap::new();
        let mut total_packets = 0;
        let mut tls_packets = 0;

        while let Ok(packet) = cap.next_packet() {
            total_packets += 1;

            // 使用packet_processor处理数据包
            if let Some(processed_result) = packet_processor::process_packet(&packet.data, &mut stream_buffers) {
                match processed_result {
                    packet_processor::ProcessedPacket::Tls(tls_data, endpoints) => {
                        tls_packets += 1;
                        self.process_tls_data(&tls_data, endpoints, &mut sessions);
                    }
                    packet_processor::ProcessedPacket::Quic(quic_data, endpoints) => {
                        tls_packets += 1;
                        self.process_quic_data(&quic_data, endpoints, &mut sessions);
                    }
                }
            }
        }

        Ok((sessions, total_packets, tls_packets))
    }

    /// 处理TLS数据
    fn process_tls_data(&self, tls_data: &[u8], endpoints: (IpAddr, u16, IpAddr, u16), sessions: &mut HashMap<String, TlsSession>) {
        let (src_ip, src_port, dst_ip, dst_port) = endpoints;

        if let Some((version, ciphers, extensions, elliptic_curves, ec_point_formats, _signature_algorithms)) =
            fingerprint::parse_client_hello_with_tls_parser(tls_data) {

            let session_key = tls_ja4_core::generate_session_key(src_ip, src_port, dst_ip, dst_port);
            let session = sessions.entry(session_key).or_insert_with(|| {
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

            // 避免重复处理
            let is_duplicate = session.client_hellos.iter().any(|existing| {
                existing.len() == tls_data.len() && existing == tls_data
            });

            if !is_duplicate && session.client_hellos.len() < self.config.max_packets_per_session {
                session.client_hellos.push(tls_data.to_vec());

                // 计算JA3指纹
                if self.config.include_ja3 {
                    if let Some(ja3) = fingerprint::calculate_ja3_from_parsed_data(
                        version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats
                    ) {
                        session.ja3_fingerprints.push(ja3);
                    }
                }
            }
        }
    }

    /// 处理QUIC数据
    fn process_quic_data(&self, quic_data: &[u8], endpoints: (IpAddr, u16, IpAddr, u16), sessions: &mut HashMap<String, TlsSession>) {
        // QUIC包处理逻辑（类似TLS，但使用不同的协议标识）
        // 这里简化处理，实际可能需要更复杂的QUIC解析
        self.process_tls_data(quic_data, endpoints, sessions);
    }

    /// 生成指纹报告
    pub fn generate_report(&self, sessions: &HashMap<String, TlsSession>, total_packets: usize, tls_packets: usize) -> FingerprintReport {
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
                if let Some((version, ciphers, extensions, _elliptic_curves, _ec_point_formats, _signature_algorithms)) =
                    fingerprint::parse_client_hello_with_tls_parser(client_hello) {
                    let ja4 = fingerprint::calculate_ja4_from_parsed_data(version, &ciphers, &extensions, &_signature_algorithms, client_hello);
                    let ja4b = fingerprint::calculate_ja4b_from_parsed_data(&ciphers);
                    let ja4c = fingerprint::calculate_ja4c_from_parsed_data(&extensions, &_signature_algorithms);

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

        FingerprintReport {
            analysis_time,
            total_sessions: sessions.len(),
            total_packets,
            tls_packets,
            sessions: fingerprint_sessions,
        }
    }

    /// 保存指纹数据到文件
    pub fn save_to_file(&self, report: &FingerprintReport, output_path: &str) -> Result<()> {
        use std::fs::File;
        use std::io::Write;

        let json_data = serde_json::to_string_pretty(report)?;
        let mut file = File::create(output_path)?;
        file.write_all(json_data.as_bytes())?;

        Ok(())
    }

    /// 分析PCAP文件并保存结果
    pub fn analyze_and_save(&self, input_path: &str, output_path: &str) -> Result<()> {
        let (sessions, total_packets, tls_packets) = self.analyze_file(input_path)?;
        let report = self.generate_report(&sessions, total_packets, tls_packets);
        self.save_to_file(&report, output_path)?;
        Ok(())
    }
}

/// 便捷函数：分析PCAP文件
pub fn analyze_pcap_file(input_path: &str, config: &Config) -> Result<(HashMap<String, TlsSession>, usize, usize)> {
    let analyzer = PcapAnalyzer::new(config.clone());
    analyzer.analyze_file(input_path)
}

/// 便捷函数：分析PCAP文件并保存结果
pub fn process_pcap_file(input_path: &str, output_path: &str, config: &Config) -> Result<()> {
    let analyzer = PcapAnalyzer::new(config.clone());
    analyzer.analyze_and_save(input_path, output_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcap_analyzer_creation() {
        let analyzer = PcapAnalyzer::new_default();
        assert_eq!(analyzer.config.max_packets_per_session, 10);
        assert_eq!(analyzer.config.include_ja3, true);
        assert_eq!(analyzer.config.verbose, false);
    }
}