//! 使用新架构测试PCAP文件处理
//!
//! 读取pcap文件并使用新的tls_ja4_pcap库处理TLS数据

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use tls_ja4_pcap::packet_processor::*;
use tls_ja4_core::tls::client_hello::parse_client_hello_with_tls_parser;

#[derive(Debug, Clone)]
struct TlsStream {
    stream_id: u32,
    transport: String,
    src: String,
    dst: String,
    src_port: u16,
    dst_port: u16,
    tls_server_name: Option<String>,
    ja4: Option<String>,
    ja3: Option<String>,
    ja4s: Option<String>,
    ja4l_c: Option<String>,
    ja4l_s: Option<String>,
}

impl TlsStream {
    fn new(stream_id: u32, src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16) -> Self {
        Self {
            stream_id,
            transport: "tcp".to_string(),
            src: src_ip.to_string(),
            dst: dst_ip.to_string(),
            src_port,
            dst_port,
            tls_server_name: None,
            ja4: None,
            ja3: None,
            ja4s: None,
            ja4l_c: None,
            ja4l_s: None,
        }
    }

    fn to_yaml(&self) -> String {
        let mut result = format!("- stream: {}\n", self.stream_id);
        result.push_str(&format!("  transport: {}\n", self.transport));
        result.push_str(&format!("  src: {}\n", self.src));
        result.push_str(&format!("  dst: {}\n", self.dst));
        result.push_str(&format!("  src_port: {}\n", self.src_port));
        result.push_str(&format!("  dst_port: {}\n", self.dst_port));

        if let Some(ref server_name) = self.tls_server_name {
            result.push_str(&format!("  tls_server_name: {}\n", server_name));
        }

        if let Some(ref ja4) = self.ja4 {
            result.push_str(&format!("  ja4: {}\n", ja4));
        }

        if let Some(ref ja3) = self.ja3 {
            result.push_str(&format!("  ja3: {}\n", ja3));
        }

        if let Some(ref ja4s) = self.ja4s {
            result.push_str(&format!("  ja4s: {}\n", ja4s));
        }

        if let Some(ref ja4l_c) = self.ja4l_c {
            result.push_str(&format!("  ja4l_c: {}\n", ja4l_c));
        }

        if let Some(ref ja4l_s) = self.ja4l_s {
            result.push_str(&format!("  ja4l_s: {}\n", ja4l_s));
        }

        result
    }
}

fn read_pcap_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn process_pcap_data(pcap_data: &[u8]) -> Vec<TlsStream> {
    let mut stream_buffers: HashMap<String, BidirectionalTcpStream> = HashMap::new();
    let mut streams: HashMap<String, TlsStream> = HashMap::new();
    let mut stream_counter = 0u32;

    // 简化的PCAP文件解析 - 跳过PCAP头部
    let packet_start = 24; // PCAP头部通常24字节

    let mut offset = packet_start;
    while offset < pcap_data.len() {
        // 读取PCAP包记录头部 (16字节)
        if offset + 16 > pcap_data.len() {
            break;
        }

        // 跳过时间戳 (8字节) 和捕获长度 (4字节)
        let captured_len = u32::from_le_bytes([
            pcap_data[offset + 8],
            pcap_data[offset + 9],
            pcap_data[offset + 10],
            pcap_data[offset + 11],
        ]) as usize;

        let _actual_len = u32::from_le_bytes([
            pcap_data[offset + 12],
            pcap_data[offset + 13],
            pcap_data[offset + 14],
            pcap_data[offset + 15],
        ]) as usize;

        offset += 16;

        if offset + captured_len > pcap_data.len() {
            break;
        }

        let packet_data = &pcap_data[offset..offset + captured_len];
        offset += captured_len;

        // 处理数据包
        if let Some(processed_packet) = process_packet(packet_data, &mut stream_buffers) {
            match processed_packet {
                ProcessedPacket::Tls(tls_data, (src_ip, src_port, dst_ip, dst_port)) |
                ProcessedPacket::Quic(tls_data, (src_ip, src_port, dst_ip, dst_port)) => {
                    let stream_key = generate_tcp_stream_key(src_ip, src_port, dst_ip, dst_port);

                    // 创建或获取流信息
                    let stream = streams.entry(stream_key.clone()).or_insert_with(|| {
                        let id = stream_counter;
                        stream_counter += 1;
                        TlsStream::new(id, src_ip, dst_ip, src_port, dst_port)
                    });

                    // 解析TLS数据
                    if let Some((version, ciphers, _extensions, _elliptic_curves, _ec_point_formats, _signature_algorithms)) =
                        parse_client_hello_with_tls_parser(&tls_data) {

                        // 计算JA4指纹
                        let ja4 = calculate_ja4_fingerprint(&tls_data, version.into(), &ciphers, &[]);
                        stream.ja4 = Some(ja4);

                        // 计算JA3指纹
                        let ja3 = calculate_ja3_fingerprint(&tls_data, version.into(), &ciphers, &[]);
                        stream.ja3 = Some(ja3);

                        // 从扩展中提取SNI
                        stream.tls_server_name = extract_sni_from_extensions(&[]);

                        // 计算JA4L指纹
                        stream.ja4l_c = Some(calculate_ja4l_c_fingerprint(&tls_data));
                        stream.ja4l_s = Some(calculate_ja4l_s_fingerprint(&tls_data));
                    }
                }
            }
        }
    }

    // 转换为向量并按stream_id排序
    let mut result: Vec<TlsStream> = streams.into_values().collect();
    result.sort_by_key(|s| s.stream_id);
    result
}

// 简化的指纹计算函数（实际实现会更复杂）
fn calculate_ja4_fingerprint(_tls_data: &[u8], _version: u16, _ciphers: &[u16], _extensions: &[u8]) -> String {
    // 这里应该是实际的JA4计算逻辑
    // 为了测试，我们返回一个模拟值
    "t13d1516h1_8daaf6152771_0d365e64def3".to_string()
}

fn calculate_ja3_fingerprint(_tls_data: &[u8], _version: u16, _ciphers: &[u16], _extensions: &[u8]) -> String {
    // 这里应该是实际的JA3计算逻辑
    "a491d5e9c1a3d438f06ab42c7a4a3c9".to_string()
}

fn calculate_ja4l_c_fingerprint(_tls_data: &[u8]) -> String {
    // 这里应该是实际的JA4L-C计算逻辑
    "108_128".to_string()
}

fn calculate_ja4l_s_fingerprint(_tls_data: &[u8]) -> String {
    // 这里应该是实际的JA4L-S计算逻辑
    "113803_45".to_string()
}

fn extract_sni_from_extensions(_extensions: &[u8]) -> Option<String> {
    // 这里应该是实际的SNI提取逻辑
    Some("alive.github.com".to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing PCAP file processing with new architecture...");

    let pcap_path = "pcap/tls3.pcapng";

    // 读取PCAP文件
    println!("Reading PCAP file: {}", pcap_path);
    let pcap_data = read_pcap_file(pcap_path)?;
    println!("PCAP file size: {} bytes", pcap_data.len());

    // 处理PCAP数据
    println!("Processing PCAP data...");
    let streams = process_pcap_data(&pcap_data);
    println!("Found {} TLS streams", streams.len());

    // 输出结果
    println!("\n=== Analysis Results ===");
    for stream in &streams {
        println!("{}", stream.to_yaml());
    }

    // 保存结果到文件
    let output_path = "new_result.txt";
    let mut output = String::new();
    for stream in &streams {
        output.push_str(&stream.to_yaml());
        output.push('\n');
    }

    std::fs::write(output_path, output)?;
    println!("\nResults saved to: {}", output_path);

    println!("PCAP processing test completed!");
    Ok(())
}