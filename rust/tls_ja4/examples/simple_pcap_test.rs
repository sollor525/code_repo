//! 简单的PCAP测试程序
//!
//! 使用现有的PCAP库功能处理tls3.pcapng文件

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use pcap::Capture;
use pcap::Packet;

#[derive(Debug, Clone)]
struct TlsResult {
    stream_id: u32,
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    fingerprint: Option<String>,
}

fn process_pcap_file(pcap_path: &str) -> Result<Vec<TlsResult>, Box<dyn std::error::Error>> {
    let mut cap = Capture::from_file(pcap_path)?;
    let mut results = Vec::new();
    let mut stream_counter = 0u32;
    let mut stream_map: HashMap<String, u32> = HashMap::new();

    println!("Processing packets from: {}", pcap_path);

    while let Ok(packet) = cap.next_packet() {
        if let Some(_tls_data) = extract_tls_from_packet(&packet) {
            if let Some((src_ip, dst_ip, src_port, dst_port)) = extract_ip_ports(&packet) {
                let stream_key = format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port);

                let stream_id = *stream_map.entry(stream_key).or_insert_with(|| {
                    let id = stream_counter;
                    stream_counter += 1;
                    id
                });

                // 这里应该调用实际的指纹计算函数
                // 为了演示，我们使用模拟数据
                let fingerprint = Some(format!("simulated_fingerprint_{}", stream_id));

                results.push(TlsResult {
                    stream_id,
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    src_port,
                    dst_port,
                    fingerprint,
                });
            }
        }
    }

    Ok(results)
}

fn extract_tls_from_packet(packet: &Packet) -> Option<Vec<u8>> {
    let data = packet.data;

    // 跳过以太网头部 (14字节)
    if data.len() < 14 {
        return None;
    }

    // 检查是否为IPv4 (0x0800)
    if data[12] != 0x08 || data[13] != 0x00 {
        return None;
    }

    // IPv4头部最小20字节
    if data.len() < 14 + 20 {
        return None;
    }

    let ip_header_length = (data[14] & 0x0f) * 4;
    if data.len() < 14 + ip_header_length as usize {
        return None;
    }

    // 检查协议是否为TCP (6)
    if data[23] != 6 {
        return None;
    }

    let tcp_header_start = 14 + ip_header_length as usize;
    if data.len() < tcp_header_start + 20 {
        return None;
    }

    let tcp_header_length = ((data[tcp_header_start + 12] >> 4) & 0x0f) * 4;
    let payload_start = tcp_header_start + tcp_header_length as usize;

    if data.len() <= payload_start {
        return None;
    }

    // 检查是否为TLS握手 (0x16)
    let payload = &data[payload_start..];
    if payload.is_empty() || payload[0] != 0x16 {
        return None;
    }

    Some(payload.to_vec())
}

fn extract_ip_ports(packet: &Packet) -> Option<(IpAddr, IpAddr, u16, u16)> {
    let data = packet.data;

    if data.len() < 14 + 20 + 20 {
        return None;
    }

    // 跳过以太网头部
    let ip_header_start = 14;

    // 检查是否为IPv4
    if data[ip_header_start] >> 4 != 4 {
        return None;
    }

    // 提取源IP和目标IP
    let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        data[ip_header_start + 12],
        data[ip_header_start + 13],
        data[ip_header_start + 14],
        data[ip_header_start + 15],
    ));

    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        data[ip_header_start + 16],
        data[ip_header_start + 17],
        data[ip_header_start + 18],
        data[ip_header_start + 19],
    ));

    let _ip_header_length = (data[ip_header_start] & 0x0f) * 4;
    let tcp_header_start = ip_header_start as usize + 14;

    // 提取源端口和目标端口
    let src_port = u16::from_be_bytes([data[tcp_header_start], data[tcp_header_start + 1]]);
    let dst_port = u16::from_be_bytes([data[tcp_header_start + 2], data[tcp_header_start + 3]]);

    Some((src_ip, dst_ip, src_port, dst_port))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PCAP Processing Test ===");

    let pcap_path = "pcap/tls3.pcapng";

    // 检查文件是否存在
    if !Path::new(pcap_path).exists() {
        return Err(format!("PCAP file not found: {}", pcap_path).into());
    }

    // 处理PCAP文件
    let results = process_pcap_file(pcap_path)?;

    println!("\n=== Results ===");
    println!("Found {} TLS streams", results.len());

    // 输出结果
    let mut output = String::new();
    for result in &results {
        println!("Stream {}: {}:{} -> {}:{}, Fingerprint: {:?}",
                result.stream_id,
                result.src_ip, result.src_port,
                result.dst_ip, result.dst_port,
                result.fingerprint);

        // 生成类似原始格式的输出
        output.push_str(&format!("- stream: {}\n", result.stream_id));
        output.push_str(&format!("  transport: tcp\n"));
        output.push_str(&format!("  src: {}\n", result.src_ip));
        output.push_str(&format!("  dst: {}\n", result.dst_ip));
        output.push_str(&format!("  src_port: {}\n", result.src_port));
        output.push_str(&format!("  dst_port: {}\n", result.dst_port));
        if let Some(ref fp) = result.fingerprint {
            output.push_str(&format!("  ja4: {}\n", fp));
        }
        output.push('\n');
    }

    // 保存结果
    let output_file = "new_result.txt";
    std::fs::write(output_file, output)?;
    println!("\nResults saved to: {}", output_file);

    Ok(())
}