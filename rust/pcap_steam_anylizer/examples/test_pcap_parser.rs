//! 测试PCAP解析功能
//!
//! 创建一个简单的测试来验证PCAP读取和解析功能

use pcap_steam_anylizer::pcap::{PcapReader, PacketParser};
use pcap_steam_anylizer::types::packet::{PacketHeader, Packet};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("测试PCAP解析功能...");

    // 创建数据包解析器
    let parser = PacketParser::new(true, true); // 验证校验和，解析负载

    // 创建一个简单的测试数据包（以太网 + IPv4 + TCP）
    let test_packet = create_test_packet();

    // 解析数据包
    match parser.parse(test_packet) {
        Ok(parsed_packet) => {
            println!("成功解析数据包:");
            println!("  协议栈: {:?}", parsed_packet.protocols);
            println!("  源MAC: {:?}", parsed_packet.src_mac);
            println!("  目的MAC: {:?}", parsed_packet.dst_mac);
            println!("  源IP: {:?}", parsed_packet.src_ip);
            println!("  目的IP: {:?}", parsed_packet.dst_ip);
            println!("  源端口: {:?}", parsed_packet.src_port);
            println!("  目的端口: {:?}", parsed_packet.dst_port);

            if let Some(flags) = parsed_packet.tcp_flags {
                println!("  TCP标志: FIN={} SYN={} RST={} PSH={} ACK={} URG={}",
                         flags.fin, flags.syn, flags.rst, flags.psh, flags.ack, flags.urg);
            }
        }
        Err(e) => {
            println!("解析失败: {}", e);
        }
    }

    println!("\n如果需要测试真实的PCAP文件，请运行:");
    println!("cargo run --example pcap_reader_demo <path_to_pcap_file>");

    Ok(())
}

/// 创建一个测试用的TCP数据包
fn create_test_packet() -> Packet {
    // 构造一个简单的TCP SYN包
    let mut packet_data = Vec::new();

    // 以太网头部 (14字节)
    // 目的MAC: 00:11:22:33:44:55
    packet_data.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // 源MAC: AA:BB:CC:DD:EE:FF
    packet_data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    // EtherType: IPv4 (0x0800)
    packet_data.extend_from_slice(&[0x08, 0x00]);

    // IP头部 (20字节)
    // Version (4) + IHL (5)
    packet_data.push(0x45);
    // DSCP/ECN
    packet_data.push(0x00);
    // Total Length (40字节: IP头部20 + TCP头部20)
    packet_data.extend_from_slice(&[0x00, 0x28]);
    // Identification
    packet_data.extend_from_slice(&[0x12, 0x34]);
    // Flags + Fragment Offset
    packet_data.extend_from_slice(&[0x40, 0x00]);
    // TTL
    packet_data.push(0x40);
    // Protocol: TCP (6)
    packet_data.push(0x06);
    // Header Checksum (0 for simplicity, normally should be calculated)
    packet_data.extend_from_slice(&[0x00, 0x00]);
    // Source IP: 192.168.1.100
    packet_data.extend_from_slice(&[192, 168, 1, 100]);
    // Destination IP: 192.168.1.1
    packet_data.extend_from_slice(&[192, 168, 1, 1]);

    // TCP头部 (20字节)
    // Source Port: 12345
    packet_data.extend_from_slice(&[0x30, 0x39]);
    // Destination Port: 80
    packet_data.extend_from_slice(&[0x00, 0x80]);
    // Sequence Number
    packet_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    // Acknowledgment Number
    packet_data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Data Offset (5) + Reserved + NS
    packet_data.push(0x50);
    // Flags: SYN only
    packet_data.push(0x02);
    // Window Size
    packet_data.extend_from_slice(&[0x20, 0x00]);
    // Checksum (0 for simplicity)
    packet_data.extend_from_slice(&[0x00, 0x00]);
    // Urgent Pointer
    packet_data.extend_from_slice(&[0x00, 0x00]);

    // 创建数据包头部
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let header = PacketHeader::new(
        timestamp.as_secs() as u32,
        timestamp.subsec_micros(),
        packet_data.len() as u32,
        packet_data.len() as u32
    );

    Packet::new(header, packet_data)
}