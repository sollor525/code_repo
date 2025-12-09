//! 测试SYN后RST-ACK检测

use pcap_steam_anylizer::{stream::{StreamManager, StreamManagerConfig}, types::PacketInfo};
use std::net::{IpAddr, Ipv4Addr};

fn main() {
    // 创建流管理器
    let config = StreamManagerConfig {
        stream_timeout: std::time::Duration::from_secs(300),
        max_streams: 100000,
        enable_event_logging: true,
        max_events_per_stream: 1000,
        cleanup_interval: std::time::Duration::from_secs(60),
        syn_rst_888: true,   // 测试SYN后的RST-ACK检测
        handshake_ack_rst_888: false,
    };

    let mut manager = StreamManager::new(config);

    println!("测试：SYN包后立即收到RST-ACK（窗口大小888）\n");

    // SYN包
    println!("1. SYN包");
    let syn_packet = PacketInfo {
        timestamp: 1000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(1000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // RST-ACK包（窗口大小888）
    println!("2. RST-ACK包（窗口大小888）");
    let rst_ack_packet = PacketInfo {
        timestamp: 1000100,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        src_port: 80,
        dst_port: 12345,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(0),
        tcp_ack: Some(1001),
        tcp_flags: Some(0x14), // RST-ACK
        tcp_window: Some(888),
    };
    manager.process_packet(&rst_ack_packet);

    // 检查结果
    println!("\n检测结果:");
    for stream in manager.get_all_streams() {
        if stream.flow_key.protocol() == 6 {
            println!("  会话: {}", stream.flow_key.to_string());
            println!("    has_rst_888_after_syn: {}", stream.has_rst_888_after_syn);
            println!("    has_immediate_rst_888_after_syn: {}", stream.has_immediate_rst_888_after_syn);
            println!("    packets_since_syn: {}", stream.packets_since_syn);

            if stream.has_rst_888_after_syn && stream.has_immediate_rst_888_after_syn {
                println!("    ✓ 成功检测到SYN后立即RST-ACK-888");
            }
        }
    }
}