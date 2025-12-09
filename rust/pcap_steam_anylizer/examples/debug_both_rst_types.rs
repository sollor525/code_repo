//! 调试两种RST-888检测功能

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
        syn_rst_888: false,  // 测试三次握手后的RST检测
        handshake_ack_rst_888: true,
    };

    let mut manager = StreamManager::new(config);

    println!("调试：测试三次握手ACK后的RST（非RST-888）\n");

    // 三次握手
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

    println!("2. SYN-ACK包");
    let syn_ack_packet = PacketInfo {
        timestamp: 1000500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        src_port: 80,
        dst_port: 12345,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(2000),
        tcp_ack: Some(1001),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_ack_packet);

    println!("3. ACK包（完成三次握手）");
    let ack_packet = PacketInfo {
        timestamp: 1001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(1001),
        tcp_ack: Some(2001),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&ack_packet);

    // 手动检查状态
    println!("\n检查ACK包后的状态:");
    for stream in manager.get_all_streams() {
        if stream.flow_key.protocol() == 6 {
            println!("  会话: {}", stream.flow_key.to_string());
            println!("    握手完成: {}", stream.connection.handshake.is_complete());
            println!("    packets_since_handshake_ack: {}", stream.packets_since_handshake_ack);
        }
    }

    println!("\n4. RST包（非RST-ACK），窗口大小888");
    let rst_packet = PacketInfo {
        timestamp: 1001100,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        src_port: 80,
        dst_port: 12345,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(2001),
        tcp_ack: Some(0), // RST包通常没有ACK号
        tcp_flags: Some(0x04), // 只有RST标志
        tcp_window: Some(888),
    };
    manager.process_packet(&rst_packet);

    // 检查最终结果
    println!("\n最终检测结果:");
    for stream in manager.get_all_streams() {
        if stream.flow_key.protocol() == 6 {
            println!("  会话: {}", stream.flow_key.to_string());
            println!("    握手完成: {}", stream.connection.handshake.is_complete());
            println!("    packets_since_handshake_ack: {}", stream.packets_since_handshake_ack);
            println!("    has_rst_888_after_handshake_ack: {}", stream.has_rst_888_after_handshake_ack);

            if stream.has_rst_888_after_handshake_ack {
                println!("    ✓ 成功检测到三次握手ACK后的RST-888");
            } else {
                println!("    ✗ 未检测到三次握手ACK后的RST-888");
            }
        }
    }
}