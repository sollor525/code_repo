//! 测试三次握手ACK后的RST-888检测功能

use pcap_steam_anylizer::{stream::{StreamManager, StreamManagerConfig}, types::PacketInfo};
use std::net::{IpAddr, Ipv4Addr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建流管理器
    let config = StreamManagerConfig {
        stream_timeout: std::time::Duration::from_secs(300),
        max_streams: 100000,
        enable_event_logging: true,
        max_events_per_stream: 1000,
        cleanup_interval: std::time::Duration::from_secs(60),
    };

    let mut manager = StreamManager::new(config);

    // 测试用例1：完整三次握手后立即跟随RST-888
    println!("测试用例1：完整三次握手后立即跟随RST-888报文");

    // SYN包
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

    // SYN-ACK包
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

    // ACK包（完成三次握手）
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

    // 立即发送RST报文，窗口大小为888
    let rst_888_packet = PacketInfo {
        timestamp: 1001100,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        src_port: 80,
        dst_port: 12345,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(2001),
        tcp_ack: Some(1001),
        tcp_flags: Some(0x04), // RST (非RST-ACK)
        tcp_window: Some(888), // 窗口大小为888
    };

    manager.process_packet(&rst_888_packet);

    // 测试用例2：三次握手后有数据传输，然后才是RST-888
    println!("\n测试用例2：三次握手后有数据传输，然后才是RST-888报文");

    // SYN包
    let syn_packet2 = PacketInfo {
        timestamp: 2000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        src_port: 12346,
        dst_port: 443,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(3000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };

    manager.process_packet(&syn_packet2);

    // SYN-ACK包
    let syn_ack_packet2 = PacketInfo {
        timestamp: 2000500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        src_port: 443,
        dst_port: 12346,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(4000),
        tcp_ack: Some(3001),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };

    manager.process_packet(&syn_ack_packet2);

    // ACK包（完成三次握手）
    let ack_packet2 = PacketInfo {
        timestamp: 2001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        src_port: 12346,
        dst_port: 443,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(3001),
        tcp_ack: Some(4001),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };

    manager.process_packet(&ack_packet2);

    // 数据包
    let data_packet = PacketInfo {
        timestamp: 2001500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        src_port: 12346,
        dst_port: 443,
        protocol: 6,
        payload: vec![0x47, 0x45, 0x54, 0x20], // "GET "
        tcp_seq: Some(3001),
        tcp_ack: Some(4001),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(64240),
    };

    manager.process_packet(&data_packet);

    // RST报文，窗口大小为888
    let rst_888_packet2 = PacketInfo {
        timestamp: 2002000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        src_port: 443,
        dst_port: 12346,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(4001),
        tcp_ack: Some(3005),
        tcp_flags: Some(0x04), // RST (非RST-ACK)
        tcp_window: Some(888), // 窗口大小为888
    };

    manager.process_packet(&rst_888_packet2);

    // 测试用例3：三次握手后正常通信，没有RST-888
    println!("\n测试用例3：三次握手后正常通信，没有RST-888报文");

    // SYN包
    let syn_packet3 = PacketInfo {
        timestamp: 3000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        src_port: 12347,
        dst_port: 22,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(5000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };

    manager.process_packet(&syn_packet3);

    // SYN-ACK包
    let syn_ack_packet3 = PacketInfo {
        timestamp: 3000500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        src_port: 22,
        dst_port: 12347,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(6000),
        tcp_ack: Some(5001),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };

    manager.process_packet(&syn_ack_packet3);

    // ACK包（完成三次握手）
    let ack_packet3 = PacketInfo {
        timestamp: 3001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        src_port: 12347,
        dst_port: 22,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(5001),
        tcp_ack: Some(6001),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };

    manager.process_packet(&ack_packet3);

    // 检查结果
    println!("\n检查检测结果:");

    let mut total_streams = 0;
    let mut streams_with_rst_888_after_handshake = 0;
    let mut streams_without_rst_888_after_handshake = 0;

    for stream in manager.get_all_streams() {
        total_streams += 1;

        // 只检查TCP流
        if stream.flow_key.protocol() != 6 {
            continue;
        }

        // 检查是否有数据包
        if stream.stats.packet_count == 0 {
            continue;
        }

        // 检查是否有完整的三次握手
        if stream.connection.handshake.is_complete() {
            if stream.has_rst_888_after_handshake_ack {
                streams_with_rst_888_after_handshake += 1;
                println!("  会话 {}: 三次握手ACK后有RST-888报文", stream.flow_key.to_string());
                println!("    三次握手ACK后的数据包数: {}", stream.packets_since_handshake_ack);
            } else {
                streams_without_rst_888_after_handshake += 1;
                println!("  会话 {}: 三次握手ACK后没有RST-888报文", stream.flow_key.to_string());
                println!("    三次握手ACK后的数据包数: {}", stream.packets_since_handshake_ack);
            }
        }
    }

    println!("\n统计结果:");
    println!("  总TCP流数: {}", total_streams);
    println!("  三次握手完成且有RST-888的流数: {}", streams_with_rst_888_after_handshake);
    println!("  三次握手完成且无RST-888的流数: {}", streams_without_rst_888_after_handshake);

    Ok(())
}