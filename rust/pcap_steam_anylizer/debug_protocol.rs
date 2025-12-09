//! 测试两种RST-888检测功能的区别
//!
//! syn-rst-888: 检测SYN后的RST+ACK（窗口888）
//! handshake-ack-rst-888: 检测三次握手ACK后的RST（窗口888，非RST-ACK）

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
    };

    let mut manager = StreamManager::new(config);

    println!("测试两种RST-888检测功能的区别：\n");

    // 测试用例1：SYN后立即RST+ACK（窗口888）
    println!("1. SYN后立即RST+ACK（窗口888）- 应该被syn-rst-888检测到");
    create_syn_immediate_rst_ack_888(&mut manager);

    // 测试用例2：SYN后立即RST（窗口888，非RST-ACK）
    println!("\n2. SYN后立即RST（窗口888）- 不应该被syn-rst-888检测到");
    create_syn_immediate_rst_888(&mut manager);

    // 测试用例3：三次握手ACK后立即RST（窗口888，非RST-ACK）
    println!("\n3. 三次握手ACK后立即RST（窗口888）- 应该被handshake-ack-rst-888检测到");
    create_handshake_rst_888(&mut manager);

    // 测试用例4：三次握手ACK后立即RST+ACK（窗口888）
    println!("\n4. 三次握手ACK后立即RST+ACK（窗口888）- 不应该被handshake-ack-rst-888检测到");
    create_handshake_rst_ack_888(&mut manager);

    // 输出检测结果
    println!("\n{}", "=".repeat(60));
    println!("检测结果总结：");
    println!("{}", "=".repeat(60));

    println!("\n--- syn-rst-888 检测结果 ---");
    println!("(检测SYN包后的RST+ACK报文，窗口大小为888)");
    for stream in manager.get_all_streams() {
        if stream.flow_key.protocol() == 6 && stream.stats.packet_count > 0 {
            println!("\n会话: {}", stream.flow_key.to_string());
            println!("  SYN后数据包数: {}", stream.packets_since_syn);
            println!("  检测到SYN后RST-888: {}", stream.has_rst_888_after_syn);
            println!("  立即SYN后RST-888: {}", stream.has_immediate_rst_888_after_syn);

            if stream.has_rst_888_after_syn {
                println!("  ✓ 被syn-rst-888检测到");
            }
        }
    }

    println!("\n--- handshake-ack-rst-888 检测结果 ---");
    println!("(检测三次握手ACK后的RST报文，窗口大小为888，非RST-ACK)");
    for stream in manager.get_all_streams() {
        if stream.flow_key.protocol() == 6 && stream.stats.packet_count > 0 {
            println!("\n会话: {}", stream.flow_key.to_string());
            println!("  三次握手ACK后数据包数: {}", stream.packets_since_handshake_ack);
            println!("  检测到三次握手ACK后RST-888: {}", stream.has_rst_888_after_handshake_ack);

            if stream.has_rst_888_after_handshake_ack {
                println!("  ✓ 被handshake-ack-rst-888检测到");
            }
        }
    }
}

fn create_syn_immediate_rst_ack_888(manager: &mut StreamManager) {
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

    // 立即RST+ACK，窗口大小888
    let rst_packet = PacketInfo {
        timestamp: 1001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        src_port: 80,
        dst_port: 12345,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(0),
        tcp_ack: Some(1001),
        tcp_flags: Some(0x14), // RST+ACK
        tcp_window: Some(888),
    };
    manager.process_packet(&rst_packet);
}

fn create_syn_immediate_rst_888(manager: &mut StreamManager) {
    // SYN包
    let syn_packet = PacketInfo {
        timestamp: 2000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        src_port: 12346,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(2000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // 立即RST（非RST-ACK），窗口大小888
    let rst_packet = PacketInfo {
        timestamp: 2001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        src_port: 80,
        dst_port: 12346,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(0),
        tcp_ack: Some(0), // RST包通常没有ACK号
        tcp_flags: Some(0x04), // 只有RST标志
        tcp_window: Some(888),
    };
    manager.process_packet(&rst_packet);
}

fn create_handshake_rst_888(manager: &mut StreamManager) {
    // SYN包
    let syn_packet = PacketInfo {
        timestamp: 3000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        src_port: 12347,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(3000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // SYN-ACK包
    let syn_ack_packet = PacketInfo {
        timestamp: 3000500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        src_port: 80,
        dst_port: 12347,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(4000),
        tcp_ack: Some(3001),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_ack_packet);

    // ACK包（完成三次握手）
    let ack_packet = PacketInfo {
        timestamp: 3001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        src_port: 12347,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(3001),
        tcp_ack: Some(4001),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&ack_packet);

    // 立即RST（非RST-ACK），窗口大小888
    let rst_packet = PacketInfo {
        timestamp: 3001100,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        src_port: 80,
        dst_port: 12347,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(4001),
        tcp_ack: Some(0), // RST包通常没有ACK号
        tcp_flags: Some(0x04), // 只有RST标志
        tcp_window: Some(888),
    };
    manager.process_packet(&rst_packet);
}

fn create_handshake_rst_ack_888(manager: &mut StreamManager) {
    // SYN包
    let syn_packet = PacketInfo {
        timestamp: 4000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 103)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 203)),
        src_port: 12348,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(5000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // SYN-ACK包
    let syn_ack_packet = PacketInfo {
        timestamp: 4000500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 203)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 103)),
        src_port: 80,
        dst_port: 12348,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(6000),
        tcp_ack: Some(5001),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_ack_packet);

    // ACK包（完成三次握手）
    let ack_packet = PacketInfo {
        timestamp: 4001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 103)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 203)),
        src_port: 12348,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(5001),
        tcp_ack: Some(6001),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&ack_packet);

    // 立即RST+ACK，窗口大小888
    let rst_packet = PacketInfo {
        timestamp: 4001100,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 203)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 103)),
        src_port: 80,
        dst_port: 12348,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(6001),
        tcp_ack: Some(5001),
        tcp_flags: Some(0x14), // RST+ACK
        tcp_window: Some(888),
    };
    manager.process_packet(&rst_packet);
}