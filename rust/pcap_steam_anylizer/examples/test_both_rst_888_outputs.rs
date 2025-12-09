//! 比较两种RST-888检测功能的输出格式

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

    println!("创建测试会话：");

    // 测试用例1：SYN后立即RST-888
    println!("\n1. SYN后立即RST-888的会话");
    create_syn_immediate_rst_888(&mut manager);

    // 测试用例2：完整三次握手但没有RST-888
    println!("\n2. 完整三次握手但没有RST-888的会话");
    create_complete_handshake_no_rst_888(&mut manager);

    // 测试用例3：三次握手后有其他报文再RST-888
    println!("\n3. 三次握手后有其他报文再RST-888的会话");
    create_handshake_delayed_rst_888(&mut manager);

    // 测试用例4：SYN后普通RST
    println!("\n4. SYN后普通RST（窗口不是888）的会话");
    create_syn_normal_rst(&mut manager);

    // 检查并输出结果
    println!("\n{}", "=".repeat(60));
    println!("检测结果对比：");
    println!("{}", "=".repeat(60));

    println!("\n--- syn-rst-888 检测结果 ---");
    println!("（检测SYN包后没有窗口大小为888的RST-ACK报文的会话）");

    let mut syn_count = 0;
    let mut syn_no_rst_888 = 0;

    for stream in manager.get_all_streams() {
        if stream.flow_key.protocol() != 6 || stream.stats.packet_count == 0 {
            continue;
        }

        syn_count += 1;
        if stream.connection.handshake.client_syn && !stream.has_immediate_rst_888_after_syn {
            syn_no_rst_888 += 1;
            print_stream_info(stream, "SYN", stream.packets_since_syn);
        }
    }

    println!("\n--- handshake-ack-rst-888 检测结果 ---");
    println!("（检测三次握手完成后的ACK报文后没有窗口大小为888的RST-ACK报文的会话）");

    let mut handshake_count = 0;
    let mut handshake_no_rst_888 = 0;

    for stream in manager.get_all_streams() {
        if stream.flow_key.protocol() != 6 || stream.stats.packet_count == 0 {
            continue;
        }

        handshake_count += 1;
        if stream.connection.handshake.is_complete() && !stream.has_rst_888_after_handshake_ack {
            handshake_no_rst_888 += 1;
            print_stream_info(stream, "三次握手ACK", stream.packets_since_handshake_ack);
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("统计摘要：");
    println!("{}", "=".repeat(60));
    println!("\nsyn-rst-888 检测:");
    println!("  总TCP流数: {}", syn_count);
    println!("  没有立即RST-888的流数: {}", syn_no_rst_888);

    println!("\nhandshake-ack-rst-888 检测:");
    println!("  完成三次握手的流数: {}", handshake_count);
    println!("  三次握手ACK后没有RST-888的流数: {}", handshake_no_rst_888);

    Ok(())
}

fn create_syn_immediate_rst_888(manager: &mut StreamManager) {
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

    // 立即RST-ACK，窗口大小888
    let rst_packet = PacketInfo {
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
    manager.process_packet(&rst_packet);
}

fn create_complete_handshake_no_rst_888(manager: &mut StreamManager) {
    // SYN
    let syn_packet = PacketInfo {
        timestamp: 2000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        src_port: 12346,
        dst_port: 443,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(2000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // SYN-ACK
    let syn_ack_packet = PacketInfo {
        timestamp: 2000500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        src_port: 443,
        dst_port: 12346,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(3000),
        tcp_ack: Some(2001),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_ack_packet);

    // ACK（完成三次握手）
    let ack_packet = PacketInfo {
        timestamp: 2001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        src_port: 12346,
        dst_port: 443,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(2001),
        tcp_ack: Some(3001),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&ack_packet);

    // 正常通信，没有RST-888
    let data_packet = PacketInfo {
        timestamp: 2002000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 201)),
        src_port: 12346,
        dst_port: 443,
        protocol: 6,
        payload: b"Hello".to_vec(),
        tcp_seq: Some(2001),
        tcp_ack: Some(3001),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(502),
    };
    manager.process_packet(&data_packet);
}

fn create_handshake_delayed_rst_888(manager: &mut StreamManager) {
    // SYN
    let syn_packet = PacketInfo {
        timestamp: 3000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        src_port: 12347,
        dst_port: 22,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(4000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // SYN-ACK
    let syn_ack_packet = PacketInfo {
        timestamp: 3000500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        src_port: 22,
        dst_port: 12347,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(5000),
        tcp_ack: Some(4001),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_ack_packet);

    // ACK（完成三次握手）
    let ack_packet = PacketInfo {
        timestamp: 3001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        src_port: 12347,
        dst_port: 22,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(4001),
        tcp_ack: Some(5001),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&ack_packet);

    // 一些数据包
    let data_packet = PacketInfo {
        timestamp: 3002000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        src_port: 12347,
        dst_port: 22,
        protocol: 6,
        payload: b"SSH".to_vec(),
        tcp_seq: Some(4001),
        tcp_ack: Some(5001),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(502),
    };
    manager.process_packet(&data_packet);

    // RST-ACK，窗口大小888
    let rst_packet = PacketInfo {
        timestamp: 3003000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 202)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
        src_port: 22,
        dst_port: 12347,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(5001),
        tcp_ack: Some(4004),
        tcp_flags: Some(0x14), // RST-ACK
        tcp_window: Some(888),
    };
    manager.process_packet(&rst_packet);
}

fn create_syn_normal_rst(manager: &mut StreamManager) {
    // SYN包
    let syn_packet = PacketInfo {
        timestamp: 4000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 103)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 203)),
        src_port: 12348,
        dst_port: 8080,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(6000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // RST-ACK，窗口大小不是888
    let rst_packet = PacketInfo {
        timestamp: 4000100,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 203)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 103)),
        src_port: 8080,
        dst_port: 12348,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(0),
        tcp_ack: Some(6001),
        tcp_flags: Some(0x14), // RST-ACK
        tcp_window: Some(1024), // 不是888
    };
    manager.process_packet(&rst_packet);
}

fn print_stream_info(stream: &pcap_steam_anylizer::TcpStream, label: &str, packets_count: u32) {
    println!("  会话ID: {}", stream.flow_key.to_string());
    println!("    客户端: {}:{}", stream.flow_key.src_ip(), stream.flow_key.src_port());
    println!("    服务器: {}:{}", stream.flow_key.dst_ip(), stream.flow_key.dst_port());
    println!("    状态: {}", stream.state.as_str());
    println!("    数据包数: {}", stream.stats.packet_count);
    println!("    字节数: {}", stream.stats.byte_count);
    println!("    {}后的数据包数: {}", label, packets_count);

    if let Some(duration) = stream.connection.duration_seconds() {
        println!("    持续时间: {:.3} 秒", duration);
    }

    if stream.connection.handshake.is_complete() {
        println!("    握手: 完成");
    } else {
        println!("    握手: 未完成");
    }

    if stream.connection.close.is_complete() {
        println!("    关闭: 已关闭");
        if stream.connection.close.reset {
            println!("    关闭方式: RST");
        }
    } else {
        println!("    关闭: 未关闭");
    }
    println!();
}