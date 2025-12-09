//! 测试完整三次握手但没有RST-888的情况

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

    println!("创建完整三次握手但没有RST-888的会话...");

    // 完整的三次握手
    // 1. SYN包
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

    // 2. SYN-ACK包
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

    // 3. ACK包（完成三次握手）
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

    // 后续的数据包（没有RST-888）
    // HTTP GET请求
    let get_packet = PacketInfo {
        timestamp: 1002000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        src_port: 12345,
        dst_port: 80,
        protocol: 6,
        payload: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        tcp_seq: Some(1001),
        tcp_ack: Some(2001),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(502),
    };

    manager.process_packet(&get_packet);

    // HTTP响应
    let http_response = PacketInfo {
        timestamp: 1003000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        src_port: 80,
        dst_port: 12345,
        protocol: 6,
        payload: b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!".to_vec(),
        tcp_seq: Some(2001),
        tcp_ack: Some(1037),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(64240),
    };

    manager.process_packet(&http_response);

    // 正常的RST包（窗口大小不是888）
    let normal_rst = PacketInfo {
        timestamp: 1004000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        src_port: 80,
        dst_port: 12345,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(2013),
        tcp_ack: Some(1037),
        tcp_flags: Some(0x14), // RST-ACK
        tcp_window: Some(1024), // 窗口大小不是888
    };

    manager.process_packet(&normal_rst);

    // 检查结果
    println!("\n检查三次握手ACK后的RST-888检测结果:");
    let mut total_streams = 0;
    let mut streams_with_rst_888 = 0;
    let mut streams_without_rst_888 = 0;

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
                streams_with_rst_888 += 1;
            } else {
                streams_without_rst_888 += 1;

                // 输出详细会话信息
                println!("\n会话详情:");
                println!("  会话ID: {}", stream.flow_key.to_string());
                println!("  客户端: {}:{}", stream.flow_key.src_ip(), stream.flow_key.src_port());
                println!("  服务器: {}:{}", stream.flow_key.dst_ip(), stream.flow_key.dst_port());
                println!("  状态: {}", stream.state.as_str());
                println!("  数据包数: {}", stream.stats.packet_count);
                println!("  字节数: {}", stream.stats.byte_count);
                println!("  三次握手ACK后的数据包数: {}", stream.packets_since_handshake_ack);

                // 显示连接持续时间
                if let Some(duration) = stream.connection.duration_seconds() {
                    println!("  持续时间: {:.3} 秒", duration);
                }

                // 握手状态
                if stream.connection.handshake.is_complete() {
                    println!("  握手: 完成 (SYN={}, SYN-ACK={}, ACK={})",
                        stream.connection.handshake.client_syn,
                        stream.connection.handshake.server_syn_ack,
                        stream.connection.handshake.client_ack);
                }

                // 关闭状态
                if stream.connection.close.is_complete() {
                    println!("  关闭: 已关闭");
                    if stream.connection.close.reset {
                        println!("  关闭方式: RST");
                    }
                } else {
                    println!("  关闭: 未关闭");
                }
            }
        }
    }

    println!("\n统计结果:");
    println!("  总TCP流数: {}", total_streams);
    println!("  三次握手完成且有RST-888报文的流数: {}", streams_with_rst_888);
    println!("  三次握手完成且无RST-888报文的流数: {}", streams_without_rst_888);

    Ok(())
}