//! 测试三次握手ACK后没有RST-888报文的输出

use pcap_steam_anylizer::{stream::{StreamManager, StreamManagerConfig}, types::PacketInfo};
use std::net::{IpAddr, Ipv4Addr};
use std::fs::File;
use std::io::Write;

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

    println!("创建测试场景：包含有RST-888和无RST-888的会话");

    // 会话1：三次握手后立即RST-888
    println!("\n1. 创建三次握手后立即RST-888的会话（不会在输出中显示）");
    create_handshake_with_rst_888(&mut manager, 1);

    // 会话2：三次握手后没有RST-888
    println!("\n2. 创建三次握手后没有RST-888的会话（会在输出中显示）");
    create_handshake_without_rst_888(&mut manager, 2);

    // 会话3：三次握手后有其他数据，然后RST-888
    println!("\n3. 创建三次握手后有其他数据再RST-888的会话（不会在输出中显示）");
    create_handshake_delayed_rst_888(&mut manager, 3);

    // 会话4：三次握手后正常通信，没有RST
    println!("\n4. 创建三次握手后正常通信，没有RST的会话（会在输出中显示）");
    create_handshake_normal_communication(&mut manager, 4);

    // 模拟--handshake-ack-rst-888的输出
    println!("\n模拟 --handshake-ack-rst-888 输出：");
    println!("(只显示三次握手完成且无RST-888报文的会话)");

    let mut output = File::create("handshake_rst_888_output.txt")?;
    writeln!(output, "# 三次握手ACK后RST-888检测结果报告")?;
    writeln!(output, "# 以下会话在三次握手完成后的ACK报文后没有收到窗口大小为888的RST-ACK报文")?;
    writeln!(output, "")?;

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
                println!("\n[跳过] 会话 {} - 三次握手ACK后有RST-888", stream.flow_key.to_string());
            } else {
                streams_without_rst_888 += 1;

                println!("\n[输出] 会话 {} - 三次握手ACK后无RST-888", stream.flow_key.to_string());

                // 输出会话详细信息
                writeln!(output, "会话ID: {}", stream.flow_key.to_string())?;
                writeln!(output, "  客户端: {}:{}", stream.flow_key.src_ip(), stream.flow_key.src_port())?;
                writeln!(output, "   服务器: {}:{}", stream.flow_key.dst_ip(), stream.flow_key.dst_port())?;
                writeln!(output, "  状态: {}", stream.state.as_str())?;
                writeln!(output, "  数据包数: {}", stream.stats.packet_count)?;
                writeln!(output, "  字节数: {}", stream.stats.byte_count)?;

                // 显示三次握手ACK后的数据包数
                writeln!(output, "  三次握手ACK后的数据包数: {}", stream.packets_since_handshake_ack)?;

                // 显示连接持续时间
                if let Some(duration) = stream.connection.duration_seconds() {
                    writeln!(output, "  持续时间: {:.3} 秒", duration)?;
                }

                // 显示握手状态
                if stream.connection.handshake.is_complete() {
                    writeln!(output, "  握手: 完成")?;
                } else {
                    writeln!(output, "  握手: 未完成")?;
                }

                // 显示关闭状态
                if stream.connection.close.is_complete() {
                    writeln!(output, "  关闭: 已关闭")?;
                    if stream.connection.close.reset {
                        writeln!(output, "  关闭方式: RST")?;
                    }
                } else {
                    writeln!(output, "  关闭: 未关闭")?;
                }

                writeln!(output, "")?;
            }
        }
    }

    // 写入统计信息
    writeln!(output, "# 统计摘要:")?;
    writeln!(output, "# 总TCP流数: {}", total_streams)?;
    writeln!(output, "# 三次握手完成且有RST-888报文的流数: {}", streams_with_rst_888)?;
    writeln!(output, "# 三次握手完成且无RST-888报文的流数: {}", streams_without_rst_888)?;

    println!("\n{}", "=".repeat(60));
    println!("输出统计摘要：");
    println!("{}", "=".repeat(60));
    println!("\n# 统计摘要:");
    println!("# 总TCP流数: {}", total_streams);
    println!("# 三次握手完成且有RST-888报文的流数: {}", streams_with_rst_888);
    println!("# 三次握手完成且无RST-888报文的流数: {}", streams_without_rst_888);

    println!("\n详细输出已保存到 handshake_rst_888_output.txt");

    Ok(())
}

fn create_handshake_with_rst_888(manager: &mut StreamManager, id: u8) {
    let base_ip = 100 + id as u8;

    // SYN
    let syn_packet = PacketInfo {
        timestamp: id as u64 * 1000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12340 + id as u16,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(1000 * id as u32),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // SYN-ACK
    let syn_ack_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        src_port: 80,
        dst_port: 12340 + id as u16,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(2000 * id as u32),
        tcp_ack: Some((1000 * id as u32) + 1),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_ack_packet);

    // ACK（完成三次握手）
    let ack_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 1000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12340 + id as u16,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some((1000 * id as u32) + 1),
        tcp_ack: Some((2000 * id as u32) + 1),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&ack_packet);

    // 立即RST-ACK，窗口大小888
    let rst_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 1100,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        src_port: 80,
        dst_port: 12340 + id as u16,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some((2000 * id as u32) + 1),
        tcp_ack: Some((1000 * id as u32) + 1),
        tcp_flags: Some(0x14), // RST-ACK
        tcp_window: Some(888),
    };
    manager.process_packet(&rst_packet);
}

fn create_handshake_without_rst_888(manager: &mut StreamManager, id: u8) {
    let base_ip = 20 + id as u8;

    // SYN
    let syn_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 10000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12350 + id as u16,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(10000 + id as u32 * 1000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // SYN-ACK
    let syn_ack_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 10000500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        src_port: 80,
        dst_port: 12350 + id as u16,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(20000 + id as u32 * 1000),
        tcp_ack: Some((10000 + id as u32 * 1000) + 1),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_ack_packet);

    // ACK（完成三次握手）
    let ack_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 10001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12350 + id as u16,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some((10000 + id as u32 * 1000) + 1),
        tcp_ack: Some((20000 + id as u32 * 1000) + 1),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&ack_packet);

    // HTTP GET请求
    let get_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 10002000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12350 + id as u16,
        dst_port: 80,
        protocol: 6,
        payload: format!("GET /page{} HTTP/1.1\r\nHost: example.com\r\n\r\n", id).into_bytes(),
        tcp_seq: Some((10000 + id as u32 * 1000) + 1),
        tcp_ack: Some((20000 + id as u32 * 1000) + 1),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(502),
    };
    manager.process_packet(&get_packet);

    // HTTP 200响应
    let response_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 10003000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        src_port: 80,
        dst_port: 12350 + id as u16,
        protocol: 6,
        payload: format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\nPage {} content", 12, id).into_bytes(),
        tcp_seq: Some((20000 + id as u32 * 1000) + 1),
        tcp_ack: Some((10000 + id as u32 * 1000) + 30),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&response_packet);

    // 正常的FIN包
    let fin_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 10004000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12350 + id as u16,
        dst_port: 80,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some((10000 + id as u32 * 1000) + 45),
        tcp_ack: Some((20000 + id as u32 * 1000) + 40),
        tcp_flags: Some(0x11), // FIN
        tcp_window: Some(502),
    };
    manager.process_packet(&fin_packet);

    // ACK
    let final_ack = PacketInfo {
        timestamp: id as u64 * 1000000 + 10005000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        src_port: 80,
        dst_port: 12350 + id as u16,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some((20000 + id as u32 * 1000) + 41),
        tcp_ack: Some((10000 + id as u32 * 1000) + 46),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(502),
    };
    manager.process_packet(&final_ack);
}

fn create_handshake_delayed_rst_888(manager: &mut StreamManager, id: u8) {
    let base_ip = 30 + id as u8;

    // SYN
    let syn_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 20000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12360 + id as u16,
        dst_port: 443,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(20000 + id as u32 * 1000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // SYN-ACK
    let syn_ack_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 20000500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        src_port: 443,
        dst_port: 12360 + id as u16,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(30000 + id as u32 * 1000),
        tcp_ack: Some((20000 + id as u32 * 1000) + 1),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_ack_packet);

    // ACK（完成三次握手）
    let ack_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 20001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12360 + id as u16,
        dst_port: 443,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some((20000 + id as u32 * 1000) + 1),
        tcp_ack: Some((30000 + id as u32 * 1000) + 1),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&ack_packet);

    // Client Hello
    let client_hello = PacketInfo {
        timestamp: id as u64 * 1000000 + 20002000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12360 + id as u16,
        dst_port: 443,
        protocol: 6,
        payload: b"Client Hello".to_vec(),
        tcp_seq: Some((20000 + id as u32 * 1000) + 1),
        tcp_ack: Some((30000 + id as u32 * 1000) + 1),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(502),
    };
    manager.process_packet(&client_hello);

    // Server Hello
    let server_hello = PacketInfo {
        timestamp: id as u64 * 1000000 + 20003000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        src_port: 443,
        dst_port: 12360 + id as u16,
        protocol: 6,
        payload: b"Server Hello".to_vec(),
        tcp_seq: Some((30000 + id as u32 * 1000) + 1),
        tcp_ack: Some((20000 + id as u32 * 1000) + 13),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&server_hello);

    // RST-ACK，窗口大小888
    let rst_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 20004000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        src_port: 443,
        dst_port: 12360 + id as u16,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some((30000 + id as u32 * 1000) + 1),
        tcp_ack: Some((20000 + id as u32 * 1000) + 25),
        tcp_flags: Some(0x14), // RST-ACK
        tcp_window: Some(888),
    };
    manager.process_packet(&rst_packet);
}

fn create_handshake_normal_communication(manager: &mut StreamManager, id: u8) {
    let base_ip = 40 + id as u8;

    // SYN
    let syn_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 30000000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12370 + id as u16,
        dst_port: 22,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(30000 + id as u32 * 1000),
        tcp_ack: Some(0),
        tcp_flags: Some(0x02), // SYN
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_packet);

    // SYN-ACK
    let syn_ack_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 30000500,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        src_port: 22,
        dst_port: 12370 + id as u16,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some(40000 + id as u32 * 1000),
        tcp_ack: Some((30000 + id as u32 * 1000) + 1),
        tcp_flags: Some(0x12), // SYN-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&syn_ack_packet);

    // ACK（完成三次握手）
    let ack_packet = PacketInfo {
        timestamp: id as u64 * 1000000 + 30001000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12370 + id as u16,
        dst_port: 22,
        protocol: 6,
        payload: vec![],
        tcp_seq: Some((30000 + id as u32 * 1000) + 1),
        tcp_ack: Some((40000 + id as u32 * 1000) + 1),
        tcp_flags: Some(0x10), // ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&ack_packet);

    // SSH认证
    let ssh_auth = PacketInfo {
        timestamp: id as u64 * 1000000 + 30002000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12370 + id as u16,
        dst_port: 22,
        protocol: 6,
        payload: b"SSH Authentication".to_vec(),
        tcp_seq: Some((30000 + id as u32 * 1000) + 1),
        tcp_ack: Some((40000 + id as u32 * 1000) + 1),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(502),
    };
    manager.process_packet(&ssh_auth);

    // SSH命令
    let ssh_command = PacketInfo {
        timestamp: id as u64 * 1000000 + 30003000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        src_port: 12370 + id as u16,
        dst_port: 22,
        protocol: 6,
        payload: b"ls -la".to_vec(),
        tcp_seq: Some((30000 + id as u32 * 1000) + 19),
        tcp_ack: Some((40000 + id as u32 * 1000) + 1),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(502),
    };
    manager.process_packet(&ssh_command);

    // 命令输出
    let command_output = PacketInfo {
        timestamp: id as u64 * 1000000 + 30004000,
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip + 10)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, base_ip)),
        src_port: 22,
        dst_port: 12370 + id as u16,
        protocol: 6,
        payload: b"file1 file2 file3".to_vec(),
        tcp_seq: Some((40000 + id as u32 * 1000) + 1),
        tcp_ack: Some((30000 + id as u32 * 1000) + 26),
        tcp_flags: Some(0x18), // PSH-ACK
        tcp_window: Some(64240),
    };
    manager.process_packet(&command_output);

    // 持续连接，长时间没有其他报文
    // （模拟长时间连接）
}