//! 类型使用示例
//!
//! 展示如何使用定义的各种类型

use std::net::{IpAddr, Ipv4Addr};

// 使用示例需要导入相关类型
use super::{
    Packet, PacketHeader, Protocol, TcpFlags,
    FlowKey, FlowDirection, FlowStats, FiveTuple, FlowLabel,
    TcpStream, TcpState, TcpHandshake, TcpClose,
};

/// 创建示例数据包
pub fn create_sample_packet() -> Packet {
    let header = PacketHeader::new(1640995200, 0, 100, 100); // 时间戳: 2022-01-01 00:00:00

    // 创建一个简单的TCP SYN包（简化版）
    let mut packet = Packet::new(header, vec![0u8; 100]);

    // 设置协议信息
    packet.protocols.push(Protocol::Ethernet);
    packet.protocols.push(Protocol::Ipv4);
    packet.protocols.push(Protocol::Tcp);

    // 设置IP地址
    packet.src_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    packet.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

    // 设置端口
    packet.src_port = Some(54321);
    packet.dst_port = Some(80);

    // 设置TCP标志（SYN包）
    let mut flags = TcpFlags::new();
    flags.syn = true;
    packet.tcp_flags = Some(flags);

    packet
}

/// 创建示例流键值
pub fn create_sample_flow_key() -> FlowKey {
    let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    FlowKey::new(src_ip, dst_ip, 54321, 80, 6) // 6 = TCP协议
}

/// 创建示例TCP流
pub fn create_sample_tcp_stream() -> TcpStream {
    let flow_key = create_sample_flow_key();
    let mut stream = TcpStream::new(flow_key);

    // 设置为已建立状态
    stream.update_state(TcpState::Established, 1640995200_000_000);

    // 更新序列号
    stream.update_sequence(1000, 2000, true, 100); // 客户端发送

    stream
}

/// 演示流统计的使用
pub fn demonstrate_flow_stats() {
    let mut stats = FlowStats::new();

    // 模拟接收一些数据包
    stats.update(1000, FlowDirection::ClientToServer, 1640995200_000_000);
    stats.update(500, FlowDirection::ServerToClient, 1640995200_001_000);
    stats.update(1200, FlowDirection::ClientToServer, 1640995200_002_000);

    println!("流统计信息:");
    println!("  总包数: {}", stats.packet_count);
    println!("  总字节数: {}", stats.byte_count);
    println!("  C2S包数: {}", stats.c2s_packet_count);
    println!("  S2C包数: {}", stats.s2c_packet_count);
    println!("  平均包大小: {:.2} 字节", stats.avg_packet_size);
    println!("  持续时间: {:.3} 秒", stats.duration_seconds().unwrap_or(0.0));
    println!("  包速率: {:.2} pps", stats.packets_per_second());
    println!("  吞吐量: {:.2} bps", stats.bits_per_second());
}

/// 演示TCP握手和关闭状态
pub fn demonstrate_tcp_states() {
    // 握手状态
    let mut handshake = TcpHandshake::new();
    handshake.client_syn = true;
    handshake.update(1640995200_000_000);
    handshake.server_syn_ack = true;
    handshake.update(1640995200_000_100);
    handshake.client_ack = true;
    handshake.update(1640995200_000_200);

    println!("TCP握手:");
    println!("  握手完成: {}", handshake.is_complete());
    println!("  握手时间: {:.2} ms", handshake.duration_ms().unwrap_or(0.0));

    // 关闭状态
    let mut close = TcpClose::new();
    close.client_fin = true;
    close.update(1640995280_000_000);
    close.server_fin = true;
    close.update(1640995280_000_500);

    println!("TCP关闭:");
    println!("  优雅关闭: {}", close.is_graceful());
    println!("  关闭时间: {:.2} ms", close.duration_ms().unwrap_or(0.0));
}

/// 演示五元组和流标签
pub fn demonstrate_flow_labels() {
    // 创建五元组
    let five_tuple = FiveTuple::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        54321,
        443,
        6
    );

    println!("五元组: {}", five_tuple);

    // 根据端口识别协议
    if let Some(label) = FlowLabel::from_port(443) {
        println!("端口443识别为: {}", label);
    }

    if let Some(label) = FlowLabel::from_port(80) {
        println!("端口80识别为: {}", label);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_creation() {
        let packet = create_sample_packet();
        assert_eq!(packet.len(), 100);
        assert!(packet.is_tcp());
        assert!(packet.tcp_flags.unwrap().syn);
    }

    #[test]
    fn test_flow_key() {
        let flow_key = create_sample_flow_key();
        assert!(flow_key.is_tcp());
        assert!(flow_key.is_ipv4());
        assert_eq!(flow_key.src_port(), 54321);
        assert_eq!(flow_key.dst_port(), 80);
    }

    #[test]
    fn test_tcp_stream() {
        let stream = create_sample_tcp_stream();
        assert_eq!(stream.state, TcpState::Established);
        assert_eq!(stream.client_ip(), &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(stream.server_port(), 80);
    }

    #[test]
    fn test_flow_direction() {
        let flow_key = create_sample_flow_key();
        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let server_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        assert_eq!(
            flow_key.get_direction(&client_ip, 54321),
            FlowDirection::ClientToServer
        );
        assert_eq!(
            flow_key.get_direction(&server_ip, 80),
            FlowDirection::ServerToClient
        );
    }
}