//! 流重组功能演示
//!
//! 演示如何使用TCP流管理器、重组器和IP分片重组器

use pcap_steam_anylizer::stream::{
    StreamManager, StreamManagerConfig,
    TcpReassembler, ReassemblerConfig,
    IpFragmenter, FragmenterConfig,
};
use pcap_steam_anylizer::types::PacketInfo;
use std::net::{Ipv4Addr, IpAddr};
use std::time::Duration;

fn main() {
    println!("TCP流管理和重组演示");
    println!("====================");

    // 创建流管理器
    let manager_config = StreamManagerConfig {
        stream_timeout: Duration::from_secs(300),
        max_streams: 10000,
        enable_event_logging: true,
        max_events_per_stream: 100,
        cleanup_interval: Duration::from_secs(30),
    };
    let mut stream_manager = StreamManager::new(manager_config);

    // 创建TCP重组器
    let reassembler_config = ReassemblerConfig {
        max_buffer_size: 4 * 1024 * 1024, // 4MB
        segment_timeout: Duration::from_secs(30),
        max_out_of_order_window: 32768,
        enable_fast_reassembly: true,
        detect_duplicates: true,
        max_overlap_count: 5,
    };
    let mut tcp_reassembler = TcpReassembler::new(reassembler_config);

    // 创建IP分片重组器
    let fragmenter_config = FragmenterConfig {
        max_cache_size: 16 * 1024 * 1024, // 16MB
        fragment_timeout: Duration::from_secs(60),
        max_fragments_per_packet: 32,
        enable_overlap_detection: true,
        max_overlap_count: 5,
        drop_overlapping_fragments: false,
    };
    let mut ip_fragmenter = IpFragmenter::new(fragmenter_config);

    // 模拟TCP数据包
    println!("\n1. TCP流管理演示");
    println!("模拟TCP三次握手过程...");

    // SYN包
    let syn_packet = create_tcp_packet(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        54321,
        80,
        vec![],
        Some(1000),
        Some(0),
        Some(0x02), // SYN
    );

    let flow_key1 = stream_manager.process_packet(&syn_packet);
    println!("  - 处理SYN包: {:?}", flow_key1);

    // SYN-ACK包
    let syn_ack_packet = create_tcp_packet(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        80,
        54321,
        vec![],
        Some(2000),
        Some(1001),
        Some(0x12), // SYN+ACK
    );

    let flow_key2 = stream_manager.process_packet(&syn_ack_packet);
    println!("  - 处理SYN-ACK包: {:?}", flow_key2);

    // ACK包
    let ack_packet = create_tcp_packet(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        54321,
        80,
        vec![],
        Some(1001),
        Some(2000),
        Some(0x10), // ACK
    );

    let flow_key3 = stream_manager.process_packet(&ack_packet);
    println!("  - 处理ACK包: {:?}", flow_key3);

    // 检查流状态
    if let Some(stream) = stream_manager.find_stream(&flow_key1) {
        println!("  - 流状态: {:?}", stream.state);
        println!("  - 连接已建立: {}", stream.connection.handshake.is_complete());
    }

    // 模拟数据传输
    println!("\n2. TCP重组演示");
    println!("模拟乱序数据包重组...");

    tcp_reassembler.set_initial_seq(2000);

    // 数据包2（先到达）
    let data2 = vec![5, 6, 7, 8];
    let packet2 = create_tcp_packet(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        54321,
        80,
        data2,
        Some(2000),
        Some(0),
        Some(0x18), // PSH+ACK
    );

    let result2 = tcp_reassembler.process_segment(&packet2);
    println!("  - 处理数据包2: {:?}", result2.is_ok());

    // 数据包1（后到达）
    let data1 = vec![1, 2, 3, 4];
    let packet1 = create_tcp_packet(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        54321,
        80,
        data1,
        Some(2000),
        Some(0),
        Some(0x18), // PSH+ACK
    );

    let result1 = tcp_reassembler.process_segment(&packet1);
    if let Ok(Some(assembled)) = result1 {
        println!("  - 重组成功: 数据长度={}, 数据={:?}", assembled.data.len(), assembled.data);
    }

    // 模拟IP分片
    println!("\n3. IP分片重组演示");
    println!("模拟IP分片重组...");

    // 创建分片包
    let fragment1 = create_tcp_packet(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        54321,
        80,
        vec![1, 2, 3, 4], // 分片1数据
        None,
        None,
        None,
    );

    let frag_result1 = ip_fragmenter.process_fragment(&fragment1);
    println!("  - 处理分片1: {:?}", frag_result1.is_ok());

    // 输出统计信息
    println!("\n4. 统计信息");

    let manager_stats = stream_manager.get_stats();
    println!("  流管理器统计:");
    println!("    - 当前活跃流数: {}", manager_stats.active_streams);
    println!("    - 总创建流数: {}", manager_stats.total_streams_created);
    println!("    - 最大并发流数: {}", manager_stats.peak_concurrent_streams);

    let reassembler_stats = tcp_reassembler.get_stats();
    println!("  TCP重组器统计:");
    println!("    - 接收的分段数: {}", reassembler_stats.total_segments);
    println!("    - 乱序分段数: {}", reassembler_stats.out_of_order_segments);
    println!("    - 平均重组时间: {:.2} μs", reassembler_stats.avg_assembly_time_us);

    let fragmenter_stats = ip_fragmenter.get_stats();
    println!("  IP分片重组器统计:");
    println!("    - 接收的分片数: {}", fragmenter_stats.total_fragments);
    println!("    - 重组的包数: {}", fragmenter_stats.reassembled_packets);
    println!("    - 缓存使用峰值: {} 字节", fragmenter_stats.peak_cache_usage);

    println!("\n演示完成！");
}

/// 创建TCP数据包
fn create_tcp_packet(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>,
    seq: Option<u32>,
    ack: Option<u32>,
    flags: Option<u8>,
) -> PacketInfo {
    PacketInfo {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: 6, // TCP
        payload,
        tcp_seq: seq,
        tcp_ack: ack,
        tcp_flags: flags,
        tcp_window: Some(8192),
    }
}