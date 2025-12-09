//! 流信息格式化器演示程序
//!
//! 此程序演示如何使用 FlowFormatter 来格式化输出流信息

use std::net::{IpAddr, Ipv4Addr};
use pcap_steam_anylizer::output::{FlowFormatter, OutputFormat, SortField, SortOrder, FlowFilter};
use pcap_steam_anylizer::types::flow::FlowKey;
use pcap_steam_anylizer::types::stream::{TcpStream, TcpState};
use pcap_steam_anylizer::types::flow::{FlowDirection};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 流信息格式化器演示 ===\n");

    // 创建一些示例流
    let streams = create_sample_streams();

    // 1. 表格格式输出
    println!("1. 表格格式输出（简洁模式）：");
    println!("{}", "=".repeat(80));
    let formatter = FlowFormatter::new(OutputFormat::Table);
    let output = formatter.format_streams(&streams.iter().collect::<Vec<_>>())?;
    print!("{}", output);
    println!();

    // 2. 表格格式输出（详细模式）
    println!("\n2. 表格格式输出（详细模式）：");
    println!("{}", "=".repeat(120));
    let formatter = FlowFormatter::new(OutputFormat::Table)
        .verbose(true)
        .color(true);
    let output = formatter.format_streams(&streams.iter().collect::<Vec<_>>())?;
    print!("{}", output);
    println!();

    // 3. JSON格式输出
    println!("\n3. JSON格式输出：");
    println!("{}", "=".repeat(80));
    let formatter = FlowFormatter::new(OutputFormat::Json)
        .verbose(true);
    let output = formatter.format_streams(&streams.iter().collect::<Vec<_>>())?;
    print!("{}", output);
    println!();

    // 4. CSV格式输出
    println!("\n4. CSV格式输出：");
    println!("{}", "=".repeat(80));
    let formatter = FlowFormatter::new(OutputFormat::Csv)
        .verbose(true);
    let output = formatter.format_streams(&streams.iter().collect::<Vec<_>>())?;
    print!("{}", output);
    println!();

    // 5. 简单文本格式输出
    println!("\n5. 简单文本格式输出（详细模式）：");
    println!("{}", "=".repeat(80));
    let formatter = FlowFormatter::new(OutputFormat::Simple)
        .verbose(true);
    let output = formatter.format_streams(&streams.iter().collect::<Vec<_>>())?;
    print!("{}", output);
    println!();

    // 6. 使用过滤器
    println!("\n6. 过滤器演示 - 只显示TCP流量：");
    println!("{}", "=".repeat(80));
    let filter = FlowFilter::new()
        .protocol(6)  // TCP
        .packet_range(5, u64::MAX);
    let formatter = FlowFormatter::new(OutputFormat::Table)
        .filter(filter);
    let output = formatter.format_streams(&streams.iter().collect::<Vec<_>>())?;
    print!("{}", output);
    println!();

    // 7. 排序演示 - 按数据包数量降序
    println!("\n7. 排序演示 - 按数据包数量降序：");
    println!("{}", "=".repeat(80));
    let formatter = FlowFormatter::new(OutputFormat::Table)
        .sort_by(SortField::PacketCount)
        .sort_order(SortOrder::Descending);
    let output = formatter.format_streams(&streams.iter().collect::<Vec<_>>())?;
    print!("{}", output);
    println!();

    // 8. HTTP流量过滤
    println!("\n8. HTTP流量过滤（端口80/8080）：");
    println!("{}", "=".repeat(80));
    let filter = FlowFilter::new()
        .dst_port(80)
        .complete_only(true);
    let formatter = FlowFormatter::new(OutputFormat::Simple)
        .filter(filter)
        .verbose(true);
    let output = formatter.format_streams(&streams.iter().collect::<Vec<_>>())?;
    print!("{}", output);

    Ok(())
}

/// 创建示例流数据
fn create_sample_streams() -> Vec<TcpStream> {
    let mut streams = Vec::new();

    // 流1: HTTP请求 (完整连接)
    let flow_key1 = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        54321,
        80,
        6
    );
    let mut stream1 = TcpStream::new(flow_key1);
    setup_http_stream(&mut stream1);
    streams.push(stream1);

    // 流2: HTTPS请求 (活动连接)
    let flow_key2 = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(151, 101, 1, 69)),
        54322,
        443,
        6
    );
    let mut stream2 = TcpStream::new(flow_key2);
    setup_https_stream(&mut stream2);
    streams.push(stream2);

    // 流3: SSH连接 (长时间连接)
    let flow_key3 = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
        54323,
        22,
        6
    );
    let mut stream3 = TcpStream::new(flow_key3);
    setup_ssh_stream(&mut stream3);
    streams.push(stream3);

    // 流4: DNS查询 (UDP)
    let flow_key4 = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        54324,
        53,
        17
    );
    let mut stream4 = TcpStream::new(flow_key4);
    setup_dns_stream(&mut stream4);
    streams.push(stream4);

    // 流5: 被重置的连接
    let flow_key5 = FlowKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        54325,
        80,
        6
    );
    let mut stream5 = TcpStream::new(flow_key5);
    setup_reset_stream(&mut stream5);
    streams.push(stream5);

    streams
}

/// 设置HTTP流的数据
fn setup_http_stream(stream: &mut TcpStream) {
    stream.update_state(TcpState::Established, 1_600_000_000_000);
    stream.connection.handshake.client_syn = true;
    stream.connection.handshake.server_syn_ack = true;
    stream.connection.handshake.client_ack = true;
    stream.connection.handshake.start_time = Some(1_600_000_000_000);
    stream.connection.handshake.end_time = Some(1_600_000_000_050_000);
    stream.connection.handshake.duration = Some(50_000);

    stream.connection.set_established(1_600_000_000_050_000);
    stream.connection.close.client_fin = true;
    stream.connection.close.server_fin = true;
    stream.connection.close.client_ack = true;
    stream.connection.close.server_ack = true;
    stream.connection.close.start_time = Some(1_600_000_005_000_000);
    stream.connection.close.end_time = Some(1_600_000_005_100_000);
    stream.connection.close.duration = Some(100_000);

    stream.stats.update(1500, FlowDirection::ClientToServer, 1_600_000_000_100_000);
    stream.stats.update(1400, FlowDirection::ServerToClient, 1_600_000_000_200_000);
    stream.stats.update(800, FlowDirection::ClientToServer, 1_600_000_001_000_000);
    stream.stats.update(12000, FlowDirection::ServerToClient, 1_600_000_002_000_000);
    stream.stats.update(500, FlowDirection::ClientToServer, 1_600_000_003_000_000);
    stream.stats.update(400, FlowDirection::ServerToClient, 1_600_000_004_000_000);

    stream.client_received = 13800;
    stream.server_received = 2800;

    stream.add_label("HTTP".to_string());
    stream.add_label("Web".to_string());
}

/// 设置HTTPS流的数据
fn setup_https_stream(stream: &mut TcpStream) {
    stream.update_state(TcpState::Established, 1_600_000_010_000_000);
    stream.connection.handshake.client_syn = true;
    stream.connection.handshake.server_syn_ack = true;
    stream.connection.handshake.client_ack = true;
    stream.connection.handshake.start_time = Some(1_600_000_010_000_000);
    stream.connection.handshake.end_time = Some(1_600_000_010_080_000);
    stream.connection.handshake.duration = Some(80_000);

    stream.connection.set_established(1_600_000_010_080_000);
    stream.connection.update_activity(1_600_000_050_000_000);

    stream.stats.update(1500, FlowDirection::ClientToServer, 1_600_000_010_100_000);
    stream.stats.update(1400, FlowDirection::ServerToClient, 1_600_000_010_200_000);
    stream.stats.update(2000, FlowDirection::ClientToServer, 1_600_000_011_000_000);
    stream.stats.update(5000, FlowDirection::ServerToClient, 1_600_000_012_000_000);
    stream.stats.update(3000, FlowDirection::ClientToServer, 1_600_000_015_000_000);
    stream.stats.update(8000, FlowDirection::ServerToClient, 1_600_000_020_000_000);
    stream.stats.update(1500, FlowDirection::ClientToServer, 1_600_000_030_000_000);
    stream.stats.update(3000, FlowDirection::ServerToClient, 1_600_000_040_000_000);

    stream.client_received = 17400;
    stream.server_received = 8000;
    stream.connection.retransmission_count = 1;

    stream.add_label("HTTPS".to_string());
    stream.add_label("TLS".to_string());
}

/// 设置SSH流的数据
fn setup_ssh_stream(stream: &mut TcpStream) {
    stream.update_state(TcpState::Established, 1_600_000_000_000_000);
    stream.connection.handshake.client_syn = true;
    stream.connection.handshake.server_syn_ack = true;
    stream.connection.handshake.client_ack = true;
    stream.connection.handshake.start_time = Some(1_600_000_000_000_000);
    stream.connection.handshake.end_time = Some(1_600_000_000_100_000);
    stream.connection.handshake.duration = Some(100_000);

    stream.connection.set_established(1_600_000_000_100_000);
    stream.connection.update_activity(1_600_030_000_000_000);

    stream.stats.update(1000, FlowDirection::ClientToServer, 1_600_000_000_200_000);
    stream.stats.update(800, FlowDirection::ServerToClient, 1_600_000_000_300_000);
    stream.stats.update(500, FlowDirection::ClientToServer, 1_600_001_000_000_000);
    stream.stats.update(600, FlowDirection::ServerToClient, 1_600_002_000_000_000);
    stream.stats.update(300, FlowDirection::ClientToServer, 1_600_010_000_000_000);
    stream.stats.update(400, FlowDirection::ServerToClient, 1_600_020_000_000_000);

    stream.client_received = 1800;
    stream.server_received = 1800;
    stream.connection.sack_enabled = true;
    stream.connection.timestamps_enabled = true;

    stream.add_label("SSH".to_string());
    stream.add_label("Remote".to_string());
}

/// 设置DNS流的数据（UDP，没有TCP状态）
fn setup_dns_stream(stream: &mut TcpStream) {
    // DNS流是UDP，没有TCP状态
    stream.stats.update(64, FlowDirection::ClientToServer, 1_600_000_100_000_000);
    stream.stats.update(128, FlowDirection::ServerToClient, 1_600_000_100_000_100);

    stream.client_received = 128;
    stream.server_received = 64;

    stream.add_label("DNS".to_string());
}

/// 设置被重置的流的数据
fn setup_reset_stream(stream: &mut TcpStream) {
    stream.update_state(TcpState::Reset, 1_600_000_200_000_000);
    stream.connection.handshake.client_syn = true;
    stream.connection.handshake.server_syn_ack = true;

    stream.stats.update(1500, FlowDirection::ClientToServer, 1_600_000_200_000_000);
    stream.stats.update(60, FlowDirection::ServerToClient, 1_600_000_200_000_100);

    stream.client_received = 60;
    stream.server_received = 1500;
    stream.connection.close.reset = true;

    stream.add_label("Reset".to_string());
    stream.add_label("Error".to_string());
}