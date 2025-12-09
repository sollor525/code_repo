//! 测试 Rayon 并行处理功能

use pcap_steam_anylizer::{
    rayon_parallel::{RayonProcessor, RayonConfig},
    stream::StreamManagerConfig,
    pcap::{PcapReader, PacketParser},
    types::PacketInfo,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 获取命令行参数
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("用法: {} <pcap文件> [group_by_flow]", args[0]);
        eprintln!("  group_by_flow: 使用 'flow' 来启用按流分组处理");
        std::process::exit(1);
    }

    let pcap_path = &args[1];
    let group_by_flow = args.get(2).map(|s| s == "flow").unwrap_or(false);

    println!("=== Rayon 并行处理测试 ===");
    println!("PCAP文件: {}", pcap_path);
    println!("处理模式: {}", if group_by_flow { "按流分组" } else { "批次并行" });
    println!();

    // 创建 Rayon 配置
    let stream_config = StreamManagerConfig {
        stream_timeout: std::time::Duration::from_secs(300),
        max_streams: 100000,
        enable_event_logging: true,
        max_events_per_stream: 100,
        cleanup_interval: std::time::Duration::from_secs(60),
        syn_rst_888: false,
        handshake_ack_rst_888: false,
    };

    let rayon_config = RayonConfig {
        stream_config,
        batch_size: 1000,
        enable_progress: true,
        thread_pool_size: None, // 使用默认（CPU核心数）
    };

    // 创建 Rayon 处理器
    let processor = RayonProcessor::new(rayon_config);

    // 读取和解析所有数据包
    println!("正在读取和解析 PCAP 文件...");
    let start_time = std::time::Instant::now();

    let mut pcap_reader = PcapReader::open(pcap_path)?;
    let linktype = pcap_reader.global_header().linktype;
    let parser = PacketParser::new(false, false, linktype);

    let mut packets = Vec::new();
    let mut parse_errors = 0u64;

    for packet_result in pcap_reader {
        match packet_result {
            Ok(packet) => {
                match parser.parse(packet) {
                    Ok(parsed_packet) => {
                        let packet_info: PacketInfo = parsed_packet.into();
                        packets.push(packet_info);
                    }
                    Err(_) => {
                        parse_errors += 1;
                    }
                }
            }
            Err(_) => {
                parse_errors += 1;
            }
        }
    }

    let read_time = start_time.elapsed();
    println!("读取完成: {} 个数据包，解析错误: {}，耗时 {:?}",
             packets.len(), parse_errors, read_time);
    println!();

    // 使用 Rayon 并行处理
    println!("开始 Rayon 并行处理...");
    let result = if group_by_flow {
        processor.process_packets_by_flow(packets)?
    } else {
        processor.process_packets_parallel(packets)?
    };

    // 输出结果
    println!();
    println!("=== 处理结果 ===");
    println!("处理的数据包总数: {}", result.packet_count);
    println!("识别的流数: {}", result.stream_count);
    println!("处理时间: {:?}", result.processing_time);
    println!("读取时间: {:?}", read_time);
    println!("总耗时: {:?}", start_time.elapsed());
    println!("处理速度: {:.2} 包/秒", result.packets_per_second());
    println!("平均处理时间: {:.2} 微秒/包", result.avg_packet_time_us());

    // 显示前几个流的信息
    println!();
    println!("=== 流信息（前10个）===");
    for (i, stream) in result.streams.iter().take(10).enumerate() {
        println!("{}. 流: {}", i + 1, stream.flow_key);
        println!("   数据包数: {}", stream.stats.packet_count);
        println!("   字节数: {}", stream.stats.byte_count);
        println!("   握手完成: {}", stream.connection.handshake.is_complete());
        if let Some(duration) = stream.connection.duration_seconds() {
            println!("   持续时间: {:.3} 秒", duration);
        }
        println!();
    }

    // 按数据包数量排序
    println!("=== 按数据包数量排序的前10个流 ===");
    let mut sorted_streams = result.streams.clone();
    sorted_streams.sort_by(|a, b| b.stats.packet_count.cmp(&a.stats.packet_count));

    for (i, stream) in sorted_streams.iter().take(10).enumerate() {
        println!("{}. 数据包数: {}, 流: {}", i + 1, stream.stats.packet_count, stream.flow_key);
    }

    Ok(())
}