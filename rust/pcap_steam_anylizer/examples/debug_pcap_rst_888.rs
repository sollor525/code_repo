//! 调试PCAP文件中的RST-888检测

use pcap_steam_anylizer::{
    pcap::reader::PcapReader,
    pcap::parser::PacketParser,
    stream::{StreamManager, StreamManagerConfig},
};
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("用法: {} <pcap文件>", args[0]);
        std::process::exit(1);
    }

    let pcap_file = &args[1];

    // 创建流管理器，启用RST-888检测
    let config = StreamManagerConfig {
        stream_timeout: Duration::from_secs(300),
        max_streams: 100000,
        enable_event_logging: true,
        max_events_per_stream: 1000,
        cleanup_interval: Duration::from_secs(60),
        syn_rst_888: true,
        handshake_ack_rst_888: true,
    };
    let mut manager = StreamManager::new(config);

    // 打开PCAP文件
    let mut pcap_reader = match PcapReader::open(pcap_file) {
        Ok(reader) => reader,
        Err(e) => {
            eprintln!("无法打开PCAP文件 {}: {}", pcap_file, e);
            std::process::exit(1);
        }
    };

    let linktype = pcap_reader.global_header().linktype;
    println!("分析文件: {}", pcap_file);
    println!("PCAP版本: {}.{}",
        pcap_reader.global_header().major_version,
        pcap_reader.global_header().minor_version);
    println!("链路层类型: {}", linktype);
    println!("捕获长度: {}\n", pcap_reader.global_header().snaplen);

    let parser = PacketParser::new(false, false, linktype);
    let mut packet_count = 0;

    // 处理数据包
    for packet_result in pcap_reader {
        match packet_result {
            Ok(packet) => {
                packet_count += 1;

                // 解析数据包
                let parsed_packet = match parser.parse(packet) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("解析数据包{}失败: {}", packet_count, e);
                        continue;
                    }
                };

                // 转换为PacketInfo
                let packet_info: pcap_steam_anylizer::types::PacketInfo = parsed_packet.into();

                // 更新流管理器
                manager.process_packet(&packet_info);

                // 输出调试信息
                if packet_count == 4 {
                    println!("\n调试信息（数据包4处理后）:");
                    for stream in manager.get_all_streams() {
                        if stream.flow_key.protocol() == 6 {
                            println!("  流: {}", stream.flow_key);
                            println!("  握手完成: {}", stream.connection.handshake.is_complete());
                            println!("  packets_since_handshake_ack: {}", stream.packets_since_handshake_ack);
                            println!("  has_rst_888_after_handshake_ack: {}", stream.has_rst_888_after_handshake_ack);
                        }
                    }
                    println!();
                }

                // 输出前几个包的详细信息
                if packet_count <= 10 {
                    let protocol_name = match packet_info.protocol {
                        6 => "TCP",
                        17 => "UDP",
                        1 => "ICMP",
                        _ => "Other",
                    };

                    println!("数据包 {}:", packet_count);
                    println!("  协议: {} ({})", protocol_name, packet_info.protocol);
                    println!("  源: {}:{}", packet_info.src_ip, packet_info.src_port);
                    println!("  目标: {}:{}", packet_info.dst_ip, packet_info.dst_port);
                    println!("  标志: {:?}", packet_info.tcp_flags);
                    if let Some(window) = packet_info.tcp_window {
                        println!("  窗口: {}", window);
                    }
                    println!();
                }
            }
            Err(e) => {
                eprintln!("读取数据包失败: {}", e);
            }
        }
    }

    println!("处理完成，共处理 {} 个数据包\n", packet_count);

    // 输出检测结果
    println!("=== RST-888检测结果 ===\n");

    println!("--- syn-rst-888 检测 ---");
    println!("检测SYN包后的RST-ACK报文（窗口大小为888）\n");

    let mut syn_rst_888_count = 0;
    for stream in manager.get_all_streams() {
        if stream.flow_key.protocol() == 6 && stream.stats.packet_count > 0 {
            println!("流: {}", stream.flow_key);
            println!("  数据包数: {}", stream.stats.packet_count);
            println!("  SYN后数据包数: {}", stream.packets_since_syn);
            println!("  检测到SYN后RST-888: {}", stream.has_rst_888_after_syn);
            println!("  立即SYN后RST-888: {}", stream.has_immediate_rst_888_after_syn);

            if stream.has_rst_888_after_syn {
                syn_rst_888_count += 1;
            }
            println!();
        }
    }
    println!("SYN后RST-888检测到的流数: {}\n", syn_rst_888_count);

    println!("--- handshake-ack-rst-888 检测 ---");
    println!("检测三次握手ACK后的RST报文（窗口大小为888，非RST-ACK）\n");

    let mut handshake_rst_888_count = 0;
    let mut handshake_complete_count = 0;
    for stream in manager.get_all_streams() {
        if stream.flow_key.protocol() == 6 && stream.stats.packet_count > 0 {
            println!("流: {}", stream.flow_key);
            println!("  数据包数: {}", stream.stats.packet_count);
            println!("  握手完成: {}", stream.connection.handshake.is_complete());
            if stream.connection.handshake.is_complete() {
                handshake_complete_count += 1;
            }
            println!("  三次握手ACK后数据包数: {}", stream.packets_since_handshake_ack);
            println!("  检测到三次握手ACK后RST-888: {}", stream.has_rst_888_after_handshake_ack);

            if stream.has_rst_888_after_handshake_ack {
                handshake_rst_888_count += 1;
            }
            println!();
        }
    }

    println!("统计摘要:");
    println!("  总TCP流数: {}", handshake_complete_count);
    println!("  三次握手完成且有RST-888报文的流数: {}", handshake_rst_888_count);
    println!("  三次握手完成且无RST-888报文的流数: {}", handshake_complete_count - handshake_rst_888_count);
}