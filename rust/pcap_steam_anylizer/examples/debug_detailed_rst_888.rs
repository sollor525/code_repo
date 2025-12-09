//! 详细调试PCAP文件中的RST-888检测

use pcap_steam_anylizer::{
    pcap::reader::PcapReader,
    pcap::parser::PacketParser,
    stream::{StreamManager, StreamManagerConfig},
};
use std::time::Duration;

fn main() {
    let pcap_file = "./pcap_file/ack_rest.pcap";

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
    let pcap_reader = PcapReader::open(pcap_file).unwrap();
    let linktype = pcap_reader.global_header().linktype;
    let parser = PacketParser::new(false, false, linktype);

    println!("详细调试RST-888检测过程:\n");

    // 处理数据包
    for (packet_count, packet_result) in pcap_reader.into_iter().enumerate() {
        let packet = packet_result.unwrap();

        // 解析数据包
        let parsed_packet = parser.parse(packet).unwrap();
        let packet_info: pcap_steam_anylizer::types::PacketInfo = parsed_packet.into();

        println!("数据包 {}:", packet_count + 1);
        println!("  协议: TCP ({})", packet_info.protocol);
        println!("  源: {}:{}", packet_info.src_ip, packet_info.src_port);
        println!("  目标: {}:{}", packet_info.dst_ip, packet_info.dst_port);

        if let Some(flags) = packet_info.tcp_flags {
            let flag_names = if flags & 0x02 != 0 { "SYN" } else { "" };
            let flag_names = format!("{}{}",
                flag_names,
                if flags & 0x10 != 0 && flag_names.is_empty() { "ACK" }
                else if flags & 0x10 != 0 { "+ACK" }
                else { "" });
            let flag_names = format!("{}{}",
                flag_names,
                if flags & 0x04 != 0 { "+RST" } else { "" });
            let flag_names = format!("{}{}",
                flag_names,
                if flags & 0x01 != 0 { "+FIN" } else { "" });
            println!("  标志: {} ({:#04x})", flag_names.trim_start_matches('+'), flags);
        }

        if let Some(window) = packet_info.tcp_window {
            println!("  窗口: {}", window);
        }

        // 获取处理前的状态
        let stream = manager.find_stream_by_tuple(
            packet_info.src_ip,
            packet_info.dst_ip,
            packet_info.src_port,
            packet_info.dst_port,
            packet_info.protocol
        );

        if let Some(s) = stream {
            println!("  处理前状态:");
            println!("    握手完成: {}", s.connection.handshake.is_complete());
            println!("    packets_since_handshake_ack: {}", s.packets_since_handshake_ack);
            println!("    has_rst_888_after_handshake_ack: {}", s.has_rst_888_after_handshake_ack);
        }

        // 更新流管理器
        manager.process_packet(&packet_info);

        // 获取处理后的状态
        let stream = manager.find_stream_by_tuple(
            packet_info.src_ip,
            packet_info.dst_ip,
            packet_info.src_port,
            packet_info.dst_port,
            packet_info.protocol
        );

        if let Some(s) = stream {
            println!("  处理后状态:");
            println!("    握手完成: {}", s.connection.handshake.is_complete());
            println!("    packets_since_handshake_ack: {}", s.packets_since_handshake_ack);
            println!("    has_rst_888_after_handshake_ack: {}", s.has_rst_888_after_handshake_ack);
        }

        println!();
    }

    // 最终结果
    println!("=== 最终检测结果 ===");
    for stream in manager.get_all_streams() {
        if stream.flow_key.protocol() == 6 {
            println!("流: {}", stream.flow_key);
            println!("  握手完成: {}", stream.connection.handshake.is_complete());
            println!("  三次握手ACK后数据包数: {}", stream.packets_since_handshake_ack);
            println!("  检测到三次握手ACK后RST-888: {}", stream.has_rst_888_after_handshake_ack);
        }
    }
}