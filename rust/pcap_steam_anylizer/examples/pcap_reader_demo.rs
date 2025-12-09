//! PCAP文件读取和解析示例
//!
//! 此示例展示如何使用PcapReader和PacketParser读取并解析PCAP文件

use pcap_steam_anylizer::pcap::{PcapReader, PacketParser};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 获取命令行参数
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("用法: {} <pcap文件>", args[0]);
        std::process::exit(1);
    }

    let pcap_path = &args[1];

    // 创建PCAP读取器
    println!("正在打开PCAP文件: {}", pcap_path);
    let mut reader = PcapReader::open(pcap_path)?;

    // 显示全局头部信息
    let header = reader.global_header();
    println!("PCAP文件信息:");
    println!("  版本: {}.{}", header.major_version, header.minor_version);
    println!("  时区修正: {}", header.thiszone);
    println!("  最大捕获长度: {} 字节", header.snaplen);
    println!("  链路层类型: {}", header.linktype);

    // 创建数据包解析器
    let parser = PacketParser::new(false, true); // 不验证校验和，解析负载

    // 读取并解析数据包
    let mut packet_count = 0;
    for result in reader {
        match result {
            Ok(packet) => {
                // 解析数据包
                match parser.parse(packet) {
                    Ok(parsed_packet) => {
                        packet_count += 1;
                        println!("\n数据包 #{}", packet_count);
                        print_packet_info(&parsed_packet);

                        // 只显示前10个数据包的详细信息
                        if packet_count >= 10 {
                            println!("...（已显示前10个数据包）");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("解析数据包失败: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("读取数据包失败: {}", e);
                break;
            }
        }
    }

    println!("\n总共读取了 {} 个数据包", packet_count);
    Ok(())
}

/// 打印数据包信息
fn print_packet_info(packet: &pcap_steam_anylizer::types::packet::Packet) {
    println!("  时间戳: {:?}", packet.header.system_time());
    println!("  长度: {} 字节", packet.header.len);

    // MAC地址
    if let (Some(src_mac), Some(dst_mac)) = (packet.src_mac, packet.dst_mac) {
        println!("  MAC: {} -> {}",
                 mac_to_string(&src_mac),
                 mac_to_string(&dst_mac));
    }

    // IP地址和端口
    if let (Some(src_ip), Some(dst_ip)) = (packet.src_ip, packet.dst_ip) {
        if let (Some(src_port), Some(dst_port)) = (packet.src_port, packet.dst_port) {
            println!("  地址: {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
        } else {
            println!("  地址: {} -> {}", src_ip, dst_ip);
        }
    }

    // 协议信息
    if !packet.protocols.is_empty() {
        let protocols: Vec<String> = packet.protocols
            .iter()
            .map(|p| format!("{:?}", p))
            .collect();
        println!("  协议: {}", protocols.join(" -> "));
    }

    // TCP特定信息
    if let Some(tcp_flags) = packet.tcp_flags {
        let flags = [
            tcp_flags.fin.then_some("FIN"),
            tcp_flags.syn.then_some("SYN"),
            tcp_flags.rst.then_some("RST"),
            tcp_flags.psh.then_some("PSH"),
            tcp_flags.ack.then_some("ACK"),
            tcp_flags.urg.then_some("URG"),
            tcp_flags.ece.then_some("ECE"),
            tcp_flags.cwr.then_some("CWR"),
        ]
        .iter()
        .filter_map(|&f| f)
        .collect::<Vec<_>>()
        .join("|");

        if !flags.is_empty() {
            println!("  TCP标志: {}", flags);
        }
    }

    // 负载信息
    if let Some(payload) = packet.payload() {
        if !payload.is_empty() {
            println!("  负载长度: {} 字节", payload.len());

            // 尝试显示文本内容
            if let Ok(text) = std::str::from_utf8(payload) {
                if text.chars().take(100).all(|c| c.is_ascii()) {
                    let preview = text.chars().take(100).collect::<String>();
                    println!("  负载预览: {}", preview);
                }
            }
        }
    }
}

/// MAC地址转换为字符串
fn mac_to_string(mac: &[u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}