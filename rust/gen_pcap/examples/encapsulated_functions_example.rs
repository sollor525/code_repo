use gen_pcap::{
    build_tcp_handshake_packets, 
    build_http_get_flow_packets, 
    build_http_post_flow_packets, 
    build_http_get_post_flow_packets
};
use pcap::{Capture, Packet, PacketHeader};
use libc::timeval;
use std::net::Ipv4Addr;

fn main() {
    // 网络配置
    const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const DST_MAC: [u8; 6] = [0xe2, 0xc9, 0xfc, 0xf5, 0x9e, 0x3c];
    const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 10, 1, 100);
    const DST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const SRC_PORT: u16 = 12345;
    const DST_PORT: u16 = 8080;

    println!("=== 封装函数使用示例 ===\n");

    // 示例1: 仅TCP三次握手
    println!("1. TCP三次握手:");
    let (handshake_packets, conn) = build_tcp_handshake_packets(
        SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, 1000000
    );
    println!("   生成了 {} 个握手包", handshake_packets.len());
    println!("   连接状态: {:?}", conn);

    // 示例2: HTTP GET流程
    println!("\n2. HTTP GET完整流程:");
    let get_packets = build_http_get_flow_packets(
        SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, DST_PORT, 1001000,
        "/api/users", "api.example.com",
        b"{\"users\": [{\"id\": 1, \"name\": \"Alice\"}]}"
    );
    println!("   生成了 {} 个包（包含三次握手、GET请求、GET响应）", get_packets.len());

    // 示例3: HTTP POST流程
    println!("\n3. HTTP POST完整流程:");
    let post_packets = build_http_post_flow_packets(
        SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT + 1, DST_PORT, 1002000,
        "/api/users", "api.example.com", "application/json",
        b"{\"name\": \"Bob\", \"email\": \"bob@example.com\"}",
        b"{\"id\": 2, \"message\": \"User created successfully\"}"
    );
    println!("   生成了 {} 个包（包含三次握手、POST请求、POST响应）", post_packets.len());

    // 示例4: 完整的HTTP流程（GET + POST）
    println!("\n4. 完整HTTP流程（GET + POST）:");
    let complete_packets = build_http_get_post_flow_packets(
        SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT + 2, DST_PORT, 1003000,
        "/api/users",           // GET URI
        "/api/users",           // POST URI
        "api.example.com",      // Host
        b"{\"name\": \"Charlie\", \"email\": \"charlie@example.com\"}", // POST数据
        b"{\"users\": [{\"id\": 1, \"name\": \"Alice\"}, {\"id\": 2, \"name\": \"Bob\"}]}", // GET响应
        b"{\"id\": 3, \"message\": \"User created successfully\"}", // POST响应
    );
    println!("   生成了 {} 个包（包含三次握手、GET请求/响应、POST请求/响应）", complete_packets.len());

    // 示例5: 生成PCAP文件
    println!("\n5. 生成PCAP文件:");
    let cap = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut savefile = cap.savefile("encapsulated_example.pcap").unwrap();

    // 写入所有包
    for (i, packet_data) in complete_packets.iter().enumerate() {
        let header = PacketHeader {
            ts: timeval { tv_sec: 0, tv_usec: (i * 1000) as i64 },
            caplen: packet_data.len() as u32,
            len: packet_data.len() as u32,
        };
        let packet = Packet::new(&header, packet_data);
        savefile.write(&packet);
    }

    println!("   已写入 encapsulated_example.pcap");
    println!("   文件大小: {} 字节", complete_packets.iter().map(|p| p.len()).sum::<usize>());

    // 示例6: 显示包信息
    println!("\n6. 包信息详情:");
    for (i, packet_data) in complete_packets.iter().enumerate() {
        let packet_type = match i {
            0 => "SYN",
            1 => "SYN/ACK", 
            2 => "ACK",
            3 => "HTTP GET",
            4 => "HTTP GET Response",
            5 => "HTTP POST",
            6 => "HTTP POST Response",
            _ => "Unknown"
        };
        println!("   包 {}: {} ({} 字节)", i + 1, packet_type, packet_data.len());
    }

    println!("\n=== 示例完成 ===");
    println!("\n优势说明:");
    println!("- 自动处理TCP序列号和确认号");
    println!("- 简化了复杂的网络包构造");
    println!("- 提供了不同层次的封装（握手、GET、POST、完整流程）");
    println!("- 减少了手动计算序列号的错误");
}
