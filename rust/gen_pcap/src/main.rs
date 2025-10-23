use clap::{Arg, Command};
use pcap::{Capture, Packet, PacketHeader};
use libc::timeval;
use std::net::Ipv4Addr;
use gen_pcap::{
    TcpSessionConfig, IpRange, PortRange, ApplicationFlowType, NetworkConnection, TcpSession,
    core::{HttpFlow, ApplicationFlow}
};

fn main() {
    let matches = Command::new("gen_pcap")
        .version("1.0")
        .about("生成TCP和HTTP流量的PCAP文件")
        .arg(
            Arg::new("sessions")
                .short('n')
                .long("sessions")
                .value_name("COUNT")
                .help("TCP会话数量")
                .default_value("1")
        )
        .arg(
            Arg::new("src-ip")
                .short('s')
                .long("src-ip")
                .value_name("IP_RANGE")
                .help("源IP地址范围 (例如: 10.0.0.1, 10.0.0.1-10.0.0.100, 或 random)")
                .default_value("10.10.1.100")
        )
        .arg(
            Arg::new("dst-ip")
                .short('d')
                .long("dst-ip")
                .value_name("IP_RANGE")
                .help("目标IP地址范围 (例如: 192.168.1.100, 192.168.1.100-192.168.1.200, 或 random)")
                .default_value("192.168.1.100")
        )
        .arg(
            Arg::new("src-port")
                .long("src-port")
                .value_name("PORT_RANGE")
                .help("源端口范围 (例如: 30000, 30000-40000, 或 random)")
                .default_value("30000-40000")
        )
        .arg(
            Arg::new("dst-port")
                .short('p')
                .long("dst-port")
                .value_name("PORT_RANGE")
                .help("目标端口范围 (例如: 80, 80-443, 或 random)")
                .default_value("80")
        )
        .arg(
            Arg::new("http")
                .long("http")
                .help("包含HTTP流量")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("http-host")
                .long("http-host")
                .value_name("HOST")
                .help("HTTP请求的Host头")
                .default_value("example.com")
        )
        .arg(
            Arg::new("http-uris")
                .long("http-uris")
                .value_name("URIS")
                .help("HTTP请求的URI列表，用逗号分隔")
                .value_delimiter(',')
                .default_value("/")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("输出PCAP文件名")
                .default_value("output.pcap")
        )
        .arg(
            Arg::new("legacy")
                .long("legacy")
                .help("使用传统模式生成示例流量")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    // 如果使用传统模式
    if matches.get_flag("legacy") {
        run_legacy_mode();
        return;
    }

    // 新模式：使用配置参数
    run_new_mode(&matches);
}

fn run_new_mode(matches: &clap::ArgMatches) {
    println!("[*] 使用新的配置模式生成PCAP文件");

    // 解析参数
    let session_count: u32 = matches.get_one::<String>("sessions").unwrap().parse()
        .expect("无效的会话数量");

    let src_ip_range = IpRange::from_string(matches.get_one::<String>("src-ip").unwrap())
        .expect("无效的源IP范围");
    let dst_ip_range = IpRange::from_string(matches.get_one::<String>("dst-ip").unwrap())
        .expect("无效的目标IP范围");
    let src_port_range = PortRange::from_string(matches.get_one::<String>("src-port").unwrap())
        .expect("无效的源端口范围");
    let dst_port_range = PortRange::from_string(matches.get_one::<String>("dst-port").unwrap())
        .expect("无效的目标端口范围");

    let include_http = matches.get_flag("http");
    let http_host = matches.get_one::<String>("http-host").unwrap().clone();
    let http_uris: Vec<String> = matches.get_many::<String>("http-uris")
        .unwrap_or_default().cloned()
        .collect();

    let output_file = matches.get_one::<String>("output").unwrap();

    // 创建配置
    let mut config = TcpSessionConfig::new()
        .with_session_count(session_count)
        .with_src_ip_range(src_ip_range.clone())
        .with_dst_ip_range(dst_ip_range.clone())
        .with_src_port_range(src_port_range.clone())
        .with_dst_port_range(dst_port_range.clone());

    if include_http {
        config = config.with_http(http_uris.clone(), http_host.clone());
    }

    // 显示配置信息
    println!("[*] 配置信息:");
    println!("    会话数量: {}", session_count);
    println!("    源IP范围: {} - {} ({}个地址)",
        src_ip_range.start, src_ip_range.end, if src_ip_range.count() > 1000000 { "很多" } else { &src_ip_range.count().to_string() });
    println!("    目标IP范围: {} - {} ({}个地址)",
        dst_ip_range.start, dst_ip_range.end, if dst_ip_range.count() > 1000000 { "很多" } else { &dst_ip_range.count().to_string() });
    println!("    源端口范围: {} - {} ({}个端口)",
        src_port_range.start, src_port_range.end, src_port_range.count());
    println!("    目标端口范围: {} - {} ({}个端口)",
        dst_port_range.start, dst_port_range.end, dst_port_range.count());
    println!("    应用流量: {}", config.application_flow.name());
    if include_http {
        println!("    HTTP Host: {}", http_host);
        println!("    HTTP URIs: {:?}", http_uris);
    }
    println!("    输出文件: {}", output_file);

    // 生成会话
    let sessions = config.generate_sessions();
    println!("[*] 生成了 {} 个TCP会话", sessions.len());

    // 创建PCAP文件
    let cap = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut savefile = cap.savefile(output_file).unwrap();
    let mut packet_count = 0;

    // 生成并写入数据包
    for (i, session) in sessions.iter().enumerate() {
        let packets = session.generate_packets(&config.application_flow);

        println!("[*] 会话 {}: {}个数据包 ({} -> {}:{})",
            i + 1, packets.len(),
            session.connection.src_ip, session.connection.dst_ip, session.connection.dst_port);

        for packet_data in packets {
            let header = PacketHeader {
                ts: timeval { tv_sec: i as i64, tv_usec: 0 },
                caplen: packet_data.len() as u32,
                len: packet_data.len() as u32,
            };
            let packet = Packet::new(&header, &packet_data);
            savefile.write(&packet);
            packet_count += 1;
        }
    }

    println!("[+] 完成! 总共写入 {} 个数据包到 {}", packet_count, output_file);
}

fn run_legacy_mode() {
    println!("[*] 使用传统模式生成示例PCAP文件");

    const PCAP_FILE: &str = "multi_tcp_handshake.pcap";
    const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const DST_MAC: [u8; 6] = [0xe2, 0xc9, 0xfc, 0xf5, 0x9e, 0x3c];
    const SRC_IP: Ipv4Addr = Ipv4Addr::new(10, 10, 1, 100);
    const DST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const SRC_PORT: u16 = 23333;

    // 以"死"设备方式创建 pcap 文件
    let cap = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut savefile = cap.savefile(PCAP_FILE).unwrap();

    // 生成TCP三次握手流量（端口 22, 21, 25, 3306, 5672, 9200）
    const DST_PORTS: [u16; 6] = [22, 21, 25, 3306, 5672, 9200];

    for (idx, &dst_port) in DST_PORTS.iter().enumerate() {
        let connection = NetworkConnection::new(
            SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, dst_port
        );
        let session = TcpSession::new(connection, 1000000 + idx as u32);
        let flow = ApplicationFlowType::TcpOnly;

        let packets = session.generate_packets(&flow);

        // 写入所有握手包
        for (packet_idx, packet_data) in packets.iter().enumerate() {
            let header = PacketHeader {
                ts: timeval { tv_sec: idx as i64, tv_usec: packet_idx as i64 },
                caplen: packet_data.len() as u32,
                len: packet_data.len() as u32,
            };
            let packet = Packet::new(&header, packet_data);
            savefile.write(&packet);
        }

        println!("[+] 端口 {} 三次握手完成", dst_port);
    }

    // 生成HTTP流量（GET和POST）
    let http_flow = ApplicationFlowType::Http(
        HttpFlow::new(
            vec!["/".to_string(), "/api/users".to_string()],
            "example.com".to_string()
        )
    );

    let http_connection = NetworkConnection::new(
        SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT, 8080
    );
    let http_session = TcpSession::new(http_connection, 1008080);
    let http_packets = http_session.generate_packets(&http_flow);

    // 写入所有HTTP包
    for (packet_idx, packet_data) in http_packets.iter().enumerate() {
        let header = PacketHeader {
            ts: timeval { tv_sec: 1, tv_usec: packet_idx as i64 },
            caplen: packet_data.len() as u32,
            len: packet_data.len() as u32,
        };
        let packet = Packet::new(&header, packet_data);
        savefile.write(&packet);
    }

    println!("[+] HTTP 完整流程完成（包含三次握手、请求/响应）");

    // 模拟四种视频协议的流量
    const VIDEO_URIS: [&str; 4] = [
        "/onvif/device_service",
        "/RPC2_Login",
        "/web_caps/webCapsConfig",
        "/System/deviceInfo",
    ];

    let video_flow = ApplicationFlowType::Http(
        HttpFlow::new(
            VIDEO_URIS.iter().map(|s| s.to_string()).collect(),
            "192.168.1.100".to_string()
        )
    );

    for (idx, _uri) in VIDEO_URIS.iter().enumerate() {
        let connection = NetworkConnection::new(
            SRC_MAC, DST_MAC, SRC_IP, DST_IP, SRC_PORT + idx as u16 + 1, 8080
        );
        let session = TcpSession::new(connection, 1008080);

        let packets = session.generate_packets(&video_flow);

        // 写入所有HTTP包
        for (packet_idx, packet_data) in packets.iter().enumerate() {
            let header = PacketHeader {
                ts: timeval { tv_sec: 2 + idx as i64, tv_usec: packet_idx as i64 },
                caplen: packet_data.len() as u32,
                len: packet_data.len() as u32,
            };
            let packet = Packet::new(&header, packet_data);
            savefile.write(&packet);
        }
    }

    println!("[+] HTTP 四种视频协议流的流程完成（包含三次握手、请求/响应）");
    println!("全部完成，已写入 {}", PCAP_FILE);
}

