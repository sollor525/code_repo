use clap::{Arg, Command};
use pcap::{Capture, Packet, PacketHeader};
use libc::timeval;
use std::net::Ipv4Addr;
use gen_pcap::{
    TcpSessionConfig, IpRange, PortRange, ApplicationFlowType, NetworkConnection, TcpSession,
    TemplateEngine, TemplateConfig, LicenseManager, VlanConfig, VlanTag, build_vlan_ethernet_header,
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
            Arg::new("vlan")
                .long("vlan")
                .value_name("VLAN_ID")
                .help("VLAN ID (1-4094)")
        )
        .arg(
            Arg::new("vlan-priority")
                .long("vlan-priority")
                .value_name("PRIORITY")
                .help("VLAN优先级 (0-7)")
                .default_value("0")
        )
        .arg(
            Arg::new("vlan-dei")
                .long("vlan-dei")
                .help("设置VLAN DEI位 (Drop Eligible Indicator)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("qinq")
                .long("qinq")
                .help("使用双层VLAN (QinQ)")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("outer-vlan")
                .long("outer-vlan")
                .value_name("OUTER_VLAN_ID")
                .help("外层VLAN ID (用于QinQ)")
        )
        .arg(
            Arg::new("inner-vlan")
                .long("inner-vlan")
                .value_name("INNER_VLAN_ID")
                .help("内层VLAN ID (用于QinQ)")
        )
        .arg(
            Arg::new("outer-priority")
                .long("outer-priority")
                .value_name("OUTER_PRIORITY")
                .help("外层VLAN优先级 (0-7)")
                .default_value("0")
        )
        .arg(
            Arg::new("inner-priority")
                .long("inner-priority")
                .value_name("INNER_PRIORITY")
                .help("内层VLAN优先级 (0-7)")
                .default_value("0")
        )
        .arg(
            Arg::new("template")
                .short('t')
                .long("template")
                .value_name("FILE")
                .help("YAML模板文件路径")
        )
        .arg(
            Arg::new("legacy")
                .long("legacy")
                .help("使用传统模式生成示例流量")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("license-status")
                .long("license-status")
                .help("显示许可证状态")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("bypass-license")
                .long("bypass-license")
                .help("绕过许可证检查 (仅用于测试)")
                .action(clap::ArgAction::SetTrue)
                .hide(true) // 隐藏这个选项，不显示在帮助中
        )
        .get_matches();

    // 检查许可证状态（除非绕过）
    if !matches.get_flag("bypass-license") {
        check_license_and_exit_if_needed();
    }

    // 如果检查许可证状态
    if matches.get_flag("license-status") {
        show_license_status();
        return;
    }

    // 如果使用模板模式
    if let Some(template_file) = matches.get_one::<String>("template") {
        run_template_mode(template_file, matches.get_one::<String>("output").unwrap());
        return;
    }

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

    // 解析VLAN配置
    let vlan_config = parse_vlan_config(matches);

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

    // 显示VLAN配置信息
    if let Some(ref vlan_cfg) = vlan_config {
        println!("[*] VLAN配置:");
        if vlan_cfg.is_qinq {
            println!("    类型: 双层VLAN (QinQ)");
            if let Some(ref outer_tag) = vlan_cfg.outer_tag {
                println!("    外层VLAN: ID={}, 优先级={}", outer_tag.vlan_id, outer_tag.priority);
            }
            if let Some(ref inner_tag) = vlan_cfg.inner_tag {
                println!("    内层VLAN: ID={}, 优先级={}, DEI={}",
                    inner_tag.vlan_id, inner_tag.priority, inner_tag.dei);
            }
        } else {
            println!("    类型: 单层VLAN");
            if let Some(ref outer_tag) = vlan_cfg.outer_tag {
                println!("    VLAN ID: {}, 优先级={}, DEI={}",
                    outer_tag.vlan_id, outer_tag.priority, outer_tag.dei);
            }
        }
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

        // 应用VLAN标签
        let vlan_packets = apply_vlan_to_packets(packets, session, &vlan_config);

        println!("[*] 会话 {}: {}个数据包 ({} -> {}:{})",
            i + 1, vlan_packets.len(),
            session.connection.src_ip, session.connection.dst_ip, session.connection.dst_port);

        for packet_data in vlan_packets {
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

    // 记录PCAP生成
    record_pcap_generation(output_file).unwrap_or_else(|e| {
        eprintln!("[!] 警告: 无法记录PCAP生成: {}", e);
    });
}

fn run_template_mode(template_file: &str, output_file: &str) {
    println!("[*] 使用YAML模板模式生成PCAP文件");
    println!("[*] 模板文件: {}", template_file);
    println!("[*] 输出文件: {}", output_file);

    // 解析YAML模板
    let template_config = match TemplateConfig::from_yaml_file(template_file) {
        Ok(config) => {
            println!("[+] 模板解析成功");
            config
        }
        Err(e) => {
            eprintln!("[!] 模板解析失败: {}", e);
            std::process::exit(1);
        }
    };

    // 显示模板信息
    println!("[*] 模板信息:");
    println!("    名称: {}", template_config.template.metadata.name);
    println!("    描述: {}", template_config.template.metadata.description.as_deref().unwrap_or("无"));
    println!("    版本: {}", template_config.template.metadata.version.as_deref().unwrap_or("1.0"));
    println!("    会话数量: {}", template_config.template.sessions.len());

    // 创建模板引擎
    let engine = TemplateEngine::new(template_config);

    // 生成数据包
    match engine.generate_packets() {
        Ok(packets) => {
            println!("[+] 数据包生成成功，共 {} 个数据包", packets.len());

            // 创建PCAP文件
            let cap = Capture::dead(pcap::Linktype::ETHERNET).unwrap();
            let mut savefile = cap.savefile(output_file).unwrap();

            // 写入数据包
            for (i, packet_data) in packets.iter().enumerate() {
                let header = PacketHeader {
                    ts: timeval { tv_sec: i as i64, tv_usec: 0 },
                    caplen: packet_data.len() as u32,
                    len: packet_data.len() as u32,
                };
                let packet = Packet::new(&header, &packet_data);
                savefile.write(&packet);
            }

            println!("[+] 完成! 总共写入 {} 个数据包到 {}", packets.len(), output_file);

            // 记录PCAP生成
            record_pcap_generation(output_file).unwrap_or_else(|e| {
                eprintln!("[!] 警告: 无法记录PCAP生成: {}", e);
            });
        }
        Err(e) => {
            eprintln!("[!] 数据包生成失败: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_legacy_mode() {
    println!("[*] 使用传统模式生成示例PCAP文件");

    // 获取命令行参数
    let args: Vec<String> = std::env::args().collect();
    let mut vlan_config = None;

    // 简单解析VLAN参数 (从命令行直接获取)
    for (i, arg) in args.iter().enumerate() {
        match arg.as_str() {
            "--vlan" => {
                if i + 1 < args.len() {
                    if let Ok(vlan_id) = args[i + 1].parse::<u16>() {
                        vlan_config = Some(VlanConfig::single_layer(vlan_id, 0, false));
                        println!("[*] 检测到VLAN参数: {}", vlan_id);
                    }
                }
            }
            "--vlan-priority" => {
                if i + 1 < args.len() {
                    if let Some(priority) = args[i + 1].parse::<u8>().ok() {
                        if let Some(ref mut vlan_cfg) = vlan_config {
                            if let Some(ref mut tag) = vlan_cfg.outer_tag {
                                tag.priority = priority;
                            }
                            println!("[*] VLAN优先级: {}", priority);
                        }
                    }
                }
            }
            "--vlan-dei" => {
                if let Some(ref mut vlan_cfg) = vlan_config {
                    if let Some(ref mut tag) = vlan_cfg.outer_tag {
                        tag.dei = true;
                    }
                    println!("[*] 启用VLAN DEI位");
                }
            }
            "--qinq" => {
                if i + 1 < args.len() {
                    if let Ok(outer_vlan) = args[i + 1].parse::<u16>() {
                        if i + 2 < args.len() {
                            if let Ok(inner_vlan) = args[i + 2].parse::<u16>() {
                                vlan_config = Some(VlanConfig::double_layer(outer_vlan, inner_vlan, 0, 0));
                                println!("[*] 检测到QinQ参数: 外层{}, 内层{}", outer_vlan, inner_vlan);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

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

        // 应用VLAN标签
        let vlan_packets = apply_vlan_to_packets(packets, &session, &vlan_config);

        // 写入所有握手包
        for (packet_idx, packet_data) in vlan_packets.iter().enumerate() {
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

    // 为HTTP流量应用VLAN标签
    let vlan_http_packets = apply_vlan_to_packets(http_packets, &http_session, &vlan_config);

    // 写入所有HTTP包
    for (packet_idx, packet_data) in vlan_http_packets.iter().enumerate() {
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

        // 为视频协议流量应用VLAN标签
        let vlan_packets = apply_vlan_to_packets(packets, &session, &vlan_config);

        // 写入所有HTTP包
        for (packet_idx, packet_data) in vlan_packets.iter().enumerate() {
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

    // 记录PCAP生成
    record_pcap_generation(PCAP_FILE).unwrap_or_else(|e| {
        eprintln!("[!] 警告: 无法记录PCAP生成: {}", e);
    });
}

/// 检查许可证状态并在需要时退出
fn check_license_and_exit_if_needed() {
    let license_manager = LicenseManager::new();

    // 检查程序是否允许使用
    match license_manager.check_usage_allowed() {
        Ok(is_allowed) => {
            if !is_allowed {
                let (_, unique, _) = license_manager.get_usage_stats().unwrap_or((0, 0, false));
                let is_expired = license_manager.check_is_expired().unwrap_or(false);

                if is_expired {
                    eprintln!("[!] 程序已过期！");
                    eprintln!("[*] 过期时间: 2026年5月31日");
                    eprintln!("[*] 请联系开发者获取更新版本。");
                } else {
                    eprintln!("[!] 程序使用次数已达到限制！");
                    eprintln!("[*] 当前唯一PCAP文件数: {}/{}", unique, license_manager.config.activation_threshold);
                    eprintln!("[*] 程序已达到最大使用次数，无法继续生成PCAP文件。");
                    eprintln!("[*] 如需继续使用，请联系开发者获取新的许可证。");
                }
                eprintln!("[*] 使用 --license-status 查看详细状态。");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("[!] 无法检查许可证状态: {}", e);
            std::process::exit(1);
        }
    }
}

/// 显示许可证状态
fn show_license_status() {
    let license_manager = LicenseManager::new();

    if let Err(e) = license_manager.show_license_status() {
        eprintln!("[!] 无法显示许可证状态: {}", e);
        std::process::exit(1);
    }

    // 显示使用提示
    println!("\n[*] 使用说明:");
    println!("    - 程序将在2026年5月31日后过期");
    println!("    - 可生成最多{}个不同的PCAP文件", license_manager.config.activation_threshold);
    println!("    - 达到使用限制后程序将禁用");
    println!("    - 每次生成新的PCAP文件都会增加计数");
}

/// 从命令行参数解析VLAN配置
fn parse_vlan_config(matches: &clap::ArgMatches) -> Option<VlanConfig> {
    // 检查是否有任何VLAN相关参数
    let has_vlan = matches.get_one::<String>("vlan").is_some()
        || matches.get_one::<String>("outer-vlan").is_some()
        || matches.get_one::<String>("inner-vlan").is_some()
        || matches.get_flag("vlan-dei")
        || matches.get_flag("qinq");

    if !has_vlan {
        return None;
    }

    let mut vlan_config = VlanConfig::new();

    if matches.get_flag("qinq") {
        // QinQ配置
        vlan_config.is_qinq = true;

        // 外层VLAN
        if let Some(outer_vlan_str) = matches.get_one::<String>("outer-vlan") {
            if let Ok(outer_vlan) = outer_vlan_str.parse::<u16>() {
                let outer_priority = matches.get_one::<String>("outer-priority")
                    .unwrap_or(&"0".to_string())
                    .parse::<u8>()
                    .unwrap_or(0);

                vlan_config.outer_tag = Some(VlanTag::new(
                    outer_vlan,
                    outer_priority,
                    false
                ));
            }
        }

        // 内层VLAN
        if let Some(inner_vlan_str) = matches.get_one::<String>("inner-vlan") {
            if let Ok(inner_vlan) = inner_vlan_str.parse::<u16>() {
                let inner_priority = matches.get_one::<String>("inner-priority")
                    .unwrap_or(&"0".to_string())
                    .parse::<u8>()
                    .unwrap_or(0);

                vlan_config.inner_tag = Some(VlanTag::new(
                    inner_vlan,
                    inner_priority,
                    false
                ));
            }
        }

        // 如果没有指定内层VLAN，使用普通VLAN参数作为内层
        if vlan_config.inner_tag.is_none() {
            if let Some(vlan_str) = matches.get_one::<String>("vlan") {
                if let Ok(vlan_id) = vlan_str.parse::<u16>() {
                    let priority = matches.get_one::<String>("vlan-priority")
                        .unwrap_or(&"0".to_string())
                        .parse::<u8>()
                        .unwrap_or(0);
                    let dei = matches.get_flag("vlan-dei");

                    vlan_config.inner_tag = Some(VlanTag::new(
                        vlan_id,
                        priority,
                        dei
                    ));
                }
            }
        }
    } else {
        // 单层VLAN配置
        if let Some(vlan_str) = matches.get_one::<String>("vlan") {
            if let Ok(vlan_id) = vlan_str.parse::<u16>() {
                let priority = matches.get_one::<String>("vlan-priority")
                    .unwrap_or(&"0".to_string())
                    .parse::<u8>()
                    .unwrap_or(0);
                let dei = matches.get_flag("vlan-dei");

                vlan_config.outer_tag = Some(VlanTag::new(
                    vlan_id,
                    priority,
                    dei
                ));
            }
        }
    }

    // 验证VLAN配置
    if let Some(ref outer_tag) = vlan_config.outer_tag {
        if outer_tag.vlan_id == 0 || outer_tag.vlan_id > 4094 {
            eprintln!("[!] 无效的外层VLAN ID: {}. 有效范围: 1-4094", outer_tag.vlan_id);
            std::process::exit(1);
        }
    }

    if let Some(ref inner_tag) = vlan_config.inner_tag {
        if inner_tag.vlan_id == 0 || inner_tag.vlan_id > 4094 {
            eprintln!("[!] 无效的内层VLAN ID: {}. 有效范围: 1-4094", inner_tag.vlan_id);
            std::process::exit(1);
        }
    }

    Some(vlan_config)
}

/// 为数据包添加VLAN标签
fn apply_vlan_to_packets(packets: Vec<Vec<u8>>, session: &TcpSession, vlan_config: &Option<VlanConfig>) -> Vec<Vec<u8>> {
    if let Some(vlan_cfg) = vlan_config {
        packets.into_iter().map(|packet| {
            if vlan_cfg.is_qinq || vlan_cfg.outer_tag.is_some() {
                // 构建新的VLAN以太网头
                let vlan_header = build_vlan_ethernet_header(
                    session.connection.src_mac,
                    session.connection.dst_mac,
                    &vlan_cfg,
                );

                // 替换原以太网头
                let mut new_packet = packet.clone();
                if packet.len() >= 14 {
                    new_packet.splice(0..14, vlan_header);
                }
                new_packet
            } else {
                packet
            }
        }).collect()
    } else {
        packets
    }
}

/// 记录PCAP生成
fn record_pcap_generation(output_file: &str) -> anyhow::Result<()> {
    let license_manager = LicenseManager::new();
    license_manager.record_pcap_generation(output_file)?;

    // 检查是否刚刚达到使用限制
    if let Ok(is_blocked) = license_manager.check_activation() {
        if is_blocked {
            let is_expired = license_manager.check_is_expired().unwrap_or(false);
            if is_expired {
                println!("\n[⚠️]  警告：程序已过期！");
                println!("[*] 这可能是最后一次成功生成PCAP文件。");
            } else {
                println!("\n[⚠️]  警告：程序使用次数已达到限制！");
                println!("[*] 这是最后一次成功生成PCAP文件。");
                println!("[*] 如需继续使用，请联系开发者获取新的许可证。");
            }
        }
    }

    Ok(())
}