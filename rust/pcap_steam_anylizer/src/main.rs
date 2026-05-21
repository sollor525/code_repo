// PCAP流分析器主程序
//
// 此程序用于分析PCAP文件中的TCP流，提供多种输出格式和过滤选项

use clap::Parser;
use std::fs::File;
use std::io::{self, Write};
use std::process;
use std::time::Instant;

use pcap_steam_anylizer::{
    pcap::{PcapReader, PcapError, PacketParser, create_pcap_writer},
    stream::StreamManagerConfig,
    output::{FlowFormatter, OutputFormat, SortField, SortOrder, FlowFilter},
    types::{PacketInfo, flow::FlowKey, stream::{BlockingMode, TcpStream}, packet::describe_tcp_flags},
    rayon_parallel::{RayonProcessor, RayonConfig},
};

/// PCAP流分析器
///
/// 一个高性能的PCAP文件分析工具，用于提取和分析TCP流信息
#[derive(Parser, Debug)]
#[command(
    author = "PCAP Stream Analyzer",
    version = "0.1.0",
    about = "分析PCAP文件中的TCP流",
    long_about = "
PCAP流分析器是一个专业的网络流量分析工具，能够：

- 解析PCAP文件中的TCP数据包
- 重建TCP流并提取流信息
- 支持多种输出格式（表格、JSON、CSV）
- 提供灵活的过滤和排序选项
- 显示详细的连接统计信息

示例用法：
  # 基本分析
  pcap_analyzer input.pcap

  # 输出为JSON格式
  pcap_analyzer input.pcap -f json -o output.json

  # 过滤特定端口
  pcap_analyzer input.pcap --dst-port 80

  # 按数据包数量排序
  pcap_analyzer input.pcap -s packet_count --desc

  # 只显示完整建立的连接
  pcap_analyzer input.pcap --complete -v

  # 验证 NPatch 阻断是否成功
  pcap_analyzer input.pcap --verify-ack-block
  pcap_analyzer input.pcap --one-way-blocking
"
)]
struct Args {
    /// 输入的PCAP文件路径
    #[arg(help = "要分析的PCAP文件路径")]
    input: String,

    /// 输出文件路径（可选，默认输出到标准输出）
    #[arg(
        short = 'o',
        long = "output",
        help = "输出文件路径（默认输出到标准输出）"
    )]
    output: Option<String>,

    /// 输出格式
    #[arg(
        short = 'f',
        long = "format",
        value_parser = ["table", "json", "csv"],
        default_value = "table",
        help = "输出格式 [table|json|csv]"
    )]
    format: String,

    /// 协议过滤
    #[arg(
        short = 'p',
        long = "protocol",
        value_parser = ["tcp", "udp", "icmp"],
        help = "协议过滤 [tcp|udp|icmp]"
    )]
    protocol: Option<String>,

    /// 源IP地址过滤
    #[arg(
        long = "src-ip",
        help = "源IP地址过滤（例如：192.168.1.1）"
    )]
    src_ip: Option<String>,

    /// 目的IP地址过滤
    #[arg(
        long = "dst-ip",
        help = "目的IP地址过滤（例如：10.0.0.1）"
    )]
    dst_ip: Option<String>,

    /// 源端口过滤
    #[arg(
        long = "src-port",
        help = "源端口过滤（例如：8080）"
    )]
    src_port: Option<u16>,

    /// 目的端口过滤
    #[arg(
        long = "dst-port",
        help = "目的端口过滤（例如：80）"
    )]
    dst_port: Option<u16>,

    /// 排序字段
    #[arg(
        short = 's',
        long = "sort",
        value_parser = [
            "flow_id", "src_ip", "src_port", "dst_ip", "dst_port",
            "protocol", "packet_count", "byte_count", "duration",
            "first_packet_time", "last_packet_time", "state"
        ],
        default_value = "flow_id",
        help = "排序字段"
    )]
    sort: String,

    /// 排序顺序
    #[arg(
        long = "desc",
        help = "降序排列（默认为升序）"
    )]
    descending: bool,

    /// 详细模式
    #[arg(
        short = 'v',
        long = "verbose",
        help = "显示详细信息"
    )]
    verbose: bool,

    /// 只显示完整流
    #[arg(
        long = "complete",
        help = "只显示完整建立的TCP连接"
    )]
    complete: bool,

    /// 禁用进度条
    #[arg(
        long = "no-progress",
        help = "禁用进度条显示"
    )]
    no_progress: bool,

    /// 最小数据包数量
    #[arg(
        long = "min-packets",
        help = "最小数据包数量过滤"
    )]
    min_packets: Option<u64>,

    /// 最大数据包数量
    #[arg(
        long = "max-packets",
        help = "最大数据包数量过滤"
    )]
    max_packets: Option<u64>,

    /// 最小字节数
    #[arg(
        long = "min-bytes",
        help = "最小字节数过滤"
    )]
    min_bytes: Option<u64>,

    /// 最大字节数
    #[arg(
        long = "max-bytes",
        help = "最大字节数过滤"
    )]
    max_bytes: Option<u64>,

    /// 验证单向阻断是否成功（通用）
    #[arg(
        long = "one-way-blocking",
        help = "验证单向阻断是否成功：服务器返回有效数据前，NPatch 是否已注入 RST 或 hijack 报文"
    )]
    one_way_blocking: bool,

    /// 验证 NPatch ACK 阻断是否成功
    #[arg(
        long = "verify-ack-block",
        help = "验证 NPatch ACK 阻断：三次握手完成后是否注入 RST(窗口888)"
    )]
    verify_ack_block: bool,

    /// 验证 NPatch SYN 阻断是否成功
    #[arg(
        long = "verify-syn-block",
        help = "验证 NPatch SYN 阻断：三次握手完成前是否注入 RST(窗口888)"
    )]
    verify_syn_block: bool,

    /// 验证 NPatch Hijack 劫持是否成功
    #[arg(
        long = "verify-hijack",
        help = "验证 NPatch Hijack 劫持：是否注入伪造响应 PSH/ACK(窗口888)"
    )]
    verify_hijack: bool,

    /// 验证 NPatch Web 扫描防护是否成功
    #[arg(
        long = "verify-web-scan",
        help = "验证 NPatch Web 扫描防护：web 流是否被注入 RST 或 hijack 报文"
    )]
    verify_web_scan: bool,
}

/// 应用程序错误类型
#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("PCAP错误: {0}")]
    Pcap(#[from] PcapError),

    #[error("IO错误: {0}")]
    Io(#[from] io::Error),

    #[error("无效的参数: {0}")]
    InvalidArgument(String),

    #[error("处理过程中发生错误: {0}")]
    Processing(String),
}

/// 把阻断验证相关开关解析为单一的 `BlockingMode`
///
/// 返回 `(mode, count)`：`count` 为被开启的开关数量，用于校验互斥。
fn resolve_verify_mode(args: &Args) -> (Option<BlockingMode>, usize) {
    let mut mode = None;
    let mut count = 0;
    if args.verify_ack_block {
        mode = Some(BlockingMode::Ack);
        count += 1;
    }
    if args.verify_syn_block {
        mode = Some(BlockingMode::Syn);
        count += 1;
    }
    if args.verify_hijack {
        mode = Some(BlockingMode::Hijack);
        count += 1;
    }
    if args.verify_web_scan {
        mode = Some(BlockingMode::WebScan);
        count += 1;
    }
    if args.one_way_blocking {
        mode = Some(BlockingMode::OneWay);
        count += 1;
    }
    (mode, count)
}

/// 应用程序主逻辑
struct App {
    args: Args,
}

impl App {
    /// 创建新的应用程序实例
    fn new(args: Args) -> Self {
        Self { args }
    }

    /// 运行应用程序：读取并解析 PCAP，按流并行分析，输出结果
    ///
    /// 始终采用「按流分组的多线程」处理：不同流并行、同一流内报文按时间有序，
    /// 从而保证流分析结果的正确性与确定性。
    fn run(&self) -> Result<(), AppError> {
        self.validate_input()?;

        let verify_mode = resolve_verify_mode(&self.args).0;

        // 构造流管理器配置
        let stream_config = StreamManagerConfig {
            verify_blocking: verify_mode,
            ..StreamManagerConfig::default()
        };
        let rayon_config = RayonConfig {
            stream_config,
            enable_progress: !self.args.no_progress,
            ..RayonConfig::default()
        };
        let processor = RayonProcessor::new(rayon_config);

        // 读取并解析所有数据包
        eprintln!("正在读取和解析 PCAP 文件...");
        let start_time = Instant::now();

        #[allow(unused_mut)]
        let mut pcap_reader = PcapReader::open(&self.args.input)?;
        let linktype = pcap_reader.global_header().linktype;
        let parser = PacketParser::new(false, false, linktype);

        let mut packets = Vec::new();
        let mut parse_errors = 0u64;
        for packet_result in pcap_reader {
            match packet_result {
                Ok(packet) => match parser.parse(packet) {
                    Ok(parsed) => packets.push(PacketInfo::from(parsed)),
                    Err(_) => parse_errors += 1,
                },
                Err(_) => parse_errors += 1,
            }
        }
        let read_time = start_time.elapsed();
        if parse_errors > 0 {
            eprintln!("读取阶段解析错误: {}", parse_errors);
        }
        eprintln!("读取完成: {} 个数据包，耗时 {:?}", packets.len(), read_time);

        // 始终按流分组并行处理：保证每条流内报文有序，分析结果正确
        eprintln!("开始按流并行分析...");
        let result = processor.process_packets_by_flow(packets);

        if self.args.verbose {
            eprintln!("\n=== 处理统计 ===");
            eprintln!("数据包总数: {}", result.packet_count);
            eprintln!("识别的流数: {}", result.stream_count);
            eprintln!("处理时间: {:?}", result.processing_time);
            eprintln!("总耗时: {:?}", start_time.elapsed());
        }

        // NPatch 阻断验证模式：输出验证报告后直接返回
        if let Some(mode) = verify_mode {
            self.output_blocking_verification_results(&result.streams, mode)?;
            return Ok(());
        }

        // 常规流分析输出
        let mut filtered_streams = result.streams;
        filtered_streams.retain(|s| s.stats.packet_count > 0);
        filtered_streams.sort_by(|a, b| b.stats.packet_count.cmp(&a.stats.packet_count));

        let output_format = match self.args.format.as_str() {
            "json" => OutputFormat::Json,
            "csv" => OutputFormat::Csv,
            _ => OutputFormat::Table,
        };
        let mut formatter = FlowFormatter::new(output_format);

        let sort_field = match self.args.sort.as_str() {
            "flow_id" => SortField::FlowId,
            "src_ip" => SortField::SrcIp,
            "src_port" => SortField::SrcPort,
            "dst_ip" => SortField::DstIp,
            "dst_port" => SortField::DstPort,
            "protocol" => SortField::Protocol,
            "packet_count" => SortField::PacketCount,
            "byte_count" => SortField::ByteCount,
            "duration" => SortField::Duration,
            "first_packet_time" => SortField::FirstPacketTime,
            "last_packet_time" => SortField::LastPacketTime,
            "state" => SortField::State,
            _ => return Err(AppError::Processing(format!("无效的排序字段: {}", self.args.sort))),
        };
        formatter = formatter.sort_by(sort_field);

        let sort_order = if self.args.descending {
            SortOrder::Descending
        } else {
            SortOrder::Ascending
        };
        formatter = formatter.sort_order(sort_order);

        // 构造并应用过滤器
        formatter = formatter.filter(self.build_filter()?);

        // 输出
        let formatted_output =
            formatter.format_streams(&filtered_streams.iter().collect::<Vec<_>>())?;
        match &self.args.output {
            Some(output_path) => std::fs::write(output_path, formatted_output)?,
            None => print!("{}", formatted_output),
        }

        Ok(())
    }

    /// 根据命令行的过滤相关参数构造流过滤器
    ///
    /// 该过滤器在常规分析输出与 NPatch 阻断验证两种模式下都会被应用，
    /// 因此过滤参数（如 --min-packets、--src-ip 等）可与 --one-way-blocking
    /// 等验证开关组合使用。
    fn build_filter(&self) -> Result<FlowFilter, AppError> {
        let mut filter = FlowFilter::new();
        if let Some(ref protocol) = self.args.protocol {
            filter = filter.protocol(protocol.parse().map_err(|e| {
                AppError::Processing(format!("无效的协议: {}", e))
            })?);
        }
        if let Some(ref src_ip) = self.args.src_ip {
            filter = filter.src_ip(src_ip.clone());
        }
        if let Some(ref dst_ip) = self.args.dst_ip {
            filter = filter.dst_ip(dst_ip.clone());
        }
        if let Some(src_port) = self.args.src_port {
            filter = filter.src_port(src_port);
        }
        if let Some(dst_port) = self.args.dst_port {
            filter = filter.dst_port(dst_port);
        }
        if let Some(min_packets) = self.args.min_packets {
            filter = filter.packet_range(min_packets, self.args.max_packets.unwrap_or(u64::MAX));
        } else if let Some(max_packets) = self.args.max_packets {
            filter = filter.packet_range(0, max_packets);
        }
        if let Some(min_bytes) = self.args.min_bytes {
            filter = filter.byte_range(min_bytes, self.args.max_bytes.unwrap_or(u64::MAX));
        } else if let Some(max_bytes) = self.args.max_bytes {
            filter = filter.byte_range(0, max_bytes);
        }
        if self.args.complete {
            filter = filter.complete_only(true);
        }
        Ok(filter)
    }

    /// 校验命令行参数（输入文件的存在性交由 PcapReader::open 报错）
    fn validate_input(&self) -> Result<(), AppError> {
        // 验证协议参数
        if let Some(ref protocol) = self.args.protocol {
            if !["tcp", "udp", "icmp"].contains(&protocol.as_str()) {
                return Err(AppError::InvalidArgument(
                    format!("无效的协议: {}", protocol)
                ));
            }
        }

        // 校验阻断验证开关互斥（一次只能验证一种模式）
        let (_, verify_count) = resolve_verify_mode(&self.args);
        if verify_count > 1 {
            return Err(AppError::InvalidArgument(
                "--one-way-blocking / --verify-ack-block / --verify-syn-block / \
                 --verify-hijack / --verify-web-scan 只能指定其中一个".to_string()
            ));
        }

        Ok(())
    }

    /// 输出 NPatch 阻断验证结果
    fn output_blocking_verification_results(
        &self,
        streams: &[TcpStream],
        mode: BlockingMode,
    ) -> Result<(), AppError> {
        eprintln!("\nNPatch 阻断验证 — 模式: {}", mode.name_cn());
        eprintln!("判定标准: {}\n", mode.description());

        // 命令行过滤参数（--min-packets、--src-ip 等）同样适用于验证模式
        let filter = self.build_filter()?;

        let mut total = 0;
        let mut blocked = 0;
        // 未阻断流的键集合，复用于后续 PCAP 导出
        let mut not_blocked_flows = std::collections::HashSet::new();

        // 创建输出写入器
        let mut writer: Box<dyn Write> = if let Some(ref output_path) = self.args.output {
            Box::new(File::create(output_path)?)
        } else {
            Box::new(io::stdout())
        };

        writeln!(writer, "# NPatch 阻断验证报告 — 模式: {}", mode.name_cn())?;
        writeln!(writer, "# 判定标准: {}", mode.description())?;
        writeln!(writer, "")?;

        for stream in streams {
            // 只统计属于本模式验证范围、且匹配命令行过滤条件的流
            if !stream.verification_in_scope(mode) || !filter.matches(stream) {
                continue;
            }
            total += 1;
            let v = &stream.verification;

            writeln!(writer, "流ID: {}", stream.flow_key)?;
            if v.blocked {
                blocked += 1;
                writeln!(writer, "  阻断结果: 已阻断 ✓")?;
            } else {
                not_blocked_flows.insert(stream.flow_key.clone());
                writeln!(writer, "  阻断结果: 未阻断 ✗")?;
            }
            writeln!(writer, "  判定原因: {}", v.reason)?;
            if let Some(conf) = v.confidence {
                writeln!(writer, "  可信度: {}", conf.name_cn())?;
            }
            if v.blocked {
                let flag_str = v
                    .matched_flags
                    .map(describe_tcp_flags)
                    .unwrap_or_else(|| "-".to_string());
                writeln!(
                    writer,
                    "  阻断报文: 标志位={} 窗口={} TTL={} IP-ID={} 方向={} 负载={}字节",
                    flag_str,
                    v.matched_window.map(|w| w.to_string()).unwrap_or_else(|| "-".to_string()),
                    v.matched_ttl.map(|t| t.to_string()).unwrap_or_else(|| "-".to_string()),
                    v.matched_ip_id
                        .map(|i| format!("0x{:04X}", i))
                        .unwrap_or_else(|| "-".to_string()),
                    match v.matched_to_client {
                        Some(true) => "朝向客户端",
                        Some(false) => "朝向服务器",
                        None => "-",
                    },
                    v.matched_payload_len
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                )?;
                if let Some(ts) = v.matched_timestamp {
                    writeln!(writer, "  阻断报文时间戳: {}", ts)?;
                }
            }
            writeln!(
                writer,
                "  握手: {}",
                if stream.connection.handshake.is_complete() { "完成" } else { "未完成" }
            )?;
            writeln!(writer, "  状态: {}", stream.state.as_str())?;
            writeln!(
                writer,
                "  数据包数: {}  字节数: {}",
                stream.stats.packet_count, stream.stats.byte_count
            )?;
            writeln!(writer, "")?;
        }

        let not_blocked = not_blocked_flows.len();
        writeln!(writer, "# 统计摘要:")?;
        writeln!(writer, "# 待验证流数: {}", total)?;
        writeln!(writer, "# 已成功阻断: {}", blocked)?;
        writeln!(writer, "# 未成功阻断: {}", not_blocked)?;

        if self.args.verbose {
            eprintln!("\n统计摘要:");
            eprintln!("  待验证流数: {}", total);
            eprintln!("  已成功阻断: {}", blocked);
            eprintln!("  未成功阻断: {}", not_blocked);
        }

        // 导出未阻断的流到 PCAP 文件
        if !not_blocked_flows.is_empty() {
            let output_path = format!("npatch_verify_{}_not_blocked.pcap", mode.slug());
            self.export_not_blocked_packets_to_pcap(&not_blocked_flows, &output_path)?;
            eprintln!("\n已导出 {} 个未阻断会话的数据包到: {}", not_blocked, output_path);
        }

        Ok(())
    }

    /// 把未被成功阻断的会话的数据包导出到 PCAP 文件
    fn export_not_blocked_packets_to_pcap(
        &self,
        not_blocked_flows: &std::collections::HashSet<FlowKey>,
        output_path: &str,
    ) -> Result<(), AppError> {
        // 重新读取原始 PCAP，导出未阻断流的全部报文
        let pcap_reader = PcapReader::open(&self.args.input)?;
        let linktype = pcap_reader.global_header().linktype;
        let parser = PacketParser::new(false, false, linktype);

        // 65535 链路层在导出时统一用 1（Ethernet）
        let export_linktype = if linktype == 65535 { 1 } else { linktype };
        let mut writer = create_pcap_writer(output_path, export_linktype)?;
        let mut exported_packets = 0;

        for packet_result in pcap_reader {
            let Ok(raw_packet) = packet_result else { continue };
            // 解析以获得五元组；parse 不修改原始字节，解析后的报文可直接写出
            let Ok(packet) = parser.parse(raw_packet) else { continue };
            if let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port)) =
                (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port)
            {
                let flow_key = FlowKey::new(src_ip, dst_ip, src_port, dst_port, 6);
                if not_blocked_flows.contains(&flow_key)
                    && writer.write_packet(&packet).is_ok()
                {
                    exported_packets += 1;
                }
            }
        }

        writer.flush()?;
        eprintln!("成功导出 {} 个数据包", exported_packets);
        Ok(())
    }
}

/// 主函数
fn main() {
    // 检查软件使用期限
    pcap_steam_anylizer::time_limit::check_expiry();

    // 解析命令行参数
    let args = Args::parse();

    // 创建并运行应用程序
    let app = App::new(args);
    if let Err(e) = app.run() {
        eprintln!("错误: {}", e);
        process::exit(1);
    }
}