// PCAP流分析器主程序
//
// 此程序用于分析PCAP文件中的TCP流，提供多种输出格式和过滤选项

use clap::Parser;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use pcap_steam_anylizer::{
    pcap::{PcapReader, PcapError, PacketParser, create_pcap_writer},
    stream::{StreamManager, StreamManagerConfig},
    output::{FlowFormatter, OutputFormat, SortField, SortOrder, FlowFilter},
    types::{PacketInfo, flow::FlowKey},
    parallel::{ParallelProcessor, ParallelConfig, stream_manager::OutputArgs},
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

 # 检测SYN包后窗口大小为888的RST-ACK报文
 pcap_analyzer input.pcap --syn-rst-888
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

    /// 检测SYN包后窗口大小为888的RST-ACK报文
    #[arg(
        long = "syn-rst-888",
        help = "检测SYN包后窗口大小为888的RST-ACK报文"
    )]
    syn_rst_888: bool,

    /// 检测三次握手ACK报文后窗口大小为888的RST报文
    #[arg(
        long = "handshake-ack-rst-888",
        help = "检测三次握手完成后的ACK报文后窗口大小为888的RST报文"
    )]
    handshake_ack_rst_888: bool,

    /// 启用并行处理
    #[arg(
        long = "parallel",
        help = "启用多线程并行处理（手动线程管理）"
    )]
    parallel: bool,

    /// 启用 Rayon 并行处理（默认已启用）
    #[arg(
        long = "rayon",
        help = "启用 Rayon 数据并行处理（默认选项）"
    )]
    rayon: bool,

    /// 禁用并行处理（使用单线程）
    #[arg(
        long = "single-thread",
        help = "禁用并行处理，使用单线程模式"
    )]
    single_thread: bool,

    /// 工作线程数量（并行模式）
    #[arg(
        long = "workers",
        help = "并行处理的工作线程数量（默认为CPU核心数）"
    )]
    workers: Option<usize>,

    /// 批处理大小（并行模式）
    #[arg(
        long = "batch-size",
        default_value = "1000",
        help = "并行处理的批处理大小"
    )]
    batch_size: usize,

    /// 按流分组处理（仅限 Rayon 模式）
    #[arg(
        long = "rayon-group-by-flow",
        help = "按流分组进行并行处理（保持同一线程处理同一个流）"
    )]
    rayon_group_by_flow: bool,
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

    #[error("Rayon并行处理错误: {0}")]
    RayonError(#[from] Box<dyn std::error::Error>),
}

/// 应用程序主逻辑
struct App {
    args: Args,
    stream_manager: Arc<Mutex<StreamManager>>,
}

impl App {
    /// 创建新的应用程序实例
    fn new(args: Args) -> Result<Self, AppError> {
        // 配置流管理器
        let config = StreamManagerConfig {
            stream_timeout: std::time::Duration::from_secs(300),
            max_streams: 100000,
            enable_event_logging: args.verbose,
            max_events_per_stream: if args.verbose { 1000 } else { 100 },
            cleanup_interval: std::time::Duration::from_secs(60),
            syn_rst_888: args.syn_rst_888,
            handshake_ack_rst_888: args.handshake_ack_rst_888,
        };

        let stream_manager = Arc::new(Mutex::new(StreamManager::new(config)));

        Ok(Self {
            args,
            stream_manager,
        })
    }

    /// 运行应用程序
    fn run(&self) -> Result<(), AppError> {
        // 验证输入文件
        self.validate_input()?;

        // 如果用户明确要求单线程模式
        if self.args.single_thread {
            return self.run_single_thread();
        }

        // 如果用户显式指定了旧的并行模式，则使用旧模式
        if self.args.parallel {
            return self.run_parallel();
        }

        // 默认使用 Rayon 处理
        return self.run_rayon();
    }

    /// 单线程处理PCAP文件
    fn run_single_thread(&self) -> Result<(), AppError> {
        // 创建PCAP读取器
        #[allow(unused_mut)]
        let mut pcap_reader = PcapReader::open(&self.args.input)?;

        // 输出文件信息
        if self.args.verbose {
            eprintln!("正在分析文件: {}", self.args.input);
            eprintln!("PCAP版本: {}.{}",
                pcap_reader.global_header().major_version,
                pcap_reader.global_header().minor_version
            );
            eprintln!("链路层类型: {}", pcap_reader.global_header().linktype);
            eprintln!("捕获长度: {}", pcap_reader.global_header().snaplen);
            eprintln!("处理模式: 单线程");
        }

        // 处理数据包
        let start_time = Instant::now();
        let packet_count = self.process_packets(&mut pcap_reader)?;
        let processing_time = start_time.elapsed();

        // 输出RST-888检测结果（如果启用）
        if self.args.syn_rst_888 {
            self.output_syn_rst_888_detection_results(&self.stream_manager)?;
            // RST-888 检测模式下不输出会话详情，直接返回
            return Ok(());
        }

        if self.args.handshake_ack_rst_888 {
            self.output_handshake_ack_rst_888_detection_results(&self.stream_manager)?;
            // RST-888 检测模式下不输出会话详情，直接返回
            return Ok(());
        }

        // 输出结果
        self.output_results(&self.stream_manager, packet_count, processing_time)?;

        Ok(())
    }

    /// 验证输入文件
    fn validate_input(&self) -> Result<(), AppError> {
        if !Path::new(&self.args.input).exists() {
            return Err(AppError::InvalidArgument(
                format!("输入文件不存在: {}", self.args.input)
            ));
        }

        // 验证协议参数
        if let Some(ref protocol) = self.args.protocol {
            if !["tcp", "udp", "icmp"].contains(&protocol.as_str()) {
                return Err(AppError::InvalidArgument(
                    format!("无效的协议: {}", protocol)
                ));
            }
        }

        Ok(())
    }

    /// 处理PCAP数据包
    fn process_packets(&self, pcap_reader: &mut PcapReader) -> Result<u64, AppError> {
        use indicatif::{ProgressBar, ProgressStyle};

        let linktype = pcap_reader.global_header().linktype;
        let mut packet_count = 0u64;

        // 创建进度条
        let progress = if !self.args.no_progress {
            // 基于数据包数量的进度条
            let progress = ProgressBar::new_spinner();

            progress.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] 处理中: {pos} 个数据包")
                    .unwrap()
            );

            Some(progress)
        } else {
            None
        };

        // 迭代处理数据包
        for packet_result in pcap_reader {
            match packet_result {
                Ok(packet) => {
                    // 先解析数据包
                    let parser = PacketParser::new(false, false, linktype);
                    let parsed_packet = match parser.parse(packet) {
                        Ok(p) => p,
                        Err(e) => {
                            if self.args.verbose {
                                eprintln!("解析数据包失败: {}", e);
                            }
                            continue;
                        }
                    };

                    // 转换为PacketInfo
                    let packet_info: PacketInfo = parsed_packet.into();

                    // 更新流管理器
                    {
                        let mut manager = self.stream_manager.lock().unwrap();
                        manager.process_packet(&packet_info);
                    }

                    packet_count += 1;

                    // 更新进度条
                    if let Some(ref p) = progress {
                        p.set_position(packet_count);
                        if packet_count % 1000 == 0 {
                            p.set_message(format!("已处理 {} 个数据包", packet_count));
                        }
                    }
                }
                Err(e) => {
                    if self.args.verbose {
                        eprintln!("警告: 处理数据包时出错: {}", e);
                    }
                }
            }
        }

        if let Some(p) = progress {
            p.finish_with_message("数据处理完成");
        }

        Ok(packet_count)
    }

    /// 输出结果
    fn output_results(
        &self,
        stream_manager: &Arc<Mutex<StreamManager>>,
        packet_count: u64,
        processing_time: std::time::Duration,
    ) -> Result<(), AppError> {
        // 创建输出写入器
        let mut writer: Box<dyn Write> = if let Some(ref output_path) = self.args.output {
            Box::new(File::create(output_path)?)
        } else {
            Box::new(io::stdout())
        };

        // 解析输出格式
        let format = match self.args.format.as_str() {
            "table" => OutputFormat::Table,
            "json" => OutputFormat::Json,
            "csv" => OutputFormat::Csv,
            _ => OutputFormat::Table,
        };

        // 解析排序字段
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
            _ => SortField::FlowId,
        };

        let sort_order = if self.args.descending {
            SortOrder::Descending
        } else {
            SortOrder::Ascending
        };

        // 创建过滤器
        let mut filter = FlowFilter::new();

        // 协议过滤
        if let Some(ref protocol) = self.args.protocol {
            let protocol_num = match protocol.as_str() {
                "tcp" => 6,
                "udp" => 17,
                "icmp" => 1,
                _ => 6,
            };
            filter = filter.protocol(protocol_num);
        }

        // IP和端口过滤
        if let Some(ref ip) = self.args.src_ip {
            filter = filter.src_ip(ip.clone());
        }
        if let Some(ref ip) = self.args.dst_ip {
            filter = filter.dst_ip(ip.clone());
        }
        if let Some(port) = self.args.src_port {
            filter = filter.src_port(port);
        }
        if let Some(port) = self.args.dst_port {
            filter = filter.dst_port(port);
        }

        // 数据包和字节过滤
        if let Some(min) = self.args.min_packets {
            filter = filter.packet_range(min, self.args.max_packets.unwrap_or(u64::MAX));
        }
        if let Some(min) = self.args.min_bytes {
            filter = filter.byte_range(min, self.args.max_bytes.unwrap_or(u64::MAX));
        }

        // 完整流过滤
        if self.args.complete {
            filter = filter.complete_only(true);
        }

        // 创建格式化器
        let formatter = FlowFormatter::new(format)
            .sort_by(sort_field)
            .sort_order(sort_order)
            .filter(filter)
            .verbose(self.args.verbose);

        // 在锁内完成所有流操作
        {
            let manager = stream_manager.lock().unwrap();

            // 如果启用了RST-888检测，输出不符合条件的会话信息
            if self.args.syn_rst_888 {
                self.output_syn_rst_888_detection_results(&stream_manager)?;

                // 不需要继续执行其他输出
                return Ok(());
            }

            // 如果启用了三次握手ACK后的RST-888检测，输出不符合条件的会话信息
            if self.args.handshake_ack_rst_888 {
                self.output_handshake_ack_rst_888_detection_results(&stream_manager)?;

                // 不需要继续执行其他输出
                return Ok(());
            }

            if self.args.verbose {
                let stream_count = manager.get_all_streams().count();
                eprintln!("\n处理完成:");
                eprintln!("  总数据包数: {}", packet_count);
                eprintln!("  识别的流数: {}", stream_count);
                eprintln!("  处理时间: {:?}", processing_time);
            }

            // 收集流的引用
            let stream_refs: Vec<&pcap_steam_anylizer::TcpStream> =
                manager.get_all_streams().collect();

            // 格式化并输出
            let output = formatter.format_streams(&stream_refs)?;
            writer.write_all(output.as_bytes())?;
        }

        Ok(())
    }

    /// 输出SYN-RST-888检测结果
    fn output_syn_rst_888_detection_results(&self, manager: &Arc<Mutex<StreamManager>>) -> Result<(), AppError> {
        eprintln!("\nRST-888检测结果:");
        eprintln!("查找SYN包后窗口大小为888的RST-ACK报文...\n");

        let mut total_streams = 0;
        let mut streams_with_rst_888 = 0;
        let mut streams_without_rst_888 = 0;

        // 创建输出写入器
        let mut writer: Box<dyn Write> = if let Some(ref output_path) = self.args.output {
            Box::new(File::create(output_path)?)
        } else {
            Box::new(io::stdout())
        };

        // 写入标题
        writeln!(writer, "# RST-888检测结果报告")?;
        writeln!(writer, "# 以下会话在SYN包后没有收到窗口大小为888的RST-ACK报文")?;
        writeln!(writer, "")?;

        for stream in manager.lock().unwrap().get_all_streams() {
            total_streams += 1;

            // 只检查TCP流
            if stream.flow_key.protocol() != 6 {
                continue;
            }

            // 检查是否有数据包（意味着有活动）
            if stream.stats.packet_count == 0 {
                continue;
            }

            // 检查是否收到了SYN包
            if stream.connection.handshake.client_syn {
                // 检查是否在SYN包后直接收到了窗口大小为888的RST-ACK报文
                if stream.has_immediate_rst_888_after_syn {
                    streams_with_rst_888 += 1;
                } else {
                    streams_without_rst_888 += 1;

                    // 输出不符合要求的会话信息
                    writeln!(writer, "会话ID: {}", stream.flow_key.to_string())?;
                    writeln!(writer, "  客户端: {}:{}", stream.flow_key.src_ip(), stream.flow_key.src_port())?;
                    writeln!(writer, "  服务器: {}:{}", stream.flow_key.dst_ip(), stream.flow_key.dst_port())?;
                    writeln!(writer, "  状态: {}", stream.state.as_str())?;
                    writeln!(writer, "  数据包数: {}", stream.stats.packet_count)?;
                    writeln!(writer, "  字节数: {}", stream.stats.byte_count)?;

                    // 显示SYN包后的数据包数
                    writeln!(writer, "  SYN包后的数据包数: {}", stream.packets_since_syn)?;

                    // 显示连接持续时间
                    if let Some(duration) = stream.connection.duration_seconds() {
                        writeln!(writer, "  持续时间: {:.3} 秒", duration)?;
                    }

                    // 显示握手状态
                    if stream.connection.handshake.is_complete() {
                        writeln!(writer, "  握手: 完成")?;
                    } else {
                        writeln!(writer, "  握手: 未完成")?;
                    }

                    // 显示关闭状态
                    if stream.connection.close.is_complete() {
                        writeln!(writer, "  关闭: 已关闭")?;
                        if stream.connection.close.reset {
                            writeln!(writer, "  关闭方式: RST")?;
                        }
                    } else {
                        writeln!(writer, "  关闭: 未关闭")?;
                    }

                    writeln!(writer, "")?;
                }
            }
        }

        // 写入统计信息
        writeln!(writer, "# 统计摘要:")?;
        writeln!(writer, "# 总TCP流数: {}", total_streams)?;
        writeln!(writer, "# 有RST-888报文的流数: {}", streams_with_rst_888)?;
        writeln!(writer, "# 无RST-888报文的流数: {}", streams_without_rst_888)?;

        if self.args.verbose {
            eprintln!("\n统计摘要:");
            eprintln!("  总TCP流数: {}", total_streams);
            eprintln!("  有RST-888报文的流数: {}", streams_with_rst_888);
            eprintln!("  无RST-888报文的流数: {}", streams_without_rst_888);
        }

        // 导出不符合要求的会话的数据包到PCAP文件
        if streams_without_rst_888 > 0 {
            self.export_non_rst888_packets_to_pcap(manager, "syn_rst_888_non_compliant.pcap")?;
        }

        Ok(())
    }

    /// 输出三次握手ACK后的RST-888检测结果
    fn output_handshake_ack_rst_888_detection_results(&self, manager: &Arc<Mutex<StreamManager>>) -> Result<(), AppError> {
        eprintln!("\n三次握手ACK后RST-888检测结果:");
        eprintln!("查找三次握手完成后的ACK报文后窗口大小为888的RST报文...\n");

        let mut total_streams = 0;
        let mut streams_with_rst_888 = 0;
        let mut streams_without_rst_888 = 0;

        // 创建输出写入器
        let mut writer: Box<dyn Write> = if let Some(ref output_path) = self.args.output {
            Box::new(File::create(output_path)?)
        } else {
            Box::new(io::stdout())
        };

        // 写入标题
        writeln!(writer, "# 三次握手ACK后RST-888检测结果报告")?;
        writeln!(writer, "# 以下会话在三次握手完成后的ACK报文后没有收到窗口大小为888的RST报文")?;
        writeln!(writer, "")?;

        for stream in manager.lock().unwrap().get_all_streams() {
            // 只检查TCP流
            if stream.flow_key.protocol() != 6 {
                continue;
            }

            // 检查是否有数据包
            if stream.stats.packet_count == 0 {
                continue;
            }

            // 检查是否有完整的三次握手
            if !stream.connection.handshake.is_complete() {
                continue;
            }

            total_streams += 1;

            if stream.has_rst_888_after_handshake_ack {
                streams_with_rst_888 += 1;
            } else {
                streams_without_rst_888 += 1;

                // 输出不符合要求的会话信息
                writeln!(writer, "会话ID: {}", stream.flow_key.to_string())?;
                writeln!(writer, "  客户端: {}:{}", stream.flow_key.src_ip(), stream.flow_key.src_port())?;
                writeln!(writer, "  服务器: {}:{}", stream.flow_key.dst_ip(), stream.flow_key.dst_port())?;
                writeln!(writer, "  状态: {}", stream.state.as_str())?;
                writeln!(writer, "  数据包数: {}", stream.stats.packet_count)?;
                writeln!(writer, "  字节数: {}", stream.stats.byte_count)?;

                // 显示三次握手ACK后的数据包数
                writeln!(writer, "  三次握手ACK后的数据包数: {}", stream.packets_since_handshake_ack)?;

                // 显示连接持续时间
                if let Some(duration) = stream.connection.duration_seconds() {
                    writeln!(writer, "  持续时间: {:.3} 秒", duration)?;
                }

                // 显示握手状态
                if stream.connection.handshake.is_complete() {
                    writeln!(writer, "  握手: 完成")?;
                } else {
                    writeln!(writer, "  握手: 未完成")?;
                }

                // 显示关闭状态
                if stream.connection.close.is_complete() {
                    writeln!(writer, "  关闭: 已关闭")?;
                    if stream.connection.close.reset {
                        writeln!(writer, "  关闭方式: RST")?;
                    }
                } else {
                    writeln!(writer, "  关闭: 未关闭")?;
                }

                writeln!(writer, "")?;
            }
        }

        // 写入统计信息
        writeln!(writer, "# 统计摘要:")?;
        writeln!(writer, "# 总TCP流数: {}", total_streams)?;
        writeln!(writer, "# 三次握手完成且有RST-888报文的流数: {}", streams_with_rst_888)?;
        writeln!(writer, "# 三次握手完成且无RST-888报文的流数: {}", streams_without_rst_888)?;

        if self.args.verbose {
            eprintln!("\n统计摘要:");
            eprintln!("  总TCP流数: {}", total_streams);
            eprintln!("  三次握手完成且有RST-888报文的流数: {}", streams_with_rst_888);
            eprintln!("  三次握手完成且无RST-888报文的流数: {}", streams_without_rst_888);
        }

        // 导出不符合要求的会话的数据包到PCAP文件
        if streams_without_rst_888 > 0 {
            self.export_handshake_ack_non_rst888_packets_to_pcap(manager, "handshake_ack_rst_888_non_compliant.pcap")?;
        }

        Ok(())
    }

    /// 并行处理PCAP文件
    fn run_parallel(&self) -> Result<(), AppError> {
        // 验证输入文件
        self.validate_input()?;

        // 输出文件信息
        if self.args.verbose {
            eprintln!("正在并行分析文件: {}", self.args.input);
            eprintln!("工作线程数: {:?}",
                self.args.workers.unwrap_or_else(|| num_cpus::get()));
            eprintln!("批处理大小: {}", self.args.batch_size);
        }

        // 配置流管理器
        let stream_config = StreamManagerConfig {
            stream_timeout: std::time::Duration::from_secs(300),
            max_streams: 100000,
            enable_event_logging: false, // 并行模式下关闭事件日志以提高性能
            max_events_per_stream: 0,
            cleanup_interval: std::time::Duration::from_secs(60),
            syn_rst_888: self.args.syn_rst_888,
            handshake_ack_rst_888: self.args.handshake_ack_rst_888,
        };

        // 配置并行处理器
        let parallel_config = ParallelConfig {
            num_workers: self.args.workers,
            stream_config,
            batch_size: self.args.batch_size,
            enable_progress: !self.args.no_progress,
        };

        // 创建并行处理器
        let mut processor = ParallelProcessor::new(parallel_config);

        // 处理PCAP文件
        let _start_time = Instant::now();
        let result = processor.process_file(&self.args.input)
            .map_err(|e| AppError::Processing(format!("并行处理失败: {}", e)))?;

        // 输出统计信息
        if self.args.verbose {
            eprintln!("\n=== 并行处理统计 ===");
            eprintln!("数据包总数: {}", result.packet_count);
            eprintln!("识别的流数: {}", result.stream_count);
            eprintln!("解析错误数: {}", result.parse_errors);
            eprintln!("处理时间: {:?}", result.processing_time);
            eprintln!("处理速度: {:.2} 包/秒", result.packets_per_second());
        }

        // 处理 RST-888 检测结果
        if self.args.syn_rst_888 {
            // 从并行处理器获取流管理器
            let manager = processor.stream_manager();
            let _streams = manager.get_all_streams();

            // 创建输出参数
            let output_args = OutputArgs {
                output: self.args.output.clone(),
                verbose: self.args.verbose,
            };

            manager.output_syn_rst_888_detection_results(&output_args)?;
            // RST-888 检测模式下不输出会话详情，直接返回
            return Ok(());
        }

        if self.args.handshake_ack_rst_888 {
            // 从并行处理器获取流管理器
            let manager = processor.stream_manager();
            let _streams = manager.get_all_streams();

            // 创建输出参数
            let output_args = OutputArgs {
                output: self.args.output.clone(),
                verbose: self.args.verbose,
            };

            manager.output_handshake_ack_rst_888_detection_results(&output_args)?;
            // RST-888 检测模式下不输出会话详情，直接返回
            return Ok(());
        }

        // 过滤流
        let filtered_streams = result.streams;

        // 输出结果
        let output_format = match self.args.format.as_str() {
            "json" => OutputFormat::Json,
            "csv" => OutputFormat::Csv,
            _ => OutputFormat::Table,
        };
        let mut formatter = FlowFormatter::new(output_format);

        // 设置排序
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
            "first_packet" => SortField::FirstPacketTime,
            "last_packet" => SortField::LastPacketTime,
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

        // 设置过滤器
        let mut filter = FlowFilter::new();

        if let Some(ref protocol) = self.args.protocol {
            filter = filter.protocol(protocol.parse().map_err(|e|
                AppError::Processing(format!("无效的协议: {}", e)))?);
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
            if let Some(max_packets) = self.args.max_packets {
                filter = filter.packet_range(min_packets, max_packets);
            } else {
                filter = filter.packet_range(min_packets, u64::MAX);
            }
        } else if let Some(max_packets) = self.args.max_packets {
            filter = filter.packet_range(0, max_packets);
        }

        if let Some(min_bytes) = self.args.min_bytes {
            if let Some(max_bytes) = self.args.max_bytes {
                filter = filter.byte_range(min_bytes, max_bytes);
            } else {
                filter = filter.byte_range(min_bytes, u64::MAX);
            }
        } else if let Some(max_bytes) = self.args.max_bytes {
            filter = filter.byte_range(0, max_bytes);
        }

        if self.args.complete {
            filter = filter.complete_only(true);
        }

        formatter = formatter.filter(filter);

        // 输出
        let formatted_output = formatter.format_streams(&filtered_streams.iter().collect::<Vec<_>>())?;

        match &self.args.output {
            Some(output_path) => {
                std::fs::write(output_path, formatted_output)?;
            }
            None => {
                print!("{}", formatted_output);
            }
        }

        // 输出RST-888检测结果（如果启用）
        if self.args.syn_rst_888 {
            // 需要从ThreadSafeStreamManager获取结果
            let streams = processor.stream_manager().get_all_streams();
            let total_streams = streams.len();
            let streams_with_rst = streams.iter()
                .filter(|s| s.flow_key.protocol() == 6 && s.has_rst_888_after_syn)
                .count();

            eprintln!("\nSYN后RST-888检测结果:");
            eprintln!("总TCP流数: {}", total_streams);
            eprintln!("检测到SYN后RST-888的流数: {}", streams_with_rst);
        }

        if self.args.handshake_ack_rst_888 {
            let streams = processor.stream_manager().get_all_streams();
            let total_streams = streams.len();
            let streams_with_rst = streams.iter()
                .filter(|s| s.flow_key.protocol() == 6 && s.has_rst_888_after_handshake_ack)
                .count();

            eprintln!("\n三次握手ACK后RST-888检测结果:");
            eprintln!("总TCP流数: {}", total_streams);
            eprintln!("检测到三次握手ACK后RST-888的流数: {}", streams_with_rst);
        }

        Ok(())
    }

    /// 使用 Rayon 并行处理PCAP文件
    fn run_rayon(&self) -> Result<(), AppError> {
        // 创建 Rayon 配置
        let stream_config = StreamManagerConfig {
            stream_timeout: std::time::Duration::from_secs(300),
            max_streams: 100000,
            enable_event_logging: self.args.verbose,
            max_events_per_stream: if self.args.verbose { 1000 } else { 100 },
            cleanup_interval: std::time::Duration::from_secs(60),
            syn_rst_888: self.args.syn_rst_888,
            handshake_ack_rst_888: self.args.handshake_ack_rst_888,
        };

        let rayon_config = RayonConfig {
            stream_config,
            batch_size: self.args.batch_size,
            enable_progress: !self.args.no_progress,
            thread_pool_size: self.args.workers,
        };

        // 创建 Rayon 处理器
        let processor = RayonProcessor::new(rayon_config);

        // 读取和解析所有数据包
        eprintln!("正在读取和解析 PCAP 文件...");
        if self.args.verbose {
            eprintln!("处理模式: Rayon 并行处理");
            if self.args.rayon_group_by_flow {
                eprintln!("分组方式: 按流分组");
            } else {
                eprintln!("分组方式: 批次并行");
            }
        }
        let start_time = Instant::now();

        #[allow(unused_mut)]
        let mut pcap_reader = PcapReader::open(&self.args.input)?;
        let linktype = pcap_reader.global_header().linktype;
        let parser = PacketParser::new(false, false, linktype);

        let mut packets = Vec::new();
        let mut parse_errors = 0u64; // 记录解析错误，用于统计

        // 使用迭代器收集所有数据包
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
        if parse_errors > 0 {
            eprintln!("读取阶段解析错误: {}", parse_errors);
        }
        eprintln!("读取完成: {} 个数据包，耗时 {:?}", packets.len(), read_time);

        // 使用 Rayon 并行处理
        eprintln!("开始 Rayon 并行处理...");
        // 对于TCP流分析，特别是RST-888检测，必须保证数据包按流分组处理
        // 否则会出现非确定性的结果
        let result = if self.args.rayon_group_by_flow || self.args.syn_rst_888 || self.args.handshake_ack_rst_888 {
            // 当检测RST-888或指定按流分组时，使用流分组模式确保一致性
            if !self.args.rayon_group_by_flow && (self.args.syn_rst_888 || self.args.handshake_ack_rst_888) {
                eprintln!("注意：为RST-888检测启用按流分组模式以确保结果一致性");
            }
            processor.process_packets_by_flow(packets)?
        } else {
            // 非流分组模式，用于一般统计分析
            processor.process_packets_parallel(packets)?
        };

        // 输出统计信息
        if self.args.verbose {
            eprintln!("\n=== 处理统计 ===");
            eprintln!("数据包总数: {}", result.packet_count);
            eprintln!("识别的流数: {}", result.stream_count);
            eprintln!("解析错误数: {}", result.parse_errors);
            eprintln!("处理时间: {:?}", result.processing_time);
            eprintln!("读取时间: {:?}", read_time);
            eprintln!("总耗时: {:?}", start_time.elapsed());
            eprintln!("处理速度: {:.2} 包/秒", result.packets_per_second());
            eprintln!("平均处理时间: {:.2} 微秒/包", result.avg_packet_time_us());
        }

        // 处理 RST-888 检测结果
        if self.args.syn_rst_888 {
            self.output_syn_rst_888_detection_results(processor.stream_manager())?;
            // RST-888 检测模式下不输出会话详情，直接返回
            return Ok(());
        }

        if self.args.handshake_ack_rst_888 {
            self.output_handshake_ack_rst_888_detection_results(processor.stream_manager())?;
            // RST-888 检测模式下不输出会话详情，直接返回
            return Ok(());
        }

        // 过滤和排序流
        let mut filtered_streams = result.streams;

        // 只保留有数据包的流
        filtered_streams.retain(|s| s.stats.packet_count > 0);

        // 按数据包数量排序
        filtered_streams.sort_by(|a, b| b.stats.packet_count.cmp(&a.stats.packet_count));

        // 输出结果
        let output_format = match self.args.format.as_str() {
            "json" => OutputFormat::Json,
            "csv" => OutputFormat::Csv,
            _ => OutputFormat::Table,
        };
        let mut formatter = FlowFormatter::new(output_format);

        // 设置排序
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
            "first_packet" => SortField::FirstPacketTime,
            "last_packet" => SortField::LastPacketTime,
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

        // 设置过滤器
        let mut filter = FlowFilter::new();

        if let Some(ref protocol) = self.args.protocol {
            filter = filter.protocol(protocol.parse().map_err(|e|
                AppError::Processing(format!("无效的协议: {}", e)))?);
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
            if let Some(max_packets) = self.args.max_packets {
                filter = filter.packet_range(min_packets, max_packets);
            } else {
                filter = filter.packet_range(min_packets, u64::MAX);
            }
        } else if let Some(max_packets) = self.args.max_packets {
            filter = filter.packet_range(0, max_packets);
        }

        if let Some(min_bytes) = self.args.min_bytes {
            if let Some(max_bytes) = self.args.max_bytes {
                filter = filter.byte_range(min_bytes, max_bytes);
            } else {
                filter = filter.byte_range(min_bytes, u64::MAX);
            }
        } else if let Some(max_bytes) = self.args.max_bytes {
            filter = filter.byte_range(0, max_bytes);
        }

        if self.args.complete {
            filter = filter.complete_only(true);
        }

        formatter = formatter.filter(filter);

        // 输出
        let formatted_output = formatter.format_streams(&filtered_streams.iter().collect::<Vec<_>>())?;

        match &self.args.output {
            Some(output_path) => {
                std::fs::write(output_path, formatted_output)?;
            }
            None => {
                print!("{}", formatted_output);
            }
        }

        Ok(())
    }

    /// 导出不符合SYN-RST-888要求的会话的数据包到PCAP文件
    fn export_non_rst888_packets_to_pcap(&self, manager: &Arc<Mutex<StreamManager>>, output_path: &str) -> Result<(), AppError> {
        use std::collections::HashSet;

        // 收集不符合要求的流的键
        let mut non_compliant_flows = HashSet::new();
        {
            let manager = manager.lock().unwrap();
            for stream in manager.get_all_streams() {
                if stream.flow_key.protocol() == 6 && stream.stats.packet_count > 0 {
                    if stream.connection.handshake.client_syn && !stream.has_immediate_rst_888_after_syn {
                        non_compliant_flows.insert(stream.flow_key.clone());
                    }
                }
            }
        }

        if non_compliant_flows.is_empty() {
            return Ok(());
        }

        eprintln!("\n正在导出 {} 个不符合SYN-RST-888要求的会话的数据包到: {}",
                  non_compliant_flows.len(), output_path);

        // 重新读取原始PCAP文件，只导出符合要求的流的数据包
        #[allow(unused_mut)]
        let mut pcap_reader = PcapReader::open(&self.args.input)?;
        let linktype = pcap_reader.global_header().linktype;
        let parser = PacketParser::new(false, false, linktype);

        // 对于 65535 链路层类型，在导出时使用 1（Ethernet）
        // 因为即使原始数据是 SLL 格式，数据内容本身仍然是以太网帧
        let export_linktype = if linktype == 65535 { 1 } else { linktype };
        let mut writer = create_pcap_writer(output_path, export_linktype)?;
        let mut exported_packets = 0;

        for packet_result in pcap_reader {
            match packet_result {
                Ok(raw_packet) => {
                    match parser.parse(raw_packet) {
                        Ok(packet) => {
                            // 检查这个数据包是否属于不符合要求的流
                            if let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port)) =
                                (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port) {
                                let flow_key = FlowKey::new(
                                    src_ip, dst_ip, src_port, dst_port, 6
                                );
                                if non_compliant_flows.contains(&flow_key) {
                                    writer.write_packet(&packet)?;
                                    exported_packets += 1;
                                }
                            }
                        }
                        Err(_) => continue,
                    }
                }
                Err(_) => continue,
            }
        }

        writer.flush()?;
        eprintln!("成功导出 {} 个数据包", exported_packets);
        Ok(())
    }

    /// 导出不符合三次握手ACK-RST-888要求的会话的数据包到PCAP文件
    fn export_handshake_ack_non_rst888_packets_to_pcap(&self, manager: &Arc<Mutex<StreamManager>>, output_path: &str) -> Result<(), AppError> {
        use std::collections::HashSet;

        // 收集不符合要求的流的键
        let mut non_compliant_flows = HashSet::new();
        {
            let manager = manager.lock().unwrap();
            for stream in manager.get_all_streams() {
                if stream.flow_key.protocol() == 6 && stream.stats.packet_count > 0 {
                    if stream.connection.handshake.is_complete() && !stream.has_rst_888_after_handshake_ack {
                        non_compliant_flows.insert(stream.flow_key.clone());
                    }
                }
            }
        }

        if non_compliant_flows.is_empty() {
            return Ok(());
        }

        eprintln!("\n正在导出 {} 个不符合三次握手ACK-RST-888要求的会话的数据包到: {}",
                  non_compliant_flows.len(), output_path);

        // 重新读取原始PCAP文件，只导出符合要求的流的数据包
        #[allow(unused_mut)]
        let mut pcap_reader = PcapReader::open(&self.args.input)?;
        let linktype = pcap_reader.global_header().linktype;
        let parser = PacketParser::new(false, false, linktype);

        // 对于 65535 链路层类型，在导出时使用 1（Ethernet）
        // 因为即使原始数据是 SLL 格式，数据内容本身仍然是以太网帧
        let export_linktype = if linktype == 65535 { 1 } else { linktype };
        let mut writer = create_pcap_writer(output_path, export_linktype)?;
        let mut exported_packets = 0;

        for packet_result in pcap_reader {
            match packet_result {
                Ok(raw_packet) => {
                    match parser.parse(raw_packet) {
                        Ok(packet) => {
                            // 检查这个数据包是否属于不符合要求的流
                            if let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port)) =
                                (packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port) {
                                let flow_key = FlowKey::new(
                                    src_ip, dst_ip, src_port, dst_port, 6
                                );
                                if non_compliant_flows.contains(&flow_key) {
                                    writer.write_packet(&packet)?;
                                    exported_packets += 1;
                                }
                            }
                        }
                        Err(_) => continue,
                    }
                }
                Err(_) => continue,
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
    match App::new(args) {
        Ok(app) => {
            if let Err(e) = app.run() {
                eprintln!("错误: {}", e);
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("错误: {}", e);
            process::exit(1);
        }
    }
}