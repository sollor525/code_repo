//! 并行处理PCAP文件示例

use clap::Parser;
use pcap_steam_anylizer::{
    parallel::{ParallelProcessor, ParallelConfig},
    stream::StreamManagerConfig,
    output::Formatter,
};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "parallel_processing")]
#[command(about = "并行处理PCAP文件示例")]
struct Args {
    /// PCAP文件路径
    #[arg(short, long)]
    input: String,

    /// 输出文件路径
    #[arg(short, long)]
    output: Option<String>,

    /// 输出格式 (table, json, csv)
    #[arg(short, long, default_value = "table")]
    format: String,

    /// 工作线程数量
    #[arg(short, long)]
    workers: Option<usize>,

    /// 批处理大小
    #[arg(long, default_value = "1000")]
    batch_size: usize,

    /// 最大流数量
    #[arg(long, default_value = "100000")]
    max_streams: usize,

    /// 流超时时间（秒）
    #[arg(long, default_value = "300")]
    stream_timeout: u64,

    /// 启用详细输出
    #[arg(short, long)]
    verbose: bool,

    /// 禁用进度条
    #[arg(long)]
    no_progress: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 创建并行处理配置
    let stream_config = StreamManagerConfig {
        stream_timeout: Duration::from_secs(args.stream_timeout),
        max_streams: args.max_streams,
        enable_event_logging: false,
        max_events_per_stream: 0,
        cleanup_interval: Duration::from_secs(60),
        syn_rst_888: false,
        handshake_ack_rst_888: false,
    };

    let parallel_config = ParallelConfig {
        num_workers: args.workers,
        stream_config,
        batch_size: args.batch_size,
        enable_progress: !args.no_progress,
    };

    // 创建并行处理器
    let mut processor = ParallelProcessor::new(parallel_config);

    // 处理PCAP文件
    println!("开始并行处理文件: {}", args.input);
    let start_time = std::time::Instant::now();

    let result = processor.process_file(&args.input)?;

    let total_time = start_time.elapsed();

    // 输出统计信息
    if args.verbose {
        println!("\n=== 处理统计 ===");
        println!("数据包总数: {}", result.packet_count);
        println!("识别的流数: {}", result.stream_count);
        println!("解析错误数: {}", result.parse_errors);
        println!("实际处理时间: {:?}", result.processing_time);
        println!("总耗时（含初始化）: {:?}", total_time);
        println!("处理速度: {:.2} 包/秒", result.packets_per_second());
        println!("平均处理时间: {:.2} 微秒/包", result.avg_packet_time_us());
    }

    // 过滤和排序流
    let mut filtered_streams = result.streams;

    // 只保留有数据包的流
    filtered_streams.retain(|s| s.stats.packet_count > 0);

    // 按数据包数量排序
    filtered_streams.sort_by(|a, b| b.stats.packet_count.cmp(&a.stats.packet_count));

    // 输出结果
    let mut formatter = Formatter::new();

    match args.format.as_str() {
        "json" => {
            formatter.set_format(pcap_steam_anylizer::output::OutputFormat::Json);
        }
        "csv" => {
            formatter.set_format(pcap_steam_anylizer::output::OutputFormat::Csv);
        }
        _ => {
            formatter.set_format(pcap_steam_anylizer::output::OutputFormat::Table);
        }
    }

    formatter.output_streams(&filtered_streams, &args.output)?;

    Ok(())
}