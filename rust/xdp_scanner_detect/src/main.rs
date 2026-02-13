//! xdp-scanner-detect - 基于 eBPF/XDP 的高性能 TCP 会话处理和扫描器检测系统
//!
//! 这是用户空间的主程序，负责：
//! - 加载和管理 eBPF 程序
//! - 配置管理和策略更新
//! - 会话超时处理
//! - 统计信息收集和展示
//! - 告警输出和日志记录

use anyhow::Result;
use clap::Parser;
use log::{info, error, warn};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::signal;
use tokio::time::{interval, Duration};

mod config;
mod session;
mod scanner;
mod stats;
mod utils;
mod xdp;

use config::{Config, InterfaceConfig};
use xdp::XdpManager;
use session::SessionManager;
use scanner::ScannerDetector;
use stats::StatsCollector;

/// xdp-scanner-detect - 高性能网络安全检测系统
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 配置文件路径
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// 网络接口名称
    #[arg(short = 'i', long)]
    interface: Option<String>,

    /// 日志级别 (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// 运行模式 (monitor, enforce)
    #[arg(short, long, default_value = "monitor")]
    mode: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // 初始化日志系统
    init_logging(&args.log_level);

    info!("xdp-scanner-detect v{} 启动", env!("CARGO_PKG_VERSION"));

    // 加载配置（如果文件不存在则使用默认配置）
    let config = if std::path::Path::new(&args.config).exists() {
        Config::load(&args.config)?
    } else {
        warn!("配置文件 {} 不存在，使用默认配置", &args.config);
        Config::default()
    };
    info!("配置已加载");

    // 创建核心组件 - 使用 Arc 包装以便在后台任务中使用
    // 先创建 session_manager 和 scanner_detector
    let session_manager = Arc::new(SessionManager::new(config.session.clone()));
    let scanner_detector = Arc::new(ScannerDetector::new(config.scanner.clone()));

    // 创建 stats_collector 并设置会话和扫描器管理器
    let mut stats_collector_mut = StatsCollector::new();
    stats_collector_mut.set_session_manager(session_manager.clone());
    stats_collector_mut.set_scanner_detector(scanner_detector.clone());
    let stats_collector = Arc::new(stats_collector_mut);

    // 创建 XdpManager
    let mut xdp_manager = XdpManager::new(stats_collector.clone());

    // 初始化 XDP 管理器
    xdp_manager.initialize().await?;

    // 获取网络接口配置
    let interface_name = args.interface
        .or_else(|| config.interface.name.clone())
        .ok_or_else(|| anyhow::anyhow!("未指定网络接口"))?;

    // 加载并启动 eBPF 程序
    info!("在接口 {} 上加载 eBPF 程序", interface_name);
    let promisc_mode = config.interface.promisc_mode;
    if let Err(e) = xdp_manager.load_and_attach(&interface_name, promisc_mode).await {
        error!("加载 eBPF 程序失败: {}", e);
        return Err(e);
    }

    info!("eBPF 程序加载成功");

    // 启动后台任务 - 克隆 Arc 以便在任务中使用
    let stats_collector_clone = stats_collector.clone();
    let stats_handle = tokio::spawn(async move {
        stats_collector_clone.run().await
    });
    let session_manager_clone = session_manager.clone();
    let cleanup_handle = tokio::spawn(async move {
        session_manager_clone.cleanup_task().await
    });
    let scanner_detector_clone = scanner_detector.clone();
    let scanner_handle = tokio::spawn(async move {
        scanner_detector_clone.run().await
    });

    // 主循环 - 定期输出统计信息
    let mut stats_interval = interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            _ = stats_interval.tick() => {
                // 输出统计信息
                let stats = stats_collector.get_stats().await;
                info!("统计信息: {:?}", stats);

                // 会话统计
                let session_stats = session_manager.get_stats().await;
                info!("会话统计: {:?}", session_stats);

                // 扫描器统计
                let scanner_stats = scanner_detector.get_stats().await;
                info!("扫描器统计: {:?}", scanner_stats);
            }

            // 优雅退出
            _ = signal::ctrl_c() => {
                info!("收到退出信号，正在关闭...");
                break;
            }
        }
    }

    // 清理资源
    info!("正在清理资源...");

    // 停止后台任务
    stats_handle.abort();
    cleanup_handle.abort();
    scanner_handle.abort();

    // 卸载 eBPF 程序
    if let Err(e) = xdp_manager.cleanup().await {
        warn!("清理 eBPF 程序时出错: {}", e);
    }

    info!("xdp-scanner-detect 已正常退出");
    Ok(())
}

/// 初始化日志系统
fn init_logging(level: &str) {
    let log_level = match level {
        "trace" => log::LevelFilter::Trace,
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => log::LevelFilter::Info,
    };

    env_logger::Builder::from_default_env()
        .filter_level(log_level)
        .format_timestamp_secs()
        .init();
}

/// 设置 CPU 亲和性以优化性能
fn set_cpu_affinity(cpu_id: usize) -> Result<()> {
    use nix::sched::{sched_setaffinity, CpuSet};

    let mut cpu_set = CpuSet::new();
    cpu_set.set(cpu_id)?;

    sched_setaffinity(nix::unistd::getpid(), &cpu_set)?;

    info!("已设置 CPU 亲和性到核心 {}", cpu_id);
    Ok(())
}

/// 配置系统参数以优化网络性能
fn configure_system() -> Result<()> {
    use std::fs;

    // 增加内存映射限制
    fs::write("/proc/sys/vm/max_map_count", "262144")?;

    // 配置网络缓冲区大小
    fs::write("/proc/sys/net/core/rmem_max", "134217728")?;  // 128MB
    fs::write("/proc/sys/net/core/wmem_max", "134217728")?;  // 128MB

    // 配置 eBPF 相关参数
    fs::write("/proc/sys/net/core/bpf_jit_enable", "1")?;

    info!("系统参数已优化");
    Ok(())
}