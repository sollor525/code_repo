//! 配置管理模块
//!
//! 负责加载、解析和管理系统配置，包括：
//! - eBPF 程序参数
//! - 会话管理配置
//! - 扫描器检测参数
//! - 网络接口设置

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::net::Ipv4Addr;

pub mod params;

pub use params::*;

/// 主配置结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// 网络接口配置
    pub interface: InterfaceConfig,
    /// 会话管理配置
    pub session: SessionConfig,
    /// 扫描器检测配置
    pub scanner: ScannerConfig,
    /// 性能优化配置
    pub performance: PerformanceConfig,
    /// 日志配置
    pub logging: LoggingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: InterfaceConfig::default(),
            session: SessionConfig::default(),
            scanner: ScannerConfig::default(),
            performance: PerformanceConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Config {
    /// 从文件加载配置
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| anyhow!("配置文件解析失败: {}", e))?;

        // 验证配置
        config.validate()?;

        Ok(config)
    }

    /// 保存配置到文件
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// 验证配置的有效性
    pub fn validate(&self) -> Result<()> {
        // 验证会话配置
        if self.session.max_sessions == 0 {
            return Err(anyhow!("max_sessions 必须大于 0"));
        }

        if self.session.timeout_sec == 0 {
            return Err(anyhow!("timeout_sec 必须大于 0"));
        }

        // 验证扫描器配置
        if self.scanner.scan_threshold == 0 {
            return Err(anyhow!("scan_threshold 必须大于 0"));
        }

        // 验证性能配置
        if self.performance.cpu_affinity.len() > 64 {
            return Err(anyhow!("CPU 亲和性设置不能超过 64 个核心"));
        }

        Ok(())
    }

    /// 获取工作线程数量
    pub fn worker_threads(&self) -> usize {
        self.performance.worker_threads.unwrap_or_else(|| {
            num_cpus::get()
        })
    }
}

/// 网络接口配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// 网络接口名称
    pub name: Option<String>,
    /// 队列映射
    pub queue_mapping: Option<Vec<QueueMapping>>,
    /// XDP 模式
    pub xdp_mode: XdpMode,
    /// 网卡卸载配置
    pub offload: OffloadConfig,
    /// 启用混杂模式（用于接收镜像流量）
    pub promisc_mode: bool,
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            name: None,
            queue_mapping: None,
            xdp_mode: XdpMode::Skb,
            offload: OffloadConfig::default(),
            promisc_mode: true,  // 默认启用混杂模式（用于镜像流量监控）
        }
    }
}

/// XDP 运行模式
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    /// 通用模式，兼容性最好
    Skb,
    /// 驱动模式，性能最好
    Native,
    /// 硬件卸载模式
    Hw,
}

/// 队列映射配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueMapping {
    /// 硬件队列 ID
    pub queue_id: u32,
    /// 对应的 CPU 核心
    pub cpu_core: u32,
}

/// 网卡卸载配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffloadConfig {
    /// 启用硬件校验和
    pub checksum: bool,
    /// 启用硬件 RSS
    pub rss: bool,
    /// 启用硬件流导向
    pub flow_director: bool,
}

impl Default for OffloadConfig {
    fn default() -> Self {
        Self {
            checksum: true,
            rss: true,
            flow_director: false,
        }
    }
}

/// 会话管理配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// 最大并发会话数
    pub max_sessions: u32,
    /// 会话超时时间（秒）
    pub timeout_sec: u32,
    /// 会话最大持续时间（秒）
    pub max_duration_sec: u32,
    /// TCP 状态跟踪配置
    pub tcp: TcpSessionConfig,
    /// 会话清理间隔（秒）
    pub cleanup_interval_sec: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: 1_000_000,
            timeout_sec: 15,
            max_duration_sec: 120,
            tcp: TcpSessionConfig::default(),
            cleanup_interval_sec: 10,
        }
    }
}

/// TCP 会话配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSessionConfig {
    /// 启用 TCP 重组
    pub enable_reassembly: bool,
    /// 最大重组缓冲区大小
    pub max_reassembly_bytes: u32,
    /// 乱序包缓存数量
    pub max_out_of_order: u32,
    /// 启用窗口缩放跟踪
    pub track_window_scale: bool,
}

impl Default for TcpSessionConfig {
    fn default() -> Self {
        Self {
            enable_reassembly: true,
            max_reassembly_bytes: 1024 * 1024,  // 1MB
            max_out_of_order: 100,
            track_window_scale: true,
        }
    }
}

/// 扫描器检测配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// 扫描检测阈值
    pub scan_threshold: u32,
    /// 检测时间窗口（秒）
    pub time_window_sec: u32,
    /// 端口扫描检测
    pub port_scan: PortScanConfig,
    /// SYN flood 检测
    pub syn_flood: SynFloodConfig,
    /// 启用白名单
    pub enable_whitelist: bool,
    /// 白名单 IP 列表
    pub whitelist_ips: Vec<String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            scan_threshold: 10,
            time_window_sec: 60,
            port_scan: PortScanConfig::default(),
            syn_flood: SynFloodConfig::default(),
            enable_whitelist: true,
            whitelist_ips: vec![
                "127.0.0.1".to_string(),
            ],
        }
    }
}

/// 端口扫描检测配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanConfig {
    /// 端口扫描阈值
    pub threshold: u32,
    /// 端口范围
    pub port_ranges: Vec<PortRange>,
    /// 启用 TCP 标志检测
    pub enable_flag_detection: bool,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            threshold: 5,
            port_ranges: vec![
                PortRange { start: 1, end: 1024 },      // 常用端口
                PortRange { start: 8000, end: 8999 },   // Web 端口
            ],
            enable_flag_detection: true,
        }
    }
}

/// 端口范围
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRange {
    /// 起始端口
    pub start: u16,
    /// 结束端口
    pub end: u16,
}

/// SYN flood 检测配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynFloodConfig {
    /// SYN 包速率阈值（每秒）
    pub syn_rate_threshold: u32,
    /// 半连接数阈值
    pub half_connection_threshold: u32,
    /// 检测时间窗口（秒）
    pub time_window_sec: u32,
}

impl Default for SynFloodConfig {
    fn default() -> Self {
        Self {
            syn_rate_threshold: 1000,
            half_connection_threshold: 10000,
            time_window_sec: 10,
        }
    }
}

/// 性能优化配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// 工作线程数量
    pub worker_threads: Option<usize>,
    /// CPU 亲和性设置
    pub cpu_affinity: Vec<u32>,
    /// 内存映射配置
    pub memory: MemoryConfig,
    /// 批量处理配置
    pub batch: BatchConfig,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: None,
            cpu_affinity: vec![],
            memory: MemoryConfig::default(),
            batch: BatchConfig::default(),
        }
    }
}

/// 内存配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// 内存映射区域大小
    pub mmap_size: usize,
    /// 内存预分配数量
    pub prealloc_count: u32,
    /// 启用 HugePage
    pub enable_hugepages: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            mmap_size: 64 * 1024 * 1024,  // 64MB
            prealloc_count: 1000,
            enable_hugepages: true,
        }
    }
}

/// 批量处理配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    /// 批量处理大小
    pub batch_size: u32,
    /// 批量处理超时（微秒）
    pub batch_timeout_us: u64,
    /// 启用批量提交
    pub enable_batch_commit: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            batch_size: 32,
            batch_timeout_us: 100,
            enable_batch_commit: true,
        }
    }
}

/// 日志配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// 日志级别
    pub level: String,
    /// 日志文件路径
    pub file_path: Option<String>,
    /// 日志文件最大大小
    pub max_file_size: Option<u64>,
    /// 日志文件保留数量
    pub max_files: Option<u32>,
    /// 启用结构化日志
    pub enable_structured: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_path: None,
            max_file_size: Some(100 * 1024 * 1024),  // 100MB
            max_files: Some(10),
            enable_structured: true,
        }
    }
}