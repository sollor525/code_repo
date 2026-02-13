//! 配置参数定义
//!
//! 定义所有系统参数和默认值

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// TCP 会话参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSessionParams {
    /// 最大并发会话数
    pub max_sessions: u32,
    /// 会话超时时间（秒）
    pub timeout_sec: u32,
    /// 会话最大持续时间（秒）
    pub max_duration_sec: u32,
    /// TCP 状态跟踪超时
    pub state_timeout_sec: u32,
    /// 乱序包缓存数量
    pub max_out_of_order: u32,
    /// 最大重组缓冲区大小
    pub max_reassembly_bytes: u32,
}

impl Default for TcpSessionParams {
    fn default() -> Self {
        Self {
            max_sessions: 1_000_000,
            timeout_sec: 15,
            max_duration_sec: 120,
            state_timeout_sec: 30,
            max_out_of_order: 100,
            max_reassembly_bytes: 1024 * 1024,  // 1MB
        }
    }
}

/// 扫描器检测参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerDetectParams {
    /// 扫描检测时间窗口（秒）
    pub time_window_sec: u32,
    /// 端口扫描阈值
    pub port_scan_threshold: u32,
    /// SYN flood 阈值（每秒）
    pub syn_flood_threshold: u32,
    /// 连接频率阈值
    pub connection_rate_threshold: u32,
    /// 扫描置信度阈值
    pub confidence_threshold: u8,
    /// 最小检测端口数
    pub min_ports_for_detection: u32,
    /// TTL 异常检测阈值
    pub ttl_anomaly_threshold: u8,
}

impl Default for ScannerDetectParams {
    fn default() -> Self {
        Self {
            time_window_sec: 60,
            port_scan_threshold: 10,
            syn_flood_threshold: 1000,
            connection_rate_threshold: 50,
            confidence_threshold: 80,
            min_ports_for_detection: 5,
            ttl_anomaly_threshold: 3,
        }
    }
}

/// 性能优化参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceParams {
    /// 工作线程数量
    pub worker_threads: usize,
    /// 批量处理大小
    pub batch_size: u32,
    /// 批量处理超时（微秒）
    pub batch_timeout_us: u64,
    /// CPU 亲和性设置
    pub cpu_affinity: Vec<u32>,
    /// 内存映射区域大小
    pub mmap_size: usize,
    /// 启用 HugePage
    pub enable_hugepages: bool,
    /// Per-CPU map 大小
    pub percpu_map_size: u32,
}

impl Default for PerformanceParams {
    fn default() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            batch_size: 32,
            batch_timeout_us: 100,
            cpu_affinity: Vec::new(),
            mmap_size: 64 * 1024 * 1024,  // 64MB
            enable_hugepages: true,
            percpu_map_size: 64,
        }
    }
}

/// 网络接口参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceParams {
    /// 网络接口名称
    pub name: String,
    /// XDP 模式
    pub xdp_mode: String,
    /// 队列映射
    pub queue_mapping: Vec<QueueMappingParams>,
    /// 启用硬件卸载
    pub enable_offload: bool,
    /// RSS 设置
    pub rss_settings: RssSettings,
    /// 启用混杂模式（用于接收镜像流量）
    pub promisc_mode: bool,
}

impl Default for InterfaceParams {
    fn default() -> Self {
        Self {
            name: "eth0".to_string(),
            xdp_mode: "skb".to_string(),
            queue_mapping: Vec::new(),
            enable_offload: false,
            rss_settings: RssSettings::default(),
            promisc_mode: false,  // 默认关闭，需要手动启用
        }
    }
}

/// 队列映射参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueMappingParams {
    /// 硬件队列 ID
    pub queue_id: u32,
    /// 对应的 CPU 核心
    pub cpu_core: u32,
    /// 队列优先级
    pub priority: u8,
}

/// RSS 设置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RssSettings {
    /// 启用 RSS
    pub enabled: bool,
    /// RSS 队列数
    pub queue_count: u32,
    /// RSS 哈希密钥
    pub hash_key: Option<Vec<u8>>,
    /// RSS 哈希类型
    pub hash_types: Vec<String>,
}

impl Default for RssSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            queue_count: 4,
            hash_key: None,
            hash_types: vec![
                "ipv4".to_string(),
                "tcp".to_string(),
                "udp".to_string(),
            ],
        }
    }
}

/// 日志参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingParams {
    /// 日志级别
    pub level: String,
    /// 日志文件路径
    pub file_path: Option<String>,
    /// 日志文件最大大小（字节）
    pub max_file_size: u64,
    /// 日志文件保留数量
    pub max_files: u32,
    /// 启用结构化日志
    pub enable_structured: bool,
    /// 启用 eBPF 日志
    pub enable_ebpf_log: bool,
    /// 日志格式
    pub format: LogFormat,
}

impl Default for LoggingParams {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file_path: None,
            max_file_size: 100 * 1024 * 1024,  // 100MB
            max_files: 10,
            enable_structured: true,
            enable_ebpf_log: false,
            format: LogFormat::Text,
        }
    }
}

/// 日志格式
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// 纯文本格式
    Text,
    /// JSON 格式
    Json,
    /// 结构化格式
    Structured,
}

/// 监控和指标参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringParams {
    /// 启用 Prometheus 指标
    pub enable_prometheus: bool,
    /// Prometheus 监听地址
    pub prometheus_addr: String,
    /// 指标收集间隔（秒）
    pub metrics_interval_sec: u32,
    /// 启用性能分析
    pub enable_profiling: bool,
    /// 性能数据保留时间（秒）
    pub profile_retention_sec: u32,
}

impl Default for MonitoringParams {
    fn default() -> Self {
        Self {
            enable_prometheus: true,
            prometheus_addr: "0.0.0.0:9090".to_string(),
            metrics_interval_sec: 10,
            enable_profiling: false,
            profile_retention_sec: 3600,  // 1小时
        }
    }
}

/// 安全参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityParams {
    /// 启用白名单
    pub enable_whitelist: bool,
    /// 白名单 IP 列表
    pub whitelist_ips: Vec<String>,
    /// 启用黑名单
    pub enable_blacklist: bool,
    /// 黑名单 IP 列表
    pub blacklist_ips: Vec<String>,
    /// 启用 geoip 过滤
    pub enable_geoip: bool,
    /// 允许的国家代码
    pub allowed_countries: Vec<String>,
    /// 禁止的国家代码
    pub blocked_countries: Vec<String>,
}

impl Default for SecurityParams {
    fn default() -> Self {
        Self {
            enable_whitelist: true,
            whitelist_ips: vec![
                "127.0.0.1".to_string(),
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            enable_blacklist: false,
            blacklist_ips: Vec::new(),
            enable_geoip: false,
            allowed_countries: Vec::new(),
            blocked_countries: Vec::new(),
        }
    }
}

/// 系统限制参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemLimitsParams {
    /// 最大内存使用（字节）
    pub max_memory_bytes: u64,
    /// 最大 CPU 使用率（百分比）
    pub max_cpu_percent: u8,
    /// 最大文件描述符数量
    pub max_file_descriptors: u32,
    /// 最大 eBPF map 数量
    pub max_maps: u32,
    /// 单个 map 最大条目数
    pub max_map_entries: u32,
}

impl Default for SystemLimitsParams {
    fn default() -> Self {
        Self {
            max_memory_bytes: 2 * 1024 * 1024 * 1024,  // 2GB
            max_cpu_percent: 80,
            max_file_descriptors: 1000000,
            max_maps: 100,
            max_map_entries: 10000000,
        }
    }
}

/// 调试参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugParams {
    /// 启用调试模式
    pub enable_debug: bool,
    /// 详细日志
    pub verbose_logging: bool,
    /// 启用性能分析
    pub enable_perf_analysis: bool,
    /// 转储数据包到文件
    pub dump_packets: bool,
    /// 转储文件路径
    pub dump_file_path: Option<String>,
    /// 启用内存泄漏检测
    pub enable_leak_detection: bool,
}

impl Default for DebugParams {
    fn default() -> Self {
        Self {
            enable_debug: false,
            verbose_logging: false,
            enable_perf_analysis: false,
            dump_packets: false,
            dump_file_path: None,
            enable_leak_detection: false,
        }
    }
}

/// 配置验证错误
#[derive(Debug, thiserror::Error)]
pub enum ConfigValidationError {
    #[error("无效的数值范围: {field} = {value}, 期望 {min} - {max}")]
    InvalidRange {
        field: String,
        value: String,
        min: String,
        max: String,
    },

    #[error("无效的 IP 地址: {ip}")]
    InvalidIpAddress { ip: String },

    #[error("无效的网络接口: {interface}")]
    InvalidInterface { interface: String },

    #[error("文件路径不存在或不可访问: {path}")]
    InvalidFilePath { path: String },

    #[error("配置冲突: {field1} 和 {field2}")]
    ConfigConflict {
        field1: String,
        field2: String,
    },
}

/// 验证配置参数
pub fn validate_config(config: &crate::config::Config) -> Result<(), ConfigValidationError> {
    // 验证 TCP 会话参数
    if config.session.max_sessions == 0 || config.session.max_sessions > 10_000_000 {
        return Err(ConfigValidationError::InvalidRange {
            field: "max_sessions".to_string(),
            value: config.session.max_sessions.to_string(),
            min: "1".to_string(),
            max: "10000000".to_string(),
        });
    }

    // 验证扫描器检测参数
    if config.scanner.scan_threshold == 0 {
        return Err(ConfigValidationError::InvalidRange {
            field: "scan_threshold".to_string(),
            value: config.scanner.scan_threshold.to_string(),
            min: "1".to_string(),
            max: "1000".to_string(),
        });
    }

    // 验证性能参数
    if config.performance.batch.batch_size == 0 || config.performance.batch.batch_size > 1024 {
        return Err(ConfigValidationError::InvalidRange {
            field: "batch_size".to_string(),
            value: config.performance.batch.batch_size.to_string(),
            min: "1".to_string(),
            max: "1024".to_string(),
        });
    }

    // 验证白名单 IP 地址
    for ip in &config.scanner.whitelist_ips {
        if let Err(e) = ip.parse::<std::net::IpAddr>() {
            return Err(ConfigValidationError::InvalidIpAddress {
                ip: ip.clone(),
            });
        }
    }

    Ok(())
}