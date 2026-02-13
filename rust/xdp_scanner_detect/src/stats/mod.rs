//! 统计信息模块
//!
//! 收集和展示系统运行统计信息

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::session::SessionManager;
use crate::scanner::ScannerDetector;

/// XDP 统计信息（从 eBPF maps 读取）
#[derive(Debug, Clone, Default)]
pub struct XdpStatsData {
    pub total_packets: u64,
    pub tcp_packets: u64,
    pub new_sessions: u64,
    pub malformed_packets: u64,
    pub scanner_detected: u64,
    pub malicious_sessions: u64,
    pub dropped_packets: u64,
}

/// 统计收集器
pub struct StatsCollector {
    stats: Arc<RwLock<GlobalStats>>,
    interface_stats: Arc<RwLock<HashMap<String, InterfaceStats>>>,
    // 存储 XDP 统计数据
    xdp_stats: Arc<RwLock<XdpStatsData>>,
    // 会话和扫描器管理器（可选，用于传递统计信息）
    session_manager: Option<Arc<SessionManager>>,
    scanner_detector: Option<Arc<ScannerDetector>>,
}

impl StatsCollector {
    /// 创建新的统计收集器
    pub fn new() -> Self {
        Self {
            stats: Arc::new(RwLock::new(GlobalStats::default())),
            interface_stats: Arc::new(RwLock::new(HashMap::new())),
            xdp_stats: Arc::new(RwLock::new(XdpStatsData::default())),
            session_manager: None,
            scanner_detector: None,
        }
    }

    /// 设置会话管理器
    pub fn set_session_manager(&mut self, manager: Arc<SessionManager>) {
        self.session_manager = Some(manager);
    }

    /// 设置扫描器检测器
    pub fn set_scanner_detector(&mut self, detector: Arc<ScannerDetector>) {
        self.scanner_detector = Some(detector);
    }

    /// 更新 XDP 统计数据（由 XdpManager 调用）
    pub async fn update_xdp_stats(&self, xdp_stats: XdpStatsData) {
        // 更新全局统计
        let mut stats = self.stats.write().await;
        stats.total_packets = xdp_stats.total_packets;
        stats.tcp_packets = xdp_stats.tcp_packets;
        stats.new_sessions = xdp_stats.new_sessions;
        stats.scanner_detected = xdp_stats.scanner_detected;
        stats.malicious_sessions = xdp_stats.malicious_sessions;
        stats.dropped_packets = xdp_stats.dropped_packets;

        // 保存 XDP 统计数据
        let mut xdps = self.xdp_stats.write().await;
        *xdps = xdp_stats.clone();

        // 传递统计信息到会话管理器
        if let Some(ref session_mgr) = self.session_manager {
            session_mgr.update_from_xdp(xdp_stats.new_sessions, xdp_stats.new_sessions).await;
        }

        // 传递统计信息到扫描器检测器
        if let Some(ref scanner_det) = self.scanner_detector {
            scanner_det.update_from_xdp(xdp_stats.scanner_detected, xdp_stats.malicious_sessions).await;
        }
    }

    /// 运行统计收集任务
    pub async fn run(&self) {
        use tokio::time::{interval, Duration};
        let mut interval = interval(Duration::from_secs(5));

        loop {
            interval.tick().await;
            self.collect_stats().await;
        }
    }

    /// 收集统计信息
    async fn collect_stats(&self) {
        let mut stats = self.stats.write().await;
        stats.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        stats.uptime += 5;

        // 从 XDP 统计数据读取（由 update_xdp_stats 更新）
        let xdps = self.xdp_stats.read().await;
        stats.total_packets = xdps.total_packets;
        stats.tcp_packets = xdps.tcp_packets;
        stats.new_sessions = xdps.new_sessions;
        stats.scanner_detected = xdps.scanner_detected;
        stats.malicious_sessions = xdps.malicious_sessions;
        stats.dropped_packets = xdps.dropped_packets;
    }

    /// 获取全局统计信息
    pub async fn get_stats(&self) -> GlobalStats {
        self.stats.read().await.clone()
    }
}

/// 全局统计信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalStats {
    /// 时间戳
    pub timestamp: u64,
    /// 运行时间（秒）
    pub uptime: u64,
    /// 总数据包数
    pub total_packets: u64,
    /// TCP 数据包数
    pub tcp_packets: u64,
    /// 新会话数
    pub new_sessions: u64,
    /// 活跃会话数
    pub active_sessions: u64,
    /// 超时会话数
    pub timeout_sessions: u64,
    /// 扫描器检测数
    pub scanner_detected: u64,
    /// 恶意会话数
    pub malicious_sessions: u64,
    /// 丢包数
    pub dropped_packets: u64,
    /// 平均处理时间（纳秒）
    pub avg_processing_time_ns: u64,
    /// 内存使用量（字节）
    pub memory_usage_bytes: u64,
    /// CPU 使用率（百分比）
    pub cpu_usage_percent: f64,
}

/// 接口统计信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceStats {
    /// 接口名称
    pub interface_name: String,
    /// 总数据包数
    pub total_packets: u64,
    /// 丢包数
    pub dropped_packets: u64,
    /// 转发数据包数
    pub passed_packets: u64,
    /// 重定向数据包数
    pub redirected_packets: u64,
    /// 异常退出数
    pub aborted_packets: u64,
    /// 最后更新时间
    pub last_update: u64,
}