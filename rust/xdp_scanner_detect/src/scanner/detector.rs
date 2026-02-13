//! 扫描器检测器

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 扫描器检测器
pub struct ScannerDetector {
    stats: Arc<RwLock<ScannerStats>>,
    config: crate::config::ScannerConfig,
}

impl ScannerDetector {
    pub fn new(config: crate::config::ScannerConfig) -> Self {
        Self {
            stats: Arc::new(RwLock::new(ScannerStats::default())),
            config,
        }
    }

    /// 更新扫描器统计（从 XDP 统计更新）
    pub async fn update_from_xdp(&self, scanner_detected: u64, malicious_sessions: u64) {
        let mut stats = self.stats.write().await;
        stats.detected_scanners = scanner_detected as u32;
        stats.active_scanners = scanner_detected as u32;
        stats.total_scans = scanner_detected;
        // 误报和准确率需要更复杂的分析
    }

    /// 运行扫描器检测
    pub async fn run(&self) {
        use tokio::time::{interval, Duration};
        let mut interval = interval(Duration::from_secs(5));

        loop {
            interval.tick().await;
            // TODO: 实现扫描器检测逻辑
        }
    }

    /// 获取扫描器统计信息
    pub async fn get_stats(&self) -> ScannerStats {
        self.stats.read().await.clone()
    }
}

/// 扫描器统计信息
#[derive(Debug, Clone, Default)]
pub struct ScannerStats {
    /// 检测到的扫描器数量
    pub detected_scanners: u32,
    /// 活跃扫描器数量
    pub active_scanners: u32,
    /// 总扫描次数
    pub total_scans: u64,
    /// 误报数量
    pub false_positives: u32,
    /// 检测准确率
    pub accuracy_rate: f64,
}