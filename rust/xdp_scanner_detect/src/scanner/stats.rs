//! 扫描器统计信息

use serde::{Deserialize, Serialize};

/// 扫描器统计信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// 端口扫描次数
    pub port_scans: u64,
    /// SYN flood 次数
    pub syn_floods: u64,
    /// 其他扫描类型次数
    pub other_scans: u64,
}