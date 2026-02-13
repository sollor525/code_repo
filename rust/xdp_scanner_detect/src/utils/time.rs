//! 时间工具函数

use std::time::{SystemTime, UNIX_EPOCH};

/// 时间工具函数
pub struct TimeUtils;

impl TimeUtils {
    /// 获取当前时间戳（毫秒）
    pub fn current_timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// 获取当前时间戳（纳秒）
    pub fn current_timestamp_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    /// 格式化时间戳
    pub fn format_timestamp(timestamp: u64) -> String {
        let datetime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);
        // 简单的时间格式化，实际应用中可以使用 chrono 库
        format!("{}", datetime.elapsed().unwrap().as_secs())
    }
}