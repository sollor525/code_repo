//! 辅助函数

/// 辅助工具函数
pub struct HelperUtils;

impl HelperUtils {
    /// 格式化字节大小
    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        format!("{:.2} {}", size, UNITS[unit_index])
    }

    /// 格式化时间
    pub fn format_duration_ns(duration_ns: u64) -> String {
        if duration_ns < 1_000 {
            format!("{} ns", duration_ns)
        } else if duration_ns < 1_000_000 {
            format!("{:.2} μs", duration_ns as f64 / 1_000.0)
        } else if duration_ns < 1_000_000_000 {
            format!("{:.2} ms", duration_ns as f64 / 1_000_000.0)
        } else {
            format!("{:.2} s", duration_ns as f64 / 1_000_000_000.0)
        }
    }
}