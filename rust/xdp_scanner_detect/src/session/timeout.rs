//! 会话超时管理

/// 会话超时管理器
pub struct SessionTimeoutManager {
    timeout_sec: u32,
}

impl SessionTimeoutManager {
    pub fn new(timeout_sec: u32) -> Self {
        Self { timeout_sec }
    }

    /// 检查会话是否超时
    pub fn is_timeout(&self, last_seen: u64, current_time: u64) -> bool {
        let timeout_ns = self.timeout_sec as u64 * 1_000_000_000;
        current_time > last_seen && current_time - last_seen > timeout_ns
    }
}