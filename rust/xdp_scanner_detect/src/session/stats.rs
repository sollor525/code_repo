//! 会话统计信息

use serde::{Deserialize, Serialize};

/// 会话统计信息
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    /// 活跃会话数
    pub active_sessions: u32,
    /// 总会话数
    pub total_sessions: u64,
    /// 超时会话数
    pub timeout_sessions: u64,
    /// 平均持续时间（毫秒）
    pub average_duration_ms: u64,
    /// 最大并发会话数
    pub max_concurrent_sessions: u32,
    /// 会话创建速率（每秒）
    pub creation_rate: f64,
}