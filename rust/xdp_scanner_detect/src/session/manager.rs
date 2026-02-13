//! TCP 会话管理器

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 会话管理器
pub struct SessionManager {
    stats: Arc<RwLock<SessionStats>>,
    config: crate::config::SessionConfig,
}

impl SessionManager {
    pub fn new(config: crate::config::SessionConfig) -> Self {
        Self {
            stats: Arc::new(RwLock::new(SessionStats::default())),
            config,
        }
    }

    /// 更新会话统计（从 XDP 统计更新）
    pub async fn update_from_xdp(&self, active_sessions: u64, total_sessions: u64) {
        let mut stats = self.stats.write().await;
        stats.active_sessions = active_sessions as u32;
        stats.total_sessions = total_sessions;
        // 注意：timeout_sessions 和 average_duration_ms 需要从 eBPF maps 获取更详细信息
    }

    /// 获取会话统计信息
    pub async fn get_stats(&self) -> SessionStats {
        self.stats.read().await.clone()
    }

    /// 会话超时清理任务
    pub async fn cleanup_task(&self) {
        use tokio::time::{interval, Duration};
        let mut interval = interval(Duration::from_secs(self.config.cleanup_interval_sec.into()));

        loop {
            interval.tick().await;
            // TODO: 实现会话清理逻辑
        }
    }
}

/// 会话统计信息
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    pub active_sessions: u32,
    pub total_sessions: u64,
    pub timeout_sessions: u64,
    pub average_duration_ms: u64,
}