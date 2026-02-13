//! XDP 统计信息收集

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// XDP 统计信息收集器
pub struct XdpStats {
    global_stats: Arc<RwLock<super::XdpProgramStats>>,
    interface_stats: Arc<RwLock<HashMap<String, super::XdpProgramStats>>>,
}

impl XdpStats {
    /// 创建新的统计收集器
    pub fn new() -> Self {
        Self {
            global_stats: Arc::new(RwLock::new(super::XdpProgramStats::default())),
            interface_stats: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 初始化统计系统
    pub async fn initialize(&self) -> Result<()> {
        Ok(())
    }

    /// 更新全局统计信息
    pub async fn update_global_stats(&self, stats: super::XdpProgramStats) -> Result<()> {
        let mut global = self.global_stats.write().await;
        *global = stats;
        Ok(())
    }

    /// 更新接口统计信息（直接传入统计数据）
    pub async fn update_interface_stats_direct(&self, interface: &str, stats: super::XdpProgramStats) -> Result<()> {
        let mut interface_stats = self.interface_stats.write().await;
        interface_stats.insert(interface.to_string(), stats);
        Ok(())
    }

    /// 获取全局统计信息
    pub async fn get_overall_stats(&self) -> super::XdpProgramStats {
        self.global_stats.read().await.clone()
    }

    /// 获取接口统计信息
    pub async fn get_interface_stats(&self, interface: &str) -> Option<super::XdpProgramStats> {
        let interface_stats = self.interface_stats.read().await;
        interface_stats.get(interface).cloned()
    }
}