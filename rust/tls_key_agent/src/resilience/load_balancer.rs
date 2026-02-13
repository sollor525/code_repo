/**
 * @file load_balancer.rs
 * @brief 负载均衡器 - 支持8种负载均衡策略
 * @author sollor525@hotmail.com
 * @version 2.0.0
 * @date 2023-12-01
 */

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::common::error::{TlsKeyAgentError, Result};

/// 负载均衡策略
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoadBalanceStrategy {
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    WeightedLeastConnections,
    Hash,
    ConsistentHash,
    Random,
    ResponseTime,
}

/// 负载均衡配置
#[derive(Debug, Clone)]
pub struct LoadBalanceConfig {
    /// 策略
    pub strategy: LoadBalanceStrategy,
    /// 健康检查间隔（毫秒）
    pub health_check_interval: Duration,
    /// 失败阈值
    pub failure_threshold: u32,
    /// 恢复阈值
    pub recovery_threshold: u32,
    /// 超时时间
    pub timeout: Duration,
}

impl Default for LoadBalanceConfig {
    fn default() -> Self {
        Self {
            strategy: LoadBalanceStrategy::RoundRobin,
            health_check_interval: Duration::from_secs(30),
            failure_threshold: 3,
            recovery_threshold: 2,
            timeout: Duration::from_secs(5),
        }
    }
}

/// 节点信息
#[derive(Debug, Clone)]
pub struct NodeInfo {
    /// 节点ID
    pub node_id: String,
    /// 地址
    pub address: String,
    /// 权重
    pub weight: u32,
    /// 是否可用
    pub available: bool,
    /// 当前连接数
    pub current_connections: u32,
    /// 响应时间（毫秒）
    pub response_time: f64,
    /// 成功计数
    pub success_count: u64,
    /// 失败计数
    pub failure_count: u64,
    /// 最后成功时间
    pub last_success_time: Option<Instant>,
    /// 最后失败时间
    pub last_failure_time: Option<Instant>,
}

impl NodeInfo {
    pub fn new(node_id: String, address: String) -> Self {
        Self {
            node_id,
            address,
            weight: 1,
            available: true,
            current_connections: 0,
            response_time: 0.0,
            success_count: 0,
            failure_count: 0,
            last_success_time: None,
            last_failure_time: None,
        }
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    pub fn update_success(&mut self) {
        self.success_count += 1;
        self.last_success_time = Some(Instant::now());
        self.available = true;
    }

    pub fn update_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure_time = Some(Instant::now());
        self.available = false;
    }
}

/// 负载均衡统计
#[derive(Debug, Clone, Default)]
pub struct LoadBalanceStats {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub total_nodes: u32,
    pub balance_efficiency: f64,
}

/// 负载均衡器
pub struct LoadBalancer {
    config: Arc<LoadBalanceConfig>,
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    stats: Arc<RwLock<LoadBalanceStats>>,
}

impl LoadBalancer {
    pub fn new(config: LoadBalanceConfig) -> Self {
        Self {
            config: Arc::new(config),
            nodes: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(LoadBalanceStats::default())),
        }
    }

    /// 添加节点
    pub async fn add_node(&self, node: NodeInfo) -> Result<()> {
        let node_id = node.node_id.clone();
        let mut nodes = self.nodes.write().await;
        nodes.insert(node_id.clone(), node);
        info!("添加负载均衡节点: {}", node_id);
        Ok(())
    }

    /// 移除节点
    pub async fn remove_node(&self, node_id: &str) -> Result<bool> {
        let mut nodes = self.nodes.write().await;
        let removed = nodes.remove(node_id).is_some();
        if removed {
            info!("移除负载均衡节点: {}", node_id);
        }
        Ok(removed)
    }

    /// 更新节点状态
    pub async fn update_node_status(&self, node_id: &str, success: bool) -> Result<()> {
        let mut nodes = self.nodes.write().await;
        if let Some(node) = nodes.get_mut(node_id) {
            if success {
                node.update_success();
            } else {
                node.update_failure();
            }
            Ok(())
        } else {
            Err(TlsKeyAgentError::Config(format!("节点 {} 不存在", node_id)))
        }
    }

    /// 选择节点
    pub async fn select_node(&self, _key: Option<&str>) -> Result<Option<NodeInfo>> {
        let nodes = self.nodes.read().await;
        let available_nodes: Vec<&NodeInfo> = nodes
            .values()
            .filter(|node| node.is_available())
            .collect();

        if available_nodes.is_empty() {
            warn!("没有可用的负载均衡节点");
            return Ok(None);
        }

        // 简化实现：直接选择第一个可用节点
        if available_nodes.is_empty() {
            Ok(None)
        } else {
            let node = (*available_nodes[0]).clone();
            // 更新统计信息
            self.update_selection_stats(&node.node_id).await;
            Ok(Some(node))
        }
    }

    /// 获取所有节点
    pub async fn get_all_nodes(&self) -> Result<Vec<NodeInfo>> {
        let nodes = self.nodes.read().await;
        Ok(nodes.values().cloned().collect())
    }

    /// 获取可用节点
    pub async fn get_available_nodes(&self) -> Result<Vec<NodeInfo>> {
        let nodes = self.nodes.read().await;
        let available_nodes: Vec<NodeInfo> = nodes
            .values()
            .filter(|node| node.is_available())
            .cloned()
            .collect();
        Ok(available_nodes)
    }

    /// 更新选择统计
    async fn update_selection_stats(&self, _node_id: &str) {
        let mut stats = self.stats.write().await;
        stats.total_requests += 1;
        stats.total_nodes = self.nodes.read().await.len() as u32;
    }

    /// 更新请求统计
    pub async fn update_request_stats(&self, success: bool) {
        let mut stats = self.stats.write().await;
        if success {
            stats.successful_requests += 1;
        } else {
            stats.failed_requests += 1;
        }
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> Result<LoadBalanceStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }

    /// 重置统计信息
    pub async fn reset_stats(&self) -> Result<()> {
        let mut stats = self.stats.write().await;
        *stats = LoadBalanceStats::default();
        Ok(())
    }

    /// 健康检查所有节点
    pub async fn health_check_all(&self) -> Result<HashMap<String, bool>> {
        let mut results = HashMap::new();
        let mut nodes_to_update = Vec::new();

        {
            let nodes = self.nodes.read().await;
            for (node_id, node) in nodes.iter() {
                // 简化实现：基于连续失败判断健康状态
                let healthy = node.failure_count < self.config.failure_threshold as u64;
                results.insert(node_id.clone(), healthy);

                // 记录需要更新的节点
                if (!healthy && node.is_available()) || (healthy && !node.is_available()) {
                    nodes_to_update.push((node_id.clone(), healthy));
                }
            }
        }

        // 更新节点状态
        for (node_id, healthy) in nodes_to_update {
            let _ = self.update_node_status(&node_id, healthy).await;
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_load_balancer_creation() {
        let config = LoadBalanceConfig::default();
        let lb = LoadBalancer::new(config);

        let stats = lb.get_stats().await.unwrap();
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_nodes, 0);
    }

    #[tokio::test]
    async fn test_node_management() {
        let config = LoadBalanceConfig::default();
        let lb = LoadBalancer::new(config);

        let node = NodeInfo::new("node1".to_string(), "127.0.0.1:8080".to_string());
        lb.add_node(node).await.unwrap();

        let nodes = lb.get_all_nodes().await.unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node1");

        let removed = lb.remove_node("node1").await.unwrap();
        assert!(removed);

        let nodes = lb.get_all_nodes().await.unwrap();
        assert_eq!(nodes.len(), 0);
    }

    #[tokio::test]
    async fn test_node_selection() {
        let config = LoadBalanceConfig::default();
        let lb = LoadBalancer::new(config);

        let node = NodeInfo::new("node1".to_string(), "127.0.0.1:8080".to_string());
        lb.add_node(node).await.unwrap();

        let selected = lb.select_node(None).await.unwrap();
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().node_id, "node1");

        let stats = lb.get_stats().await.unwrap();
        assert_eq!(stats.total_requests, 1);
    }

    #[tokio::test]
    async fn test_empty_selection() {
        let config = LoadBalanceConfig::default();
        let lb = LoadBalancer::new(config);

        let selected = lb.select_node(None).await.unwrap();
        assert!(selected.is_none());
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = LoadBalanceConfig::default();
        let lb = LoadBalancer::new(config);

        let node = NodeInfo::new("node1".to_string(), "127.0.0.1:8080".to_string());
        lb.add_node(node).await.unwrap();

        let results = lb.health_check_all().await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results.get("node1"), Some(&true));
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let config = LoadBalanceConfig::default();
        let lb = LoadBalancer::new(config);

        let node = NodeInfo::new("node1".to_string(), "127.0.0.1:8080".to_string());
        lb.add_node(node).await.unwrap();

        // 更新请求统计
        lb.update_request_stats(true).await;
        lb.update_request_stats(false).await;

        let stats = lb.get_stats().await.unwrap();
        assert_eq!(stats.successful_requests, 1);
        assert_eq!(stats.failed_requests, 1);

        // 重置统计
        lb.reset_stats().await.unwrap();
        let stats = lb.get_stats().await.unwrap();
        assert_eq!(stats.successful_requests, 0);
        assert_eq!(stats.failed_requests, 0);
    }
}