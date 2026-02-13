/**
 * @file dynamic_config_manager.rs
 * @brief 动态配置管理器 - 专门处理源IP过滤和实时配置更新
 * @author sollor525@hotmail.com
 * @version 2.0.0 - eBPF内核级SSL Hook
 * @date 2023-12-01
 */

use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, debug, warn};
use anyhow::Result;

use crate::common::error::TlsKeyAgentError;
#[allow(unused_imports)]
use crate::config::{Config, FilterRule, SourceIpFilter, FiveTupleFilter};
use crate::extractor::ssl_hook::SslHookProcessor;

/// 动态配置更新事件
#[derive(Debug, Clone)]
pub enum ConfigUpdateEvent {
    /// 过滤规则更新
    FilterRulesUpdated {
        rules: Vec<FilterRule>,
        timestamp: u64,
    },
    /// 源IP过滤策略更新
    SourceIpFilterUpdated {
        filter: SourceIpFilter,
        timestamp: u64,
    },
    /// 全局配置更新
    GlobalConfigUpdated {
        config: Config,
        timestamp: u64,
    },
    /// 增量过滤规则添加
    FilterRuleAdded {
        rule: FilterRule,
        timestamp: u64,
    },
    /// 过滤规则移除
    FilterRuleRemoved {
        rule_name: String,
        timestamp: u64,
    },
}

/// 配置更新统计信息
#[derive(Debug, Clone, Default)]
pub struct ConfigUpdateStats {
    pub total_updates: u64,
    pub successful_updates: u64,
    pub failed_updates: u64,
    pub last_update_time: Option<u64>,
    pub last_error: Option<String>,
    pub active_filters: usize,
    pub blocked_ips: usize,
    pub allowed_ips: usize,
}

/// 动态配置管理器
pub struct DynamicConfigManager {
    // 配置状态
    config: Arc<RwLock<Config>>,
    is_running: AtomicBool,

    // 事件处理
    event_sender: mpsc::UnboundedSender<ConfigUpdateEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<ConfigUpdateEvent>>>>,

    // 统计信息
    stats: Arc<RwLock<ConfigUpdateStats>>,

    // 回调函数
    processors: Arc<RwLock<Vec<Arc<SslHookProcessor>>>>,

    // 缓存优化
    rule_cache: Arc<RwLock<HashMap<String, FilterRule>>>,
    ip_filter_cache: Arc<RwLock<HashMap<String, bool>>>, // IP -> 允许/拒绝

    // 配置历史
    config_history: Arc<RwLock<Vec<ConfigUpdateEvent>>>,
    max_history_size: usize,
}

impl DynamicConfigManager {
    /// 创建新的动态配置管理器
    pub fn new(initial_config: Arc<Config>) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel::<ConfigUpdateEvent>();

        Self {
            config: Arc::new(RwLock::new((*initial_config).clone())),
            is_running: AtomicBool::new(false),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            stats: Arc::new(RwLock::new(ConfigUpdateStats::default())),
            processors: Arc::new(RwLock::new(Vec::new())),
            rule_cache: Arc::new(RwLock::new(HashMap::new())),
            ip_filter_cache: Arc::new(RwLock::new(HashMap::new())),
            config_history: Arc::new(RwLock::new(Vec::new())),
            max_history_size: 100,
        }
    }

    /// 启动动态配置管理器
    pub async fn start(&self) -> Result<()> {
        if self.is_running.load(Ordering::SeqCst) {
            warn!("动态配置管理器已在运行");
            return Ok(());
        }

        info!("启动动态配置管理器");

        // 初始化缓存
        self.initialize_caches().await?;

        // 启动事件处理器
        self.start_event_processor().await;

        // 启动缓存清理任务
        self.start_cache_cleanup_task().await;

        self.is_running.store(true, Ordering::SeqCst);
        info!("动态配置管理器启动成功");
        Ok(())
    }

    /// 停止动态配置管理器
    pub async fn stop(&self) -> Result<()> {
        if !self.is_running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("停止动态配置管理器");
        self.is_running.store(false, Ordering::SeqCst);
        info!("动态配置管理器已停止");
        Ok(())
    }

    /// 注册SSL Hook处理器
    pub async fn register_processor(&self, processor: Arc<SslHookProcessor>) {
        let mut processors = self.processors.write().await;
        processors.push(processor);
        info!("注册SSL Hook处理器，当前处理器数量: {}", processors.len());
    }

    /// 动态更新过滤规则
    pub async fn update_filter_rules(&self, new_rules: Vec<FilterRule>) -> Result<()> {
        info!("动态更新过滤规则，规则数量: {}", new_rules.len());

        let event = ConfigUpdateEvent::FilterRulesUpdated {
            rules: new_rules.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // 发送更新事件
        self.send_event(event).await?;

        // 更新配置
        {
            let mut config = self.config.write().await;
            config.filters = new_rules;
        }

        // 更新缓存
        self.update_rule_cache().await;

        // 更新统计
        self.update_stats_success().await;

        info!("过滤规则更新成功");
        Ok(())
    }

    /// 动态添加单个过滤规则
    pub async fn add_filter_rule(&self, rule: FilterRule) -> Result<()> {
        info!("动态添加过滤规则: {}", rule.name);

        let event = ConfigUpdateEvent::FilterRuleAdded {
            rule: rule.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.send_event(event).await?;

        // 添加到配置
        {
            let mut config = self.config.write().await;
            config.filters.push(rule.clone());
        }

        // 更新缓存
        {
            let mut cache = self.rule_cache.write().await;
            cache.insert(rule.name.clone(), rule.clone());
        }

        self.update_stats_success().await;

        info!("过滤规则添加成功: {}", rule.name);
        Ok(())
    }

    /// 动态移除过滤规则
    pub async fn remove_filter_rule(&self, rule_name: &str) -> Result<()> {
        info!("动态移除过滤规则: {}", rule_name);

        let event = ConfigUpdateEvent::FilterRuleRemoved {
            rule_name: rule_name.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.send_event(event).await?;

        // 从配置中移除
        {
            let mut config = self.config.write().await;
            config.filters.retain(|rule| rule.name != rule_name);
        }

        // 从缓存中移除
        {
            let mut cache = self.rule_cache.write().await;
            cache.remove(rule_name);
        }

        self.update_stats_success().await;

        info!("过滤规则移除成功: {}", rule_name);
        Ok(())
    }

    /// 更新源IP过滤策略
    pub async fn update_source_ip_filter(&self, filter: SourceIpFilter) -> Result<()> {
        info!("更新源IP过滤策略，模式: {}, IP范围数量: {}",
              filter.mode, filter.ip_ranges.len());

        let event = ConfigUpdateEvent::SourceIpFilterUpdated {
            filter: filter.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.send_event(event).await?;

        // 更新所有使用源IP过滤的规则
        {
            let mut config = self.config.write().await;
            for rule in config.filters.iter_mut() {
                if rule.source_ip_filter.is_some() {
                    rule.source_ip_filter = Some(filter.clone());
                }
            }
        }

        // 更新IP过滤器缓存
        self.update_ip_filter_cache(&filter).await;

        self.update_stats_success().await;

        info!("源IP过滤策略更新成功");
        Ok(())
    }

    /// 检查IP是否被允许
    pub async fn is_ip_allowed(&self, ip: u32) -> bool {
        let cache = self.ip_filter_cache.read().await;
        if let Some(&allowed) = cache.get(&ip.to_string()) {
            return allowed;
        }

        // 如果缓存中没有，检查当前配置
        let config = self.config.read().await;
        for rule in &config.filters {
            if let Some(ref source_filter) = rule.source_ip_filter {
                let matches = source_filter.ip_ranges.iter().any(|range| {
                    self.ip_in_range(ip, range)
                });

                let allowed = match source_filter.mode.as_str() {
                    "whitelist" => matches,
                    "blacklist" => !matches,
                    _ => true,
                };

                return allowed;
            }
        }

        true // 默认允许
    }

    /// 获取当前配置
    pub async fn get_current_config(&self) -> Config {
        self.config.read().await.clone()
    }

    /// 获取更新统计信息
    pub async fn get_stats(&self) -> ConfigUpdateStats {
        let mut stats = self.stats.read().await.clone();

        // 更新当前统计
        let config = self.config.read().await;
        stats.active_filters = config.filters.len();

        // 统计IP过滤规则中的IP数量
        stats.blocked_ips = 0;
        stats.allowed_ips = 0;
        for rule in &config.filters {
            if let Some(ref source_filter) = rule.source_ip_filter {
                match source_filter.mode.as_str() {
                    "whitelist" => stats.allowed_ips += source_filter.ip_ranges.len(),
                    "blacklist" => stats.blocked_ips += source_filter.ip_ranges.len(),
                    _ => {}
                }
            }
        }

        stats
    }

    /// 获取配置历史
    pub async fn get_config_history(&self) -> Vec<ConfigUpdateEvent> {
        let history = self.config_history.read().await;
        history.clone()
    }

    // 内部方法

    /// 初始化缓存
    async fn initialize_caches(&self) -> Result<()> {
        info!("初始化配置缓存");

        // 更新规则缓存
        self.update_rule_cache().await;

        // 更新IP过滤缓存
        let config = self.config.read().await;
        for rule in &config.filters {
            if let Some(ref source_filter) = rule.source_ip_filter {
                self.update_ip_filter_cache(source_filter).await;
            }
        }

        info!("配置缓存初始化完成");
        Ok(())
    }

    /// 更新规则缓存
    async fn update_rule_cache(&self) {
        let mut cache = self.rule_cache.write().await;
        let config = self.config.read().await;

        cache.clear();
        for rule in &config.filters {
            cache.insert(rule.name.clone(), rule.clone());
        }
    }

    /// 更新IP过滤缓存
    async fn update_ip_filter_cache(&self, filter: &SourceIpFilter) {
        let mut cache = self.ip_filter_cache.write().await;

        for range in &filter.ip_ranges {
            // 解析CIDR范围并缓存
            if let Some((start_ip, end_ip)) = self.parse_cidr_range(range) {
                for ip in start_ip..=end_ip {
                    let allowed = match filter.mode.as_str() {
                        "whitelist" => true,
                        "blacklist" => false,
                        _ => true,
                    };
                    cache.insert(ip.to_string(), allowed);
                }
            }
        }
    }

    /// 解析CIDR范围
    fn parse_cidr_range(&self, cidr: &str) -> Option<(u32, u32)> {
        let parts: Vec<&str> = cidr.split('/').collect::<Vec<_>>();
        if parts.len() != 2 {
            return None;
        }

        let base_ip = parts[0].parse::<std::net::Ipv4Addr>().ok()?;
        let prefix_len = parts[1].parse::<u32>().ok()?;

        if prefix_len > 32 {
            return None;
        }

        let base_ip_num = u32::from(base_ip);
        let mask = if prefix_len == 0 {
            0u32
        } else {
            u32::MAX << (32 - prefix_len)
        };

        let start_ip = base_ip_num & mask;
        let end_ip = start_ip | !mask;

        Some((start_ip, end_ip))
    }

    /// 检查IP是否在范围内
    fn ip_in_range(&self, ip: u32, cidr: &str) -> bool {
        if let Some((start_ip, end_ip)) = self.parse_cidr_range(cidr) {
            ip >= start_ip && ip <= end_ip
        } else {
            false
        }
    }

    /// 发送配置更新事件
    async fn send_event(&self, event: ConfigUpdateEvent) -> Result<()> {
        self.event_sender
            .send(event)
            .map_err(|e| TlsKeyAgentError::Config(format!("发送配置更新事件失败: {}", e)))?;
        Ok(())
    }

    /// 启动事件处理器
    async fn start_event_processor(&self) {
        let event_receiver = self.event_receiver.clone();
        let processors = self.processors.clone();
        let config_history = self.config_history.clone();
        let max_history_size = self.max_history_size;
        let stats = self.stats.clone();

        tokio::spawn(async move {
            let mut receiver = {
                let mut guard = event_receiver.write().await;
                guard.take().unwrap() // 取出接收器
            };

            info!("配置事件处理器已启动");

            while let Some(event) = receiver.recv().await {
                debug!("处理配置更新事件: {:?}", std::mem::discriminant(&event));

                // 更新处理器配置
                match &event {
                    ConfigUpdateEvent::FilterRulesUpdated { rules, .. } => {
                        let processors_guard = processors.read().await;
                        for processor in processors_guard.iter() {
                            processor.update_filter_rules(rules.clone()).await;
                        }
                    }
                    ConfigUpdateEvent::FilterRuleAdded { .. } => {
                        // 对于单个规则添加，需要重新获取完整规则列表
                        // 这里简化处理，实际可以通过更精细的事件处理来优化
                    }
                    ConfigUpdateEvent::FilterRuleRemoved { .. } => {
                        // 类似上面，需要重新获取完整规则列表
                    }
                    ConfigUpdateEvent::SourceIpFilterUpdated { .. } => {
                        // 更新源IP过滤器需要重新构建规则列表
                    }
                    ConfigUpdateEvent::GlobalConfigUpdated { config, .. } => {
                        let processors_guard = processors.read().await;
                        for processor in processors_guard.iter() {
                            processor.update_filter_rules(config.filters.clone()).await;
                        }
                    }
                }

                // 添加到历史记录
                {
                    let mut history = config_history.write().await;
                    history.push(event.clone());

                    // 限制历史记录大小
                    if history.len() > max_history_size {
                        history.remove(0);
                    }
                }

                // 更新统计
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_updates += 1;
                    stats_guard.last_update_time = Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                    );
                }
            }

            info!("配置事件处理器已停止");
        });
    }

    /// 启动缓存清理任务
    async fn start_cache_cleanup_task(&self) {
        let _rule_cache = self.rule_cache.clone();
        let ip_filter_cache = self.ip_filter_cache.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 每5分钟清理一次

            loop {
                interval.tick().await;

                debug!("清理配置缓存");

                // 清理IP过滤缓存（简化实现，实际可以根据策略保留常用IP）
                {
                    let mut cache = ip_filter_cache.write().await;
                    if cache.len() > 10000 { // 如果缓存过大，清空重建
                        cache.clear();
                        debug!("IP过滤缓存过大，已清空");
                    }
                }

                // 规则缓存通常不需要清理，因为规则数量有限
                debug!("配置缓存清理完成");
            }
        });
    }

    /// 更新成功统计
    async fn update_stats_success(&self) {
        let mut stats = self.stats.write().await;
        stats.successful_updates += 1;
        stats.last_update_time = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        stats.last_error = None;
    }

    /// 更新失败统计
    #[allow(dead_code)]
    async fn update_stats_failure(&self, error: String) {
        let mut stats = self.stats.write().await;
        stats.failed_updates += 1;
        stats.last_error = Some(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Protocol;

    #[tokio::test]
    async fn test_dynamic_config_manager_creation() {
        let config = Arc::new(Config::default());
        let manager = DynamicConfigManager::new(config);

        assert!(!manager.is_running.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_filter_rule_addition() {
        let config = Arc::new(Config::default());
        let manager = DynamicConfigManager::new(config);

        let rule = FilterRule {
            name: "test_rule".to_string(),
            enabled: true,
            five_tuple: FiveTupleFilter {
                src_ip: None,
                src_port: None,
                dst_ip: None,
                dst_port: Some(443),
                protocol: Some(Protocol::TCP),
            },
            process_name: None,
            pid: None,
            source_ip_filter: None,
            priority: 100,
        };

        let result = manager.add_filter_rule(rule).await;
        assert!(result.is_ok());

        let current_config = manager.get_current_config().await;
        assert_eq!(current_config.filters.len(), 2); // 默认有一个规则
    }

    #[tokio::test]
    async fn test_ip_filter_parsing() {
        let config = Arc::new(Config::default());
        let manager = DynamicConfigManager::new(config);

        // 测试单个IP
        let allowed = manager.is_ip_allowed(0x7F000001).await; // 127.0.0.1
        assert!(allowed); // 默认允许

        // 测试CIDR解析
        let ip_range = manager.parse_cidr_range("192.168.1.0/24");
        assert!(ip_range.is_some());
        let (start, end) = ip_range.unwrap();
        assert_eq!(start, 0xC0A80100); // 192.168.1.0
        assert_eq!(end, 0xC0A801FF);   // 192.168.1.255
    }
}