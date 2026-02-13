/**
 * @file performance_monitor.rs
 * @brief 性能监控和告警系统
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-12-15
 */

use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::{info, warn, error, debug};


/// 性能指标类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    /// 计数器
    Counter,
    /// 测量值
    Gauge,
    /// 直方图
    Histogram,
    /// 摘要
    Summary,
}

/// 性能指标
#[derive(Debug, Clone)]
pub struct Metric {
    pub name: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub timestamp: Instant,
    pub labels: HashMap<String, String>,
    pub help: String,
}

/// 告警级别
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertLevel {
    /// 信息
    Info = 1,
    /// 警告
    Warning = 2,
    /// 错误
    Error = 3,
    /// 关键
    Critical = 4,
}

/// 告警规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub name: String,
    pub metric_name: String,
    pub condition: AlertCondition,
    pub threshold: f64,
    pub duration: Duration,
    pub level: AlertLevel,
    pub enabled: bool,
    pub labels: HashMap<String, String>,
    pub description: String,
}

/// 告警条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    /// 大于
    GreaterThan,
    /// 小于
    LessThan,
    /// 等于
    Equal,
    /// 不等于
    NotEqual,
    /// 大于等于
    GreaterThanOrEqual,
    /// 小于等于
    LessThanOrEqual,
}

/// 告警状态
#[derive(Debug, Clone, PartialEq)]
pub enum AlertStatus {
    /// 正常
    Normal,
    /// 触发中
    Firing,
    /// 已解决
    Resolved,
}

/// 告警事件
#[derive(Debug, Clone)]
pub struct AlertEvent {
    pub rule_id: String,
    pub level: AlertLevel,
    pub status: AlertStatus,
    pub message: String,
    pub metric_value: f64,
    pub timestamp: Instant,
    pub labels: HashMap<String, String>,
}

/// 性能统计信息
#[derive(Debug, Clone, Default)]
pub struct PerformanceStats {
    pub total_metrics: u64,
    pub total_alerts: u64,
    pub active_alerts: u32,
    pub metrics_per_second: f64,
    pub alerts_per_minute: f64,
    pub average_response_time: Duration,
    pub memory_usage: u64,
    pub cpu_usage: f64,
}

/// 性能监控配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMonitorConfig {
    pub enabled: bool,
    pub metrics_retention_period: Duration,
    pub alert_check_interval: Duration,
    pub max_metrics: usize,
    pub enable_auto_cleanup: bool,
    pub enable_system_metrics: bool,
    pub enable_alerting: bool,
}

impl Default for PerformanceMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            metrics_retention_period: Duration::from_secs(3600), // 1 hour
            alert_check_interval: Duration::from_secs(30), // 30 seconds
            max_metrics: 100000,
            enable_auto_cleanup: true,
            enable_system_metrics: true,
            enable_alerting: true,
        }
    }
}

/// 性能监控器
pub struct PerformanceMonitor {
    config: Arc<PerformanceMonitorConfig>,
    metrics: Arc<RwLock<HashMap<String, Vec<Metric>>>>,
    alert_rules: Arc<RwLock<HashMap<String, AlertRule>>>,
    alert_states: Arc<RwLock<HashMap<String, AlertState>>>,
    alert_events: mpsc::UnboundedSender<AlertEvent>,
    alert_events_receiver: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<AlertEvent>>>,
    stats: Arc<RwLock<PerformanceStats>>,
    system_metrics_collector: Option<Arc<SystemMetricsCollector>>,
}

/// 告警状态跟踪
#[derive(Debug)]
pub struct AlertState {
    rule_id: String,
    status: AlertStatus,
    first_triggered: Instant,
    last_triggered: Instant,
    trigger_count: u32,
    last_metric_value: f64,
}

/// 系统指标收集器
pub struct SystemMetricsCollector {
    enabled: bool,
    collection_interval: Duration,
}

impl Default for Metric {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            metric_type: MetricType::Gauge,
            value: 0.0,
            timestamp: Instant::now(),
            labels: HashMap::new(),
            help: "Default metric".to_string(),
        }
    }
}

impl Default for AlertRule {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            name: "Default Alert".to_string(),
            metric_name: "default".to_string(),
            condition: AlertCondition::GreaterThan,
            threshold: 0.0,
            duration: Duration::from_secs(60),
            level: AlertLevel::Warning,
            enabled: true,
            labels: HashMap::new(),
            description: "Default alert rule".to_string(),
        }
    }
}

impl PerformanceMonitor {
    pub fn new(config: PerformanceMonitorConfig) -> Result<Self> {
        let (alert_events, alert_events_receiver) = mpsc::unbounded_channel();

        let system_metrics_collector = if config.enable_system_metrics {
            Some(Arc::new(SystemMetricsCollector {
                enabled: true,
                collection_interval: Duration::from_secs(10),
            }))
        } else {
            None
        };

        let monitor = Self {
            config: Arc::new(config),
            metrics: Arc::new(RwLock::new(HashMap::new())),
            alert_rules: Arc::new(RwLock::new(HashMap::new())),
            alert_states: Arc::new(RwLock::new(HashMap::new())),
            alert_events,
            alert_events_receiver: Arc::new(tokio::sync::Mutex::new(alert_events_receiver)),
            stats: Arc::new(RwLock::new(PerformanceStats::default())),
            system_metrics_collector,
        };

        Ok(monitor)
    }

    /// 记录指标
    pub async fn record_metric(&self, metric: Metric) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        debug!("记录性能指标: {} = {}", metric.name, metric.value);

        {
            let mut metrics = self.metrics.write().await;
            let metric_list = metrics.entry(metric.name.clone()).or_insert_with(Vec::new);
            metric_list.push(metric.clone());

            // 限制指标数量
            if metric_list.len() > self.config.max_metrics {
                metric_list.remove(0);
            }
        }

        // 更新统计信息
        {
            let mut stats = self.stats.write().await;
            stats.total_metrics += 1;
        }

        // 检查告警规则
        if self.config.enable_alerting {
            self.check_alert_rules(&metric).await?;
        }

        Ok(())
    }

    /// 记录计数器指标
    pub async fn record_counter(&self, name: &str, value: f64, labels: Option<HashMap<String, String>>) -> Result<()> {
        let metric = Metric {
            name: name.to_string(),
            metric_type: MetricType::Counter,
            value,
            timestamp: Instant::now(),
            labels: labels.unwrap_or_default(),
            help: format!("Counter metric: {}", name),
        };
        self.record_metric(metric).await
    }

    /// 记录测量值指标
    pub async fn record_gauge(&self, name: &str, value: f64, labels: Option<HashMap<String, String>>) -> Result<()> {
        let metric = Metric {
            name: name.to_string(),
            metric_type: MetricType::Gauge,
            value,
            timestamp: Instant::now(),
            labels: labels.unwrap_or_default(),
            help: format!("Gauge metric: {}", name),
        };
        self.record_metric(metric).await
    }

    /// 记录直方图指标
    pub async fn record_histogram(&self, name: &str, value: f64, labels: Option<HashMap<String, String>>) -> Result<()> {
        let metric = Metric {
            name: name.to_string(),
            metric_type: MetricType::Histogram,
            value,
            timestamp: Instant::now(),
            labels: labels.unwrap_or_default(),
            help: format!("Histogram metric: {}", name),
        };
        self.record_metric(metric).await
    }

    /// 添加告警规则
    pub async fn add_alert_rule(&self, rule: AlertRule) -> Result<()> {
        info!("添加告警规则: {}", rule.name);

        {
            let mut alert_rules = self.alert_rules.write().await;
            alert_rules.insert(rule.id.clone(), rule.clone());
        }

        // 初始化告警状态
        {
            let mut alert_states = self.alert_states.write().await;
            alert_states.insert(rule.id.clone(), AlertState {
                rule_id: rule.id.clone(),
                status: AlertStatus::Normal,
                first_triggered: Instant::now(),
                last_triggered: Instant::now(),
                trigger_count: 0,
                last_metric_value: 0.0,
            });
        }

        Ok(())
    }

    /// 移除告警规则
    pub async fn remove_alert_rule(&self, rule_id: &str) -> Result<()> {
        info!("移除告警规则: {}", rule_id);

        {
            let mut alert_rules = self.alert_rules.write().await;
            alert_rules.remove(rule_id);
        }

        {
            let mut alert_states = self.alert_states.write().await;
            alert_states.remove(rule_id);
        }

        Ok(())
    }

    /// 检查告警规则
    async fn check_alert_rules(&self, metric: &Metric) -> Result<()> {
        let alert_rules = self.alert_rules.read().await;
        let mut alert_states = self.alert_states.write().await;

        for (rule_id, rule) in alert_rules.iter() {
            if !rule.enabled || rule.metric_name != metric.name {
                continue;
            }

            let alert_triggered = self.evaluate_condition(&rule.condition, metric.value, rule.threshold);

            if let Some(alert_state) = alert_states.get_mut(rule_id) {
                let now = Instant::now();

                if alert_triggered {
                    match alert_state.status {
                        AlertStatus::Normal => {
                            // 首次触发告警
                            alert_state.status = AlertStatus::Firing;
                            alert_state.first_triggered = now;
                            alert_state.last_triggered = now;
                            alert_state.trigger_count = 1;
                            alert_state.last_metric_value = metric.value;

                            // 检查持续时间
                            if now.duration_since(alert_state.first_triggered) >= rule.duration {
                                self.fire_alert(rule, metric, alert_state).await?;
                            }
                        }
                        AlertStatus::Firing => {
                            // 持续触发
                            alert_state.last_triggered = now;
                            alert_state.trigger_count += 1;
                            alert_state.last_metric_value = metric.value;

                            // 再次发送告警事件
                            if now.duration_since(alert_state.first_triggered) >= rule.duration {
                                self.fire_alert(rule, metric, alert_state).await?;
                            }
                        }
                        AlertStatus::Resolved => {
                            // 重新触发
                            alert_state.status = AlertStatus::Firing;
                            alert_state.first_triggered = now;
                            alert_state.last_triggered = now;
                            alert_state.trigger_count = 1;
                            alert_state.last_metric_value = metric.value;

                            if now.duration_since(alert_state.first_triggered) >= rule.duration {
                                self.fire_alert(rule, metric, alert_state).await?;
                            }
                        }
                    }
                } else {
                    match alert_state.status {
                        AlertStatus::Firing => {
                            // 告警恢复
                            alert_state.status = AlertStatus::Resolved;
                            self.resolve_alert(rule, alert_state).await?;
                        }
                        AlertStatus::Normal | AlertStatus::Resolved => {
                            // 保持正常状态
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 评估告警条件
    fn evaluate_condition(&self, condition: &AlertCondition, value: f64, threshold: f64) -> bool {
        match condition {
            AlertCondition::GreaterThan => value > threshold,
            AlertCondition::LessThan => value < threshold,
            AlertCondition::Equal => (value - threshold).abs() < f64::EPSILON,
            AlertCondition::NotEqual => (value - threshold).abs() >= f64::EPSILON,
            AlertCondition::GreaterThanOrEqual => value >= threshold,
            AlertCondition::LessThanOrEqual => value <= threshold,
        }
    }

    /// 触发告警
    async fn fire_alert(&self, rule: &AlertRule, metric: &Metric, _alert_state: &AlertState) -> Result<()> {
        let message = format!(
            "告警触发: {} - {} = {:.2} {} {:.2}",
            rule.name, metric.name, metric.value,
            self.condition_to_string(&rule.condition),
            rule.threshold
        );

        warn!("{}", message);

        let alert_event = AlertEvent {
            rule_id: rule.id.clone(),
            level: rule.level.clone(),
            status: AlertStatus::Firing,
            message,
            metric_value: metric.value,
            timestamp: Instant::now(),
            labels: rule.labels.clone(),
        };

        let _ = self.alert_events.send(alert_event);

        // 更新统计信息
        {
            let mut stats = self.stats.write().await;
            stats.total_alerts += 1;
        }

        Ok(())
    }

    /// 告警恢复
    async fn resolve_alert(&self, rule: &AlertRule, alert_state: &AlertState) -> Result<()> {
        let message = format!(
            "告警恢复: {} - 持续时间: {:.2}s, 触发次数: {}",
            rule.name,
            alert_state.last_triggered.duration_since(alert_state.first_triggered).as_secs_f64(),
            alert_state.trigger_count
        );

        info!("{}", message);

        let alert_event = AlertEvent {
            rule_id: rule.id.clone(),
            level: rule.level.clone(),
            status: AlertStatus::Resolved,
            message,
            metric_value: alert_state.last_metric_value,
            timestamp: Instant::now(),
            labels: rule.labels.clone(),
        };

        let _ = self.alert_events.send(alert_event);

        Ok(())
    }

    /// 条件转换为字符串
    fn condition_to_string(&self, condition: &AlertCondition) -> &'static str {
        match condition {
            AlertCondition::GreaterThan => ">",
            AlertCondition::LessThan => "<",
            AlertCondition::Equal => "==",
            AlertCondition::NotEqual => "!=",
            AlertCondition::GreaterThanOrEqual => ">=",
            AlertCondition::LessThanOrEqual => "<=",
        }
    }

    /// 获取指标数据
    pub async fn get_metrics(&self, metric_name: Option<&str>) -> HashMap<String, Vec<Metric>> {
        let metrics = self.metrics.read().await;

        if let Some(name) = metric_name {
            if let Some(metric_list) = metrics.get(name) {
                let mut result = HashMap::new();
                result.insert(name.to_string(), metric_list.clone());
                return result;
            }
        }

        metrics.clone()
    }

    /// 获取告警规则
    pub async fn get_alert_rules(&self) -> HashMap<String, AlertRule> {
        let alert_rules = self.alert_rules.read().await;
        alert_rules.clone()
    }

    /// 获取告警状态
    pub async fn get_alert_states(&self) -> HashMap<String, AlertState> {
        let alert_states = self.alert_states.read().await;
        alert_states.clone()
    }

    /// 获取性能统计信息
    pub async fn get_stats(&self) -> PerformanceStats {
        let stats = self.stats.read().await;

        // 计算活跃告警数量
        let alert_states = self.alert_states.read().await;
        let active_alerts = alert_states
            .values()
            .filter(|state| state.status == AlertStatus::Firing)
            .count() as u32;

        let mut result = stats.clone();
        result.active_alerts = active_alerts;
        result
    }

    /// 启动性能监控
    pub async fn start(&self) -> Result<()> {
        info!("启动性能监控器");

        // 启动系统指标收集
        if let Some(collector) = &self.system_metrics_collector {
            let collector_clone = collector.clone();
            let monitor_clone = self.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(collector_clone.collection_interval);
                loop {
                    interval.tick().await;
                    if let Err(e) = monitor_clone.collect_system_metrics().await {
                        error!("系统指标收集失败: {}", e);
                    }
                }
            });
        }

        // 启动告警检查
        if self.config.enable_alerting {
            let monitor_clone = self.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(monitor_clone.config.alert_check_interval);
                loop {
                    interval.tick().await;
                    if let Err(e) = monitor_clone.perform_cleanup().await {
                        error!("自动清理失败: {}", e);
                    }
                }
            });
        }

        Ok(())
    }

    /// 收集系统指标
    async fn collect_system_metrics(&self) -> Result<()> {
        if !self.config.enable_system_metrics {
            return Ok(());
        }

        // 收集内存使用情况
        if let Err(e) = self.collect_memory_metrics().await {
            debug!("内存指标收集失败: {}", e);
        }

        // 收集CPU使用情况
        if let Err(e) = self.collect_cpu_metrics().await {
            debug!("CPU指标收集失败: {}", e);
        }

        Ok(())
    }

    /// 收集内存指标
    async fn collect_memory_metrics(&self) -> Result<()> {
        // 简化实现：模拟内存指标收集
        let memory_usage = rand::random::<u64>() % (1024 * 1024 * 1024); // 随机内存使用
        self.record_gauge("system_memory_usage_bytes", memory_usage as f64, None).await?;

        let memory_usage_mb = memory_usage as f64 / (1024.0 * 1024.0);
        self.record_gauge("system_memory_usage_mb", memory_usage_mb, None).await?;

        Ok(())
    }

    /// 收集CPU指标
    async fn collect_cpu_metrics(&self) -> Result<()> {
        // 简化实现：模拟CPU指标收集
        let cpu_usage = rand::random::<f64>() * 100.0; // 随机CPU使用率
        self.record_gauge("system_cpu_usage_percent", cpu_usage, None).await?;

        Ok(())
    }

    /// 执行自动清理
    async fn perform_cleanup(&self) -> Result<()> {
        if !self.config.enable_auto_cleanup {
            return Ok(());
        }

        debug!("执行自动清理任务");

        let now = Instant::now();
        let retention_period = self.config.metrics_retention_period;

        {
            let mut metrics = self.metrics.write().await;
            for (_, metric_list) in metrics.iter_mut() {
                metric_list.retain(|metric| now.duration_since(metric.timestamp) <= retention_period);
            }
        }

        Ok(())
    }

    /// 获取告警事件接收器
    pub fn get_alert_events_receiver(&self) -> mpsc::UnboundedReceiver<AlertEvent> {
        // 注意：这里需要重新创建通道，因为原始接收器被锁在Mutex中
        let (_sender, receiver) = mpsc::unbounded_channel();
        receiver
    }

    /// 重置统计信息
    pub async fn reset_stats(&self) -> Result<()> {
        let mut stats = self.stats.write().await;
        *stats = PerformanceStats::default();
        info!("性能监控统计信息已重置");
        Ok(())
    }
}

// 为了支持 tokio::spawn，需要实现 Clone
impl Clone for PerformanceMonitor {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            alert_rules: self.alert_rules.clone(),
            alert_states: self.alert_states.clone(),
            alert_events: self.alert_events.clone(),
            alert_events_receiver: self.alert_events_receiver.clone(),
            stats: self.stats.clone(),
            system_metrics_collector: self.system_metrics_collector.clone(),
        }
    }
}

impl Clone for AlertState {
    fn clone(&self) -> Self {
        Self {
            rule_id: self.rule_id.clone(),
            status: self.status.clone(),
            first_triggered: self.first_triggered,
            last_triggered: self.last_triggered,
            trigger_count: self.trigger_count,
            last_metric_value: self.last_metric_value,
        }
    }
}

impl Clone for SystemMetricsCollector {
    fn clone(&self) -> Self {
        Self {
            enabled: self.enabled,
            collection_interval: self.collection_interval,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_monitor_creation() {
        let config = PerformanceMonitorConfig::default();
        let monitor = PerformanceMonitor::new(config).unwrap();

        let stats = monitor.get_stats().await;
        assert_eq!(stats.total_metrics, 0);
    }

    #[tokio::test]
    async fn test_metric_recording() {
        let config = PerformanceMonitorConfig::default();
        let monitor = PerformanceMonitor::new(config).unwrap();

        monitor.record_counter("test_counter", 10.0, None).await.unwrap();

        let metrics = monitor.get_metrics(Some("test_counter")).await;
        assert_eq!(metrics.get("test_counter").unwrap().len(), 1);
        assert_eq!(metrics.get("test_counter").unwrap()[0].value, 10.0);
    }

    #[tokio::test]
    async fn test_alert_rule_management() {
        let config = PerformanceMonitorConfig::default();
        let monitor = PerformanceMonitor::new(config).unwrap();

        let rule = AlertRule {
            id: "test_alert".to_string(),
            name: "Test Alert".to_string(),
            metric_name: "test_metric".to_string(),
            condition: AlertCondition::GreaterThan,
            threshold: 5.0,
            duration: Duration::from_secs(10),
            level: AlertLevel::Warning,
            enabled: true,
            labels: HashMap::new(),
            description: "Test alert rule".to_string(),
        };

        monitor.add_alert_rule(rule).await.unwrap();

        let alert_rules = monitor.get_alert_rules().await;
        assert_eq!(alert_rules.len(), 1);
        assert!(alert_rules.contains_key("test_alert"));
    }
}