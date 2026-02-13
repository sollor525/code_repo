/**
 * @file system_monitor.rs
 * @brief 系统级监控和统计管理器 - 统一收集和分析系统运行数据
 * @author sollor525@hotmail.com
 * @version 2.0.0 - eBPF内核级SSL Hook
 * @date 2023-12-01
 */

use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc};
use tracing::{info, error, debug, warn};
use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::common::error::TlsKeyAgentError;
use crate::injector::ebpf::{EbpfSslHook, EbpfSslHookStats};
use crate::extractor::ssl_hook::{SslHookProcessor, SslHookProcessorStats};
use crate::transport::enhanced_udp_manager::{EnhancedUdpTransportManager, EnhancedTransportStats};
use crate::config::dynamic_config_manager::{DynamicConfigManager, ConfigUpdateStats};

/// 系统监控级别
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MonitorLevel {
    Basic,      // 基础统计
    Detailed,   // 详细统计
    Full,       // 完整统计
    Debug,      // 调试级别
}

/// 监控指标类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    Counter,    // 计数器
    Gauge,      // 仪表盘
    Histogram,  // 直方图
    Timer,      // 计时器
}

/// 监控指标定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub metric_type: MetricType,
    pub description: String,
    pub unit: String,
    pub labels: HashMap<String, String>,
    pub value: f64,
    pub timestamp: u64,
}

/// 系统资源使用统计
#[derive(Debug, Clone, Default)]
pub struct SystemResourceStats {
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: f64,
    pub memory_usage_percent: f64,
    pub disk_usage_mb: f64,
    pub disk_usage_percent: f64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub open_file_descriptors: u32,
    pub thread_count: u32,
    pub uptime_seconds: u64,
}

/// 综合系统统计信息
#[derive(Debug, Clone, Default)]
pub struct SystemStats {
    // 时间戳
    pub timestamp: u64,
    pub uptime: Duration,

    // eBPF Hook统计
    pub ebpf_stats: EbpfSslHookStats,

    // SSL处理器统计
    pub ssl_processor_stats: SslHookProcessorStats,

    // 传输统计
    pub transport_stats: EnhancedTransportStats,

    // 配置管理统计
    pub config_stats: ConfigUpdateStats,

    // 系统资源统计
    pub resource_stats: SystemResourceStats,

    // 自定义指标
    pub custom_metrics: Vec<Metric>,

    // 性能指标
    pub total_events_processed: u64,
    pub events_per_second: f64,
    pub average_processing_time_ms: f64,
    pub error_rate_percent: f64,
}

/// 监控配置
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// 监控级别
    pub level: MonitorLevel,
    /// 统计报告间隔（秒）
    pub report_interval_secs: u64,
    /// 是否启用实时监控
    pub enable_real_time: bool,
    /// 是否启用历史数据存储
    pub enable_history: bool,
    /// 历史数据保留天数
    pub history_retention_days: u32,
    /// 性能阈值告警
    pub alert_thresholds: AlertThresholds,
    /// 自定义指标
    pub custom_metrics: Vec<MetricDefinition>,
}

/// 告警阈值
#[derive(Debug, Clone)]
pub struct AlertThresholds {
    pub cpu_usage_warning: f64,      // CPU使用率警告阈值
    pub cpu_usage_critical: f64,     // CPU使用率严重阈值
    pub memory_usage_warning: f64,   // 内存使用率警告阈值
    pub memory_usage_critical: f64,  // 内存使用率严重阈值
    pub error_rate_warning: f64,     // 错误率警告阈值
    pub error_rate_critical: f64,    // 错误率严重阈值
    pub latency_warning: f64,        // 延迟警告阈值(ms)
    pub latency_critical: f64,       // 延迟严重阈值(ms)
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            cpu_usage_warning: 70.0,
            cpu_usage_critical: 90.0,
            memory_usage_warning: 75.0,
            memory_usage_critical: 90.0,
            error_rate_warning: 5.0,
            error_rate_critical: 10.0,
            latency_warning: 100.0,
            latency_critical: 500.0,
        }
    }
}

/// 自定义指标定义
#[derive(Debug, Clone)]
pub struct MetricDefinition {
    pub name: String,
    pub metric_type: MetricType,
    pub description: String,
    pub unit: String,
    pub labels: HashMap<String, String>,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            level: MonitorLevel::Detailed,
            report_interval_secs: 60,
            enable_real_time: true,
            enable_history: true,
            history_retention_days: 7,
            alert_thresholds: AlertThresholds::default(),
            custom_metrics: Vec::new(),
        }
    }
}

/// 系统监控管理器
pub struct SystemMonitor {
    config: MonitorConfig,
    is_running: AtomicBool,
    start_time: Instant,

    // 组件引用
    ebpf_hook: Option<Arc<EbpfSslHook>>,
    ssl_processor: Option<Arc<SslHookProcessor>>,
    transport_manager: Option<Arc<EnhancedUdpTransportManager>>,
    config_manager: Option<Arc<DynamicConfigManager>>,

    // 统计数据
    current_stats: Arc<RwLock<SystemStats>>,
    historical_stats: Arc<RwLock<Vec<SystemStats>>>,
    custom_metrics: Arc<RwLock<HashMap<String, Metric>>>,

    // 事件通道
    metric_sender: mpsc::UnboundedSender<Metric>,
    metric_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<Metric>>>>,

    // 告警状态
    active_alerts: Arc<RwLock<HashMap<String, Alert>>>,

    // 统计计数器
    total_processed: AtomicU64,
    last_report_time: Arc<RwLock<Instant>>,
}

/// 告警信息
#[derive(Debug, Clone)]
pub struct Alert {
    pub name: String,
    pub level: AlertLevel,
    pub message: String,
    pub current_value: f64,
    pub threshold: f64,
    pub timestamp: u64,
    pub resolved: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AlertLevel {
    Warning,
    Critical,
}

impl SystemMonitor {
    /// 创建新的系统监控器
    pub fn new(config: MonitorConfig) -> Self {
        let (metric_sender, metric_receiver) = mpsc::unbounded_channel::<Metric>();

        Self {
            config,
            is_running: AtomicBool::new(false),
            start_time: Instant::now(),
            ebpf_hook: None,
            ssl_processor: None,
            transport_manager: None,
            config_manager: None,
            current_stats: Arc::new(RwLock::new(SystemStats::default())),
            historical_stats: Arc::new(RwLock::new(Vec::new())),
            custom_metrics: Arc::new(RwLock::new(HashMap::new())),
            metric_sender,
            metric_receiver: Arc::new(RwLock::new(Some(metric_receiver))),
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
            total_processed: AtomicU64::new(0),
            last_report_time: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// 注册eBPF Hook
    pub fn register_ebpf_hook(&mut self, hook: Arc<EbpfSslHook>) {
        self.ebpf_hook = Some(hook);
        info!("注册eBPF Hook到系统监控器");
    }

    /// 注册SSL处理器
    pub fn register_ssl_processor(&mut self, processor: Arc<SslHookProcessor>) {
        self.ssl_processor = Some(processor);
        info!("注册SSL处理器到系统监控器");
    }

    /// 注册传输管理器
    pub fn register_transport_manager(&mut self, manager: Arc<EnhancedUdpTransportManager>) {
        self.transport_manager = Some(manager);
        info!("注册传输管理器到系统监控器");
    }

    /// 注册配置管理器
    pub fn register_config_manager(&mut self, manager: Arc<DynamicConfigManager>) {
        self.config_manager = Some(manager);
        info!("注册配置管理器到系统监控器");
    }

    /// 启动系统监控
    pub async fn start(&self) -> Result<()> {
        if self.is_running.load(Ordering::SeqCst) {
            warn!("系统监控器已在运行");
            return Ok(());
        }

        info!("启动系统级监控器");

        // 启动指标收集器
        self.start_metric_collector().await;

        // 启动统计报告器
        if self.config.enable_real_time {
            self.start_stats_reporter().await;
        }

        // 启动告警检查器
        self.start_alert_checker().await;

        // 启动历史数据管理器
        if self.config.enable_history {
            self.start_history_manager().await;
        }

        self.is_running.store(true, Ordering::SeqCst);
        info!("系统级监控器启动成功");
        Ok(())
    }

    /// 停止系统监控
    pub async fn stop(&self) -> Result<()> {
        if !self.is_running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("停止系统级监控器");
        self.is_running.store(false, Ordering::SeqCst);
        info!("系统级监控器已停止");
        Ok(())
    }

    /// 记录自定义指标
    pub fn record_metric(&self, metric: Metric) -> Result<()> {
        self.metric_sender
            .send(metric)
            .map_err(|e| TlsKeyAgentError::Monitoring(format!("发送指标失败: {}", e)))?;
        Ok(())
    }

    /// 增加计数器
    pub fn increment_counter(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        let metric = Metric {
            name: name.to_string(),
            metric_type: MetricType::Counter,
            description: String::new(),
            unit: String::new(),
            labels,
            value,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.record_metric(metric)
    }

    /// 设置仪表盘值
    pub fn set_gauge(&self, name: &str, value: f64, labels: HashMap<String, String>) -> Result<()> {
        let metric = Metric {
            name: name.to_string(),
            metric_type: MetricType::Gauge,
            description: String::new(),
            unit: String::new(),
            labels,
            value,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.record_metric(metric)
    }

    /// 记录计时器
    pub fn record_timer(&self, name: &str, duration_ms: f64, labels: HashMap<String, String>) -> Result<()> {
        let metric = Metric {
            name: name.to_string(),
            metric_type: MetricType::Timer,
            description: String::new(),
            unit: "ms".to_string(),
            labels,
            value: duration_ms,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.record_metric(metric)
    }

    /// 获取当前系统统计
    pub async fn get_current_stats(&self) -> SystemStats {
        self.update_system_stats().await;
        self.current_stats.read().await.clone()
    }

    /// 获取历史统计
    pub async fn get_historical_stats(&self, hours: u32) -> Vec<SystemStats> {
        let history = self.historical_stats.read().await;
        let cutoff_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() - (hours as u64 * 3600);

        history
            .iter()
            .filter(|stats| stats.timestamp >= cutoff_time)
            .cloned()
            .collect()
    }

    /// 获取活跃告警
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        self.active_alerts.read().await.values().cloned().collect()
    }

    /// 生成监控报告
    pub async fn generate_report(&self) -> MonitoringReport {
        let stats = self.get_current_stats().await;
        let alerts = self.get_active_alerts().await;

        MonitoringReport {
            timestamp: stats.timestamp,
            uptime: stats.uptime,
            system_stats: stats.clone(),
            alerts,
            performance_summary: PerformanceSummary {
                events_per_second: stats.events_per_second,
                average_processing_time: stats.average_processing_time_ms,
                error_rate: stats.error_rate_percent,
                resource_utilization: ResourceUtilization {
                    cpu_usage: stats.resource_stats.cpu_usage_percent,
                    memory_usage: stats.resource_stats.memory_usage_percent,
                    disk_usage: stats.resource_stats.disk_usage_percent,
                },
            },
        }
    }

    // 内部方法

    /// 更新系统统计
    async fn update_system_stats(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let uptime = self.start_time.elapsed();

        // 收集各组件统计
        let ebpf_stats = if let Some(ref _hook) = self.ebpf_hook {
            // 这里需要实现获取eBPF统计的方法
            // 目前使用默认值
            EbpfSslHookStats::default()
        } else {
            EbpfSslHookStats::default()
        };

        let ssl_processor_stats = if let Some(ref processor) = self.ssl_processor {
            processor.get_stats().await
        } else {
            SslHookProcessorStats::default()
        };

        let transport_stats = if let Some(ref manager) = self.transport_manager {
            manager.get_enhanced_stats().await
        } else {
            EnhancedTransportStats::default()
        };

        let config_stats = if let Some(ref manager) = self.config_manager {
            manager.get_stats().await
        } else {
            ConfigUpdateStats::default()
        };

        let resource_stats = self.collect_system_resources().await;

        let custom_metrics = self.custom_metrics.read().await.values().cloned().collect();

        let total_processed = self.total_processed.load(Ordering::SeqCst);
        let elapsed = self.last_report_time.read().await.elapsed().as_secs_f64();
        let events_per_second = if elapsed > 0.0 {
            total_processed as f64 / elapsed
        } else {
            0.0
        };

        let system_stats = SystemStats {
            timestamp: now,
            uptime,
            ebpf_stats,
            ssl_processor_stats,
            transport_stats,
            config_stats,
            resource_stats,
            custom_metrics,
            total_events_processed: total_processed,
            events_per_second,
            average_processing_time_ms: 0.0, // 需要计算
            error_rate_percent: 0.0, // 需要计算
        };

        let mut current = self.current_stats.write().await;
        *current = system_stats;

        self.total_processed.store(total_processed + 1, Ordering::SeqCst);
    }

    /// 收集系统资源信息
    async fn collect_system_resources(&self) -> SystemResourceStats {
        // 简化实现，实际应该使用系统调用获取真实数据
        SystemResourceStats {
            cpu_usage_percent: 25.0,
            memory_usage_mb: 128.0,
            memory_usage_percent: 15.0,
            disk_usage_mb: 1024.0,
            disk_usage_percent: 5.0,
            network_rx_bytes: 0,
            network_tx_bytes: 0,
            open_file_descriptors: 50,
            thread_count: 8,
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }

    /// 启动指标收集器
    async fn start_metric_collector(&self) {
        let metric_receiver = self.metric_receiver.clone();
        let custom_metrics = self.custom_metrics.clone();

        tokio::spawn(async move {
            let mut receiver = {
                let mut guard = metric_receiver.write().await;
                guard.take().unwrap()
            };

            info!("指标收集器已启动");

            while let Some(metric) = receiver.recv().await {
                let mut metrics = custom_metrics.write().await;
                metrics.insert(metric.name.clone(), metric);
            }

            info!("指标收集器已停止");
        });
    }

    /// 启动统计报告器
    async fn start_stats_reporter(&self) {
        let monitor_config = self.config.clone();
        let current_stats = self.current_stats.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(monitor_config.report_interval_secs));

            loop {
                interval.tick().await;

                let stats = current_stats.read().await;
                info!(
                    "系统监控报告 - 事件/秒: {:.1}, 延迟: {:.1}ms, CPU: {:.1}%, 内存: {:.1}%, 错误率: {:.1}%",
                    stats.events_per_second,
                    stats.average_processing_time_ms,
                    stats.resource_stats.cpu_usage_percent,
                    stats.resource_stats.memory_usage_percent,
                    stats.error_rate_percent
                );
            }
        });
    }

    /// 启动告警检查器
    async fn start_alert_checker(&self) {
        let alert_thresholds = self.config.alert_thresholds.clone();
        let current_stats = self.current_stats.clone();
        let active_alerts = self.active_alerts.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30)); // 每30秒检查一次

            loop {
                interval.tick().await;

                let stats = current_stats.read().await;
                let mut alerts = active_alerts.write().await;

                // 检查CPU使用率
                if stats.resource_stats.cpu_usage_percent > alert_thresholds.cpu_usage_critical {
                    let alert = Alert {
                        name: "cpu_usage_critical".to_string(),
                        level: AlertLevel::Critical,
                        message: format!("CPU使用率严重过高: {:.1}%", stats.resource_stats.cpu_usage_percent),
                        current_value: stats.resource_stats.cpu_usage_percent,
                        threshold: alert_thresholds.cpu_usage_critical,
                        timestamp: stats.timestamp,
                        resolved: false,
                    };
                    alerts.insert("cpu_usage_critical".to_string(), alert);
                    warn!("CPU使用率严重告警: {:.1}%", stats.resource_stats.cpu_usage_percent);
                } else if stats.resource_stats.cpu_usage_percent > alert_thresholds.cpu_usage_warning {
                    let alert = Alert {
                        name: "cpu_usage_warning".to_string(),
                        level: AlertLevel::Warning,
                        message: format!("CPU使用率过高: {:.1}%", stats.resource_stats.cpu_usage_percent),
                        current_value: stats.resource_stats.cpu_usage_percent,
                        threshold: alert_thresholds.cpu_usage_warning,
                        timestamp: stats.timestamp,
                        resolved: false,
                    };
                    alerts.insert("cpu_usage_warning".to_string(), alert);
                    warn!("CPU使用率警告: {:.1}%", stats.resource_stats.cpu_usage_percent);
                }

                // 检查内存使用率
                if stats.resource_stats.memory_usage_percent > alert_thresholds.memory_usage_critical {
                    let alert = Alert {
                        name: "memory_usage_critical".to_string(),
                        level: AlertLevel::Critical,
                        message: format!("内存使用率严重过高: {:.1}%", stats.resource_stats.memory_usage_percent),
                        current_value: stats.resource_stats.memory_usage_percent,
                        threshold: alert_thresholds.memory_usage_critical,
                        timestamp: stats.timestamp,
                        resolved: false,
                    };
                    alerts.insert("memory_usage_critical".to_string(), alert);
                    error!("内存使用率严重告警: {:.1}%", stats.resource_stats.memory_usage_percent);
                }
            }
        });
    }

    /// 启动历史数据管理器
    async fn start_history_manager(&self) {
        let current_stats = self.current_stats.clone();
        let historical_stats = self.historical_stats.clone();
        let retention_days = self.config.history_retention_days;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 每5分钟记录一次

            loop {
                interval.tick().await;

                let current = current_stats.read().await;
                let mut history = historical_stats.write().await;

                history.push(current.clone());

                // 清理过期数据
                let cutoff_timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() - (retention_days as u64 * 86400);

                history.retain(|stats| stats.timestamp >= cutoff_timestamp);

                debug!("历史数据记录完成，当前历史记录数: {}", history.len());
            }
        });
    }
}

/// 监控报告
#[derive(Debug, Clone)]
pub struct MonitoringReport {
    pub timestamp: u64,
    pub uptime: Duration,
    pub system_stats: SystemStats,
    pub alerts: Vec<Alert>,
    pub performance_summary: PerformanceSummary,
}

/// 性能摘要
#[derive(Debug, Clone)]
pub struct PerformanceSummary {
    pub events_per_second: f64,
    pub average_processing_time: f64,
    pub error_rate: f64,
    pub resource_utilization: ResourceUtilization,
}

/// 资源利用率
#[derive(Debug, Clone)]
pub struct ResourceUtilization {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_config_default() {
        let config = MonitorConfig::default();
        assert_eq!(config.level, MonitorLevel::Detailed);
        assert_eq!(config.report_interval_secs, 60);
        assert!(config.enable_real_time);
        assert!(config.enable_history);
    }

    #[test]
    fn test_alert_thresholds_default() {
        let thresholds = AlertThresholds::default();
        assert_eq!(thresholds.cpu_usage_warning, 70.0);
        assert_eq!(thresholds.cpu_usage_critical, 90.0);
        assert_eq!(thresholds.memory_usage_warning, 75.0);
        assert_eq!(thresholds.memory_usage_critical, 90.0);
    }

    #[tokio::test]
    async fn test_system_monitor_creation() {
        let config = MonitorConfig::default();
        let monitor = SystemMonitor::new(config);

        assert!(!monitor.is_running.load(Ordering::SeqCst));

        // 测试指标记录
        let result = monitor.increment_counter("test_counter", 1.0, HashMap::new());
        assert!(result.is_ok());

        let result = monitor.set_gauge("test_gauge", 42.0, HashMap::new());
        assert!(result.is_ok());

        let result = monitor.record_timer("test_timer", 100.0, HashMap::new());
        assert!(result.is_ok());
    }
}