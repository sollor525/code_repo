use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};
use serde::{Serialize, Deserialize};

use crate::common::error::Result;
use self::error_handler::{ErrorHandler, SystemHealth, ErrorStats, ErrorContext};

pub mod error_handler;

/// 监控管理器，统一管理系统监控功能
pub struct MonitoringManager {
    error_handler: Arc<ErrorHandler>,
    performance_metrics: Arc<RwLock<PerformanceMetrics>>,
    alert_manager: Arc<RwLock<AlertManager>>,
    config: MonitoringConfig,
}

/// 性能指标
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub sessions_processed: u64,
    pub keys_extracted: u64,
    pub processing_time_avg_ms: f64,
    pub memory_usage_mb: f64,
    pub cpu_usage_percent: f64,
    pub network_bytes_sent: u64,
    pub network_bytes_received: u64,
    pub last_updated: u64,
}

/// 警报管理器
#[derive(Debug, Default)]
pub struct AlertManager {
    active_alerts: HashMap<String, Alert>,
    alert_history: Vec<Alert>,
    #[allow(dead_code)]
    alert_rules: Vec<AlertRule>,
}

/// 警报
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub timestamp: u64,
    pub resolved: bool,
    pub context: HashMap<String, String>,
}

/// 警报类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertType {
    HighErrorRate,
    MemoryUsage,
    PerformanceDegradation,
    ConnectionFailure,
    KeyExtractionFailure,
    SystemHealth,
}

/// 警报严重程度
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// 警报规则
#[derive(Debug, Clone)]
pub struct AlertRule {
    pub id: String,
    pub alert_type: AlertType,
    pub condition: AlertCondition,
    pub threshold: f64,
    pub severity: AlertSeverity,
    pub enabled: bool,
}

/// 警报条件
#[derive(Debug, Clone)]
pub enum AlertCondition {
    GreaterThan,
    LessThan,
    Equals,
    RatePerMinute,
}

/// 监控配置
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub metrics_interval_seconds: u64,
    pub health_check_interval_seconds: u64,
    pub alert_cooldown_seconds: u64,
    pub auto_recovery_enabled: bool,
    pub performance_monitoring_enabled: bool,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            metrics_interval_seconds: 30,
            health_check_interval_seconds: 60,
            alert_cooldown_seconds: 300,
            auto_recovery_enabled: true,
            performance_monitoring_enabled: true,
        }
    }
}

impl MonitoringManager {
    pub fn new(config: MonitoringConfig) -> Result<Self> {
        info!("初始化监控管理器");

        let error_handler_config = error_handler::ErrorHandlerConfig::default();
        let error_handler = Arc::new(ErrorHandler::new(error_handler_config));

        let alert_manager = Arc::new(RwLock::new(AlertManager::default()));

        let manager = Self {
            error_handler,
            performance_metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
            alert_manager,
            config,
        };

        // 注册错误回调
        manager.setup_error_callbacks()?;

        Ok(manager)
    }

    /// 启动监控
    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            info!("监控功能已禁用");
            return Ok(());
        }

        info!("启动监控管理器");

        // 启动性能监控
        if self.config.performance_monitoring_enabled {
            self.start_performance_monitoring().await?;
        }

        // 启动健康检查
        self.start_health_monitoring().await?;

        // 启动警报系统
        self.start_alert_monitoring().await?;

        info!("监控管理器启动成功");
        Ok(())
    }

    /// 停止监控
    pub async fn stop(&self) -> Result<()> {
        info!("停止监控管理器");

        // 清理活跃警报
        {
            let mut alert_manager = self.alert_manager.write().await;
            alert_manager.active_alerts.clear();
        }

        info!("监控管理器已停止");
        Ok(())
    }

    /// 设置错误回调
    fn setup_error_callbacks(&self) -> Result<()> {
        let alert_manager = self.alert_manager.clone();

        let _ = self.error_handler.register_error_callback(move |error_record| {
            let alert_manager = alert_manager.clone();
            let error_record = error_record.clone();
            tokio::spawn(async move {
                Self::handle_error_alert(alert_manager, &error_record).await;
            });
        });

        Ok(())
    }

    /// 处理错误警报
    async fn handle_error_alert(
        alert_manager: Arc<RwLock<AlertManager>>,
        error_record: &error_handler::ErrorRecord,
    ) {
        if error_record.severity == error_handler::ErrorSeverity::Critical {
            let alert = Alert {
                id: format!("error-{}", error_record.timestamp),
                alert_type: AlertType::HighErrorRate,
                severity: AlertSeverity::Critical,
                message: format!("严重错误: {}", error_record.error_message),
                timestamp: error_record.timestamp,
                resolved: false,
                context: {
                    let mut ctx = HashMap::new();
                    ctx.insert("error_type".to_string(), format!("{:?}", error_record.error_type));
                    if let Some(session_id) = &error_record.context.session_id {
                        ctx.insert("session_id".to_string(), session_id.clone());
                    }
                    ctx
                },
            };

            let mut manager = alert_manager.write().await;
            manager.active_alerts.insert(alert.id.clone(), alert.clone());
            manager.alert_history.push(alert);

            error!("🚨 触发严重错误警报: {}", error_record.error_message);
        }
    }

    /// 启动性能监控
    async fn start_performance_monitoring(&self) -> Result<()> {
        let metrics = self.performance_metrics.clone();
        let interval = self.config.metrics_interval_seconds;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(
                std::time::Duration::from_secs(interval)
            );

            loop {
                interval_timer.tick().await;
                Self::update_performance_metrics(&metrics).await;
            }
        });

        info!("性能监控已启动");
        Ok(())
    }

    /// 更新性能指标
    async fn update_performance_metrics(metrics: &Arc<RwLock<PerformanceMetrics>>) {
        let mut metrics = metrics.write().await;

        // 获取内存使用情况
        let memory_usage = Self::get_memory_usage();
        metrics.memory_usage_mb = memory_usage;

        // 获取CPU使用情况
        let cpu_usage = Self::get_cpu_usage();
        metrics.cpu_usage_percent = cpu_usage;

        // 更新时间戳
        metrics.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        debug!("性能指标更新: 内存={}MB, CPU={}%", memory_usage, cpu_usage);
    }

    /// 获取内存使用情况
    fn get_memory_usage() -> f64 {
        // 这里实现内存使用情况检测
        // 简化实现，实际应该使用系统API
        use std::fs;

        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<f64>() {
                            return kb / 1024.0; // 转换为MB
                        }
                    }
                }
            }
        }

        0.0
    }

    /// 获取CPU使用情况
    fn get_cpu_usage() -> f64 {
        // 这里实现CPU使用率检测
        // 简化实现，实际应该使用更精确的方法
        0.0
    }

    /// 启动健康监控
    async fn start_health_monitoring(&self) -> Result<()> {
        let error_handler = self.error_handler.clone();
        let interval = self.config.health_check_interval_seconds;

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(
                std::time::Duration::from_secs(interval)
            );

            loop {
                interval_timer.tick().await;

                let health = error_handler.check_system_health().await;
                Self::handle_health_check(&health).await;
            }
        });

        info!("健康监控已启动");
        Ok(())
    }

    /// 处理健康检查
    async fn handle_health_check(health: &SystemHealth) {
        match health.status {
            error_handler::HealthStatus::Excellent => {
                debug!("系统健康状况: 优秀 ({:.1}分)", health.health_score);
            }
            error_handler::HealthStatus::Good => {
                info!("系统健康状况: 良好 ({:.1}分)", health.health_score);
            }
            error_handler::HealthStatus::Warning => {
                warn!("系统健康状况: 警告 ({:.1}分)", health.health_score);
                for recommendation in &health.recommendations {
                    warn!("建议: {}", recommendation);
                }
            }
            error_handler::HealthStatus::Poor => {
                error!("系统健康状况: 较差 ({:.1}分)", health.health_score);
                for recommendation in &health.recommendations {
                    error!("建议: {}", recommendation);
                }
            }
            error_handler::HealthStatus::Critical => {
                error!("🚨 系统健康状况: 严重 ({:.1}分)", health.health_score);
                for recommendation in &health.recommendations {
                    error!("建议: {}", recommendation);
                }
            }
        }
    }

    /// 启动警报监控
    async fn start_alert_monitoring(&self) -> Result<()> {
        info!("警报监控系统已启动");
        Ok(())
    }

    /// 记录会话处理
    pub async fn record_session_processed(&self, processing_time_ms: u64) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.sessions_processed += 1;

        // 更新平均处理时间
        let total_time = metrics.processing_time_avg_ms * (metrics.sessions_processed - 1) as f64 + processing_time_ms as f64;
        metrics.processing_time_avg_ms = total_time / metrics.sessions_processed as f64;
    }

    /// 记录密钥提取
    pub async fn record_key_extracted(&self) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.keys_extracted += 1;
    }

    /// 记录网络流量
    pub async fn record_network_traffic(&self, bytes_sent: u64, bytes_received: u64) {
        let mut metrics = self.performance_metrics.write().await;
        metrics.network_bytes_sent += bytes_sent;
        metrics.network_bytes_received += bytes_received;
    }

    /// 获取系统状态
    pub async fn get_system_status(&self) -> SystemStatus {
        let error_stats = self.error_handler.get_error_stats().await;
        let performance_metrics = self.performance_metrics.read().await.clone();
        let health = self.error_handler.check_system_health().await;
        let alerts = self.alert_manager.read().await.active_alerts.clone();

        SystemStatus {
            health,
            performance_metrics,
            error_stats,
            active_alerts: alerts.len(),
            uptime: Self::get_uptime(),
        }
    }

    /// 获取系统运行时间
    fn get_uptime() -> u64 {
        // 这里应该返回系统运行时间
        // 简化实现
        0
    }

    /// 获取警报列表
    pub async fn get_alerts(&self) -> Vec<Alert> {
        let alert_manager = self.alert_manager.read().await;
        alert_manager.active_alerts.values().cloned().collect()
    }

    /// 解决警报
    pub async fn resolve_alert(&self, alert_id: &str) -> Result<()> {
        let mut alert_manager = self.alert_manager.write().await;

        if let Some(alert) = alert_manager.active_alerts.get_mut(alert_id) {
            alert.resolved = true;
            alert_manager.active_alerts.remove(alert_id);
            info!("警报已解决: {}", alert_id);
        }

        Ok(())
    }

    /// 获取性能指标
    pub async fn get_performance_metrics(&self) -> PerformanceMetrics {
        self.performance_metrics.read().await.clone()
    }

    /// 获取错误统计
    pub async fn get_error_stats(&self) -> ErrorStats {
        self.error_handler.get_error_stats().await
    }

    /// 处理自定义错误
    pub async fn handle_custom_error(&self, error: &str, context: ErrorContext) {
        let tls_error = crate::common::error::TlsKeyAgentError::Config(error.to_string());
        self.error_handler.handle_error(&tls_error, context).await;
    }
}

/// 系统状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub health: SystemHealth,
    pub performance_metrics: PerformanceMetrics,
    pub error_stats: ErrorStats,
    pub active_alerts: usize,
    pub uptime: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monitoring_manager_creation() {
        let config = MonitoringConfig::default();
        let manager = MonitoringManager::new(config);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_session_recording() {
        let config = MonitoringConfig::default();
        let manager = MonitoringManager::new(config).unwrap();

        manager.record_session_processed(100).await;
        manager.record_key_extracted().await;

        let metrics = manager.get_performance_metrics().await;
        assert_eq!(metrics.sessions_processed, 1);
        assert_eq!(metrics.keys_extracted, 1);
    }
}