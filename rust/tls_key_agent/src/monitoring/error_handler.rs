use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{error, warn, info, debug};
use serde::{Serialize, Deserialize};

use crate::common::error::TlsKeyAgentError;

/// 错误处理器，用于统一处理和监控错误
pub struct ErrorHandler {
    error_stats: Arc<RwLock<ErrorStats>>,
    error_callbacks: Arc<RwLock<Vec<ErrorCallback>>>,
    config: ErrorHandlerConfig,
}

/// 错误统计信息
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ErrorStats {
    pub total_errors: u64,
    pub connection_errors: u64,
    pub parsing_errors: u64,
    pub transport_errors: u64,
    pub config_errors: u64,
    pub unknown_errors: u64,
    pub recent_errors: Vec<ErrorRecord>,
    pub error_rate_per_minute: f64,
    pub last_error_time: Option<u64>,
}

/// 错误记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRecord {
    pub timestamp: u64,
    pub error_type: ErrorType,
    pub error_message: String,
    pub context: ErrorContext,
    pub severity: ErrorSeverity,
}

/// 错误类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorType {
    Connection,
    Parsing,
    Transport,
    Config,
    Memory,
    Ffi,
    Unknown,
}

/// 错误上下文
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    pub process_name: Option<String>,
    pub session_id: Option<String>,
    pub operation: Option<String>,
    pub additional_info: HashMap<String, String>,
}

/// 错误严重程度
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// 错误回调函数类型
pub type ErrorCallback = Box<dyn Fn(&ErrorRecord) + Send + Sync>;

/// 错误处理器配置
#[derive(Debug, Clone)]
pub struct ErrorHandlerConfig {
    pub max_recent_errors: usize,
    pub error_rate_threshold: f64,
    pub auto_recovery_enabled: bool,
    pub monitoring_enabled: bool,
}

impl Default for ErrorHandlerConfig {
    fn default() -> Self {
        Self {
            max_recent_errors: 1000,
            error_rate_threshold: 10.0, // 每分钟10个错误
            auto_recovery_enabled: true,
            monitoring_enabled: true,
        }
    }
}

impl ErrorHandler {
    pub fn new(config: ErrorHandlerConfig) -> Self {
        info!("初始化错误处理器");

        Self {
            error_stats: Arc::new(RwLock::new(ErrorStats::default())),
            error_callbacks: Arc::new(RwLock::new(Vec::new())),
            config,
        }
    }

    /// 处理错误
    pub async fn handle_error(&self, error: &TlsKeyAgentError, context: ErrorContext) {
        let error_record = self.create_error_record(error, context).await;

        // 更新统计信息
        self.update_error_stats(&error_record).await;

        // 记录日志
        self.log_error(&error_record).await;

        // 触发回调
        self.trigger_callbacks(&error_record).await;

        // 检查是否需要自动恢复
        if self.config.auto_recovery_enabled {
            self.check_auto_recovery(&error_record).await;
        }

        // 监控检查
        if self.config.monitoring_enabled {
            self.monitoring_check().await;
        }
    }

    /// 创建错误记录
    async fn create_error_record(&self, error: &TlsKeyAgentError, context: ErrorContext) -> ErrorRecord {
        let (error_type, severity) = self.classify_error(error);

        ErrorRecord {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            error_type,
            error_message: error.to_string(),
            context,
            severity,
        }
    }

    /// 分类错误
    fn classify_error(&self, error: &TlsKeyAgentError) -> (ErrorType, ErrorSeverity) {
        let (error_type, severity) = match error {
            TlsKeyAgentError::TlsParse(_) => (ErrorType::Parsing, ErrorSeverity::Medium),
            TlsKeyAgentError::Transport(_) => (ErrorType::Transport, ErrorSeverity::High),
            TlsKeyAgentError::Config(_) => (ErrorType::Config, ErrorSeverity::Low),
            TlsKeyAgentError::Ffi(_) => (ErrorType::Ffi, ErrorSeverity::Medium),
            _ => (ErrorType::Unknown, ErrorSeverity::Medium),
        };

        // 根据错误内容调整严重程度
        let adjusted_severity = self.adjust_severity(&error.to_string(), severity);
        (error_type, adjusted_severity)
    }

    /// 调整错误严重程度
    fn adjust_severity(&self, error_message: &str, base_severity: ErrorSeverity) -> ErrorSeverity {
        // 关键词检测来调整严重程度
        if error_message.contains("critical") ||
           error_message.contains("fatal") ||
           error_message.contains("panic") {
            return ErrorSeverity::Critical;
        }

        if error_message.contains("timeout") ||
           error_message.contains("connection refused") {
            return std::cmp::max(base_severity, ErrorSeverity::Medium);
        }

        base_severity
    }

    /// 更新错误统计
    async fn update_error_stats(&self, error_record: &ErrorRecord) {
        let mut stats = self.error_stats.write().await;

        stats.total_errors += 1;
        stats.last_error_time = Some(error_record.timestamp);

        // 按类型更新统计
        match error_record.error_type {
            ErrorType::Connection => stats.connection_errors += 1,
            ErrorType::Parsing => stats.parsing_errors += 1,
            ErrorType::Transport => stats.transport_errors += 1,
            ErrorType::Config => stats.config_errors += 1,
            _ => stats.unknown_errors += 1,
        }

        // 添加到最近错误列表
        stats.recent_errors.push(error_record.clone());

        // 限制最近错误数量
        if stats.recent_errors.len() > self.config.max_recent_errors {
            stats.recent_errors.remove(0);
        }

        // 计算错误率
        self.calculate_error_rate(&mut stats);
    }

    /// 计算错误率
    fn calculate_error_rate(&self, stats: &mut ErrorStats) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 计算最近一分钟的错误数
        let recent_minute_errors = stats.recent_errors.iter()
            .filter(|e| now - e.timestamp <= 60)
            .count() as f64;

        stats.error_rate_per_minute = recent_minute_errors;
    }

    /// 记录错误日志
    async fn log_error(&self, error_record: &ErrorRecord) {
        match error_record.severity {
            ErrorSeverity::Critical => {
                error!(
                    error_type = ?error_record.error_type,
                    error_message = %error_record.error_message,
                    session_id = ?error_record.context.session_id,
                    "CRITICAL ERROR"
                );
            }
            ErrorSeverity::High => {
                error!(
                    error_type = ?error_record.error_type,
                    error_message = %error_record.error_message,
                    session_id = ?error_record.context.session_id,
                    "HIGH ERROR"
                );
            }
            ErrorSeverity::Medium => {
                warn!(
                    error_type = ?error_record.error_type,
                    error_message = %error_record.error_message,
                    session_id = ?error_record.context.session_id,
                    "MEDIUM ERROR"
                );
            }
            ErrorSeverity::Low => {
                debug!(
                    error_type = ?error_record.error_type,
                    error_message = %error_record.error_message,
                    session_id = ?error_record.context.session_id,
                    "LOW ERROR"
                );
            }
        }
    }

    /// 触发错误回调
    async fn trigger_callbacks(&self, error_record: &ErrorRecord) {
        let callbacks = self.error_callbacks.read().await;
        for callback in callbacks.iter() {
            callback(error_record);
        }
    }

    /// 检查自动恢复
    async fn check_auto_recovery(&self, error_record: &ErrorRecord) {
        // 根据错误类型和严重程度执行自动恢复策略
        match (&error_record.error_type, &error_record.severity) {
            (ErrorType::Connection, ErrorSeverity::High | ErrorSeverity::Critical) => {
                info!("检测到连接错误，尝试自动恢复");
                self.attempt_connection_recovery().await;
            }
            (ErrorType::Transport, ErrorSeverity::High) => {
                info!("检测到传输错误，尝试恢复传输层");
                self.attempt_transport_recovery().await;
            }
            _ => {
                debug!("错误类型不需要自动恢复: {:?}", error_record.error_type);
            }
        }
    }

    /// 尝试连接恢复
    async fn attempt_connection_recovery(&self) {
        // 这里可以实现连接恢复逻辑，比如：
        // 1. 重新建立连接
        // 2. 刷新DNS缓存
        // 3. 切换到备用连接
        info!("执行连接恢复策略");
        // 实现具体的恢复逻辑...
    }

    /// 尝试传输恢复
    async fn attempt_transport_recovery(&self) {
        // 这里可以实现传输恢复逻辑，比如：
        // 1. 重新初始化传输层
        // 2. 切换到备用传输方式
        // 3. 清理传输缓存
        info!("执行传输恢复策略");
        // 实现具体的恢复逻辑...
    }

    /// 监控检查
    async fn monitoring_check(&self) {
        let stats = self.error_stats.read().await;

        // 检查错误率是否超过阈值
        if stats.error_rate_per_minute > self.config.error_rate_threshold {
            warn!("错误率超过阈值: {:.2}/分钟", stats.error_rate_per_minute);
            self.trigger_error_rate_alert().await;
        }

        // 检查是否有大量严重错误
        let critical_errors_count = stats.recent_errors.iter()
            .filter(|e| e.severity == ErrorSeverity::Critical)
            .count();

        if critical_errors_count > 5 {
            error!("检测到大量严重错误: {} 个", critical_errors_count);
            self.trigger_critical_error_alert().await;
        }
    }

    /// 触发错误率警报
    async fn trigger_error_rate_alert(&self) {
        warn!("🚨 错误率警报: 当前错误率 {:.2}/分钟 超过阈值 {:.2}",
              self.error_stats.read().await.error_rate_per_minute,
              self.config.error_rate_threshold);

        // 这里可以发送警报到监控系统、邮件、Slack等
    }

    /// 触发严重错误警报
    async fn trigger_critical_error_alert(&self) {
        error!("🚨 严重错误警报: 检测到多个严重错误，需要立即处理！");

        // 这里可以发送紧急警报
    }

    /// 注册错误回调
    pub async fn register_error_callback<F>(&self, callback: F)
    where
        F: Fn(&ErrorRecord) + Send + Sync + 'static,
    {
        let mut callbacks = self.error_callbacks.write().await;
        callbacks.push(Box::new(callback));
    }

    /// 获取错误统计
    pub async fn get_error_stats(&self) -> ErrorStats {
        self.error_stats.read().await.clone()
    }

    /// 重置错误统计
    pub async fn reset_error_stats(&self) {
        let mut stats = self.error_stats.write().await;
        *stats = ErrorStats::default();
        info!("错误统计已重置");
    }

    /// 获取最近的错误
    pub async fn get_recent_errors(&self, limit: usize) -> Vec<ErrorRecord> {
        let stats = self.error_stats.read().await;
        let recent_count = stats.recent_errors.len();

        if recent_count <= limit {
            stats.recent_errors.clone()
        } else {
            stats.recent_errors[recent_count - limit..].to_vec()
        }
    }

    /// 检查系统健康状态
    pub async fn check_system_health(&self) -> SystemHealth {
        let stats = self.error_stats.read().await;

        let health_score = self.calculate_health_score(&stats);
        let status = self.determine_health_status(health_score);

        SystemHealth {
            status,
            health_score,
            total_errors: stats.total_errors,
            error_rate_per_minute: stats.error_rate_per_minute,
            last_error_time: stats.last_error_time,
            recommendations: self.generate_health_recommendations(&stats, health_score),
        }
    }

    /// 计算健康分数
    fn calculate_health_score(&self, stats: &ErrorStats) -> f64 {
        let mut score = 100.0;

        // 根据错误率扣分
        score -= (stats.error_rate_per_minute / self.config.error_rate_threshold) * 20.0;

        // 根据严重错误扣分
        let critical_count = stats.recent_errors.iter()
            .filter(|e| e.severity == ErrorSeverity::Critical)
            .count() as f64;
        score -= critical_count * 10.0;

        // 根据总错误数扣分
        let total_penalty = (stats.total_errors as f64).log10() * 5.0;
        score -= total_penalty;

        score.max(0.0).min(100.0)
    }

    /// 确定健康状态
    fn determine_health_status(&self, health_score: f64) -> HealthStatus {
        if health_score >= 90.0 {
            HealthStatus::Excellent
        } else if health_score >= 75.0 {
            HealthStatus::Good
        } else if health_score >= 60.0 {
            HealthStatus::Warning
        } else if health_score >= 40.0 {
            HealthStatus::Poor
        } else {
            HealthStatus::Critical
        }
    }

    /// 生成健康建议
    fn generate_health_recommendations(&self, stats: &ErrorStats, health_score: f64) -> Vec<String> {
        let mut recommendations = Vec::new();

        if health_score < 60.0 {
            recommendations.push("系统健康状况较差，建议立即检查".to_string());
        }

        if stats.error_rate_per_minute > self.config.error_rate_threshold {
            recommendations.push(format!("错误率过高 ({:.2}/分钟)，检查系统负载", stats.error_rate_per_minute));
        }

        let connection_errors_ratio = stats.connection_errors as f64 / stats.total_errors.max(1) as f64;
        if connection_errors_ratio > 0.5 {
            recommendations.push("连接错误占比过高，检查网络连接".to_string());
        }

        recommendations
    }
}

/// 系统健康状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub status: HealthStatus,
    pub health_score: f64,
    pub total_errors: u64,
    pub error_rate_per_minute: f64,
    pub last_error_time: Option<u64>,
    pub recommendations: Vec<String>,
}

/// 健康状态枚举
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthStatus {
    Excellent,
    Good,
    Warning,
    Poor,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::error::TlsKeyAgentError;

    #[tokio::test]
    async fn test_error_handler_creation() {
        let config = ErrorHandlerConfig::default();
        let handler = ErrorHandler::new(config);

        let stats = handler.get_error_stats().await;
        assert_eq!(stats.total_errors, 0);
    }

    #[tokio::test]
    async fn test_error_handling() {
        let handler = ErrorHandler::new(ErrorHandlerConfig::default());

        let error = TlsKeyAgentError::Network("Test connection error".to_string());
        let context = ErrorContext {
            process_name: Some("test".to_string()),
            session_id: Some("session-123".to_string()),
            operation: Some("connect".to_string()),
            additional_info: HashMap::new(),
        };

        handler.handle_error(&error, context).await;

        let stats = handler.get_error_stats().await;
        assert_eq!(stats.total_errors, 1);
        assert_eq!(stats.connection_errors, 1);
    }

    #[tokio::test]
    async fn test_system_health() {
        let handler = ErrorHandler::new(ErrorHandlerConfig::default());

        let health = handler.check_system_health().await;
        assert_eq!(health.health_score, 100.0);
        assert!(matches!(health.status, HealthStatus::Excellent));
    }
}