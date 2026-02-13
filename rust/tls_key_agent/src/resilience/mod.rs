/**
 * @file mod.rs
 * @brief 弹性和故障恢复模块
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-12-15
 */

pub mod fault_recovery;
pub mod load_balancer;
pub mod health_checker;
pub mod performance_monitor;

pub use fault_recovery::{
    FaultRecoveryManager, FaultInfo, FaultType, FaultSeverity, FaultStatus,
    RecoveryStrategy, RecoveryAction, FaultEvent, FaultRecoveryConfig, RecoveryStats
};

pub use load_balancer::{
    LoadBalancer, LoadBalanceStrategy, NodeInfo, LoadBalanceConfig,
    LoadBalanceStats
};

pub use health_checker::{
    HealthChecker, HealthCheckType, HealthStatus, HealthCheckConfig, HealthCheckResult,
    HealthSummary
};

pub use performance_monitor::{
    PerformanceMonitor, Metric, MetricType, AlertRule, AlertCondition, AlertLevel,
    AlertStatus, AlertEvent, PerformanceStats, PerformanceMonitorConfig, SystemMetricsCollector
};