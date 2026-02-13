/**
 * @file fault_recovery.rs
 * @brief 故障恢复管理器
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-12-15
 */

use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc, Mutex};
use serde::{Deserialize, Serialize};
use anyhow::Result;
use tracing::{info, warn, error, debug};

use crate::common::error::TlsKeyAgentError;

/// 故障类型
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FaultType {
    /// eBPF程序故障
    EbpfProgram,
    /// 传输层故障
    Transport,
    /// 配置管理故障
    ConfigManager,
    /// 注入器故障
    Injector,
    /// 系统资源不足
    SystemResource,
    /// 网络连接故障
    Network,
    /// 未知故障
    Unknown,
}

/// 故障严重程度
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FaultSeverity {
    /// 低 - 警告级别
    Low = 1,
    /// 中 - 需要注意
    Medium = 2,
    /// 高 - 严重故障
    High = 3,
    /// 关键 - 系统不可用
    Critical = 4,
}

/// 故障状态
#[derive(Debug, Clone, PartialEq)]
pub enum FaultStatus {
    /// 活跃故障
    Active,
    /// 恢复中
    Recovering,
    /// 已恢复
    Recovered,
    /// 已确认（无需恢复）
    Acknowledged,
}

/// 故障信息
#[derive(Debug, Clone)]
pub struct FaultInfo {
    pub fault_id: String,
    pub fault_type: FaultType,
    pub severity: FaultSeverity,
    pub status: FaultStatus,
    pub description: String,
    pub component: String,
    pub occurred_at: Instant,
    pub last_updated: Instant,
    pub recovery_attempts: u32,
    pub max_recovery_attempts: u32,
    pub recovery_action: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// 恢复策略
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStrategy {
    pub fault_type: FaultType,
    pub severity: FaultSeverity,
    pub max_attempts: u32,
    pub retry_interval: Duration,
    pub escalation_interval: Duration,
    pub actions: Vec<RecoveryAction>,
}

/// 恢复动作
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryAction {
    /// 重启组件
    RestartComponent(String),
    /// 重新初始化
    Reinitialize,
    /// 降级服务
    DegradeService,
    /// 切换到备用系统
    SwitchToBackup,
    /// 清理资源
    CleanupResources,
    /// 重新加载配置
    ReloadConfig,
    /// 发送告警
    SendAlert,
    /// 等待人工干预
    ManualIntervention,
}

/// 故障事件
#[derive(Debug, Clone)]
pub enum FaultEvent {
    /// 故障发生
    FaultOccurred(FaultInfo),
    /// 故障恢复
    FaultRecovered(String),
    /// 恢复失败
    RecoveryFailed(String, String),
    /// 故障升级
    FaultEscalated(String, FaultSeverity),
}

/// 故障恢复管理器
pub struct FaultRecoveryManager {
    config: Arc<FaultRecoveryConfig>,
    active_faults: Arc<RwLock<HashMap<String, FaultInfo>>>,
    recovery_strategies: Arc<RwLock<HashMap<(FaultType, FaultSeverity), RecoveryStrategy>>>,
    fault_events: mpsc::UnboundedSender<FaultEvent>,
    fault_events_receiver: Arc<Mutex<mpsc::UnboundedReceiver<FaultEvent>>>,
    health_check_interval: Duration,
    recovery_stats: Arc<RwLock<RecoveryStats>>,
}

/// 故障恢复配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultRecoveryConfig {
    pub enabled: bool,
    pub max_concurrent_recoveries: usize,
    pub default_max_attempts: u32,
    pub default_retry_interval: Duration,
    pub default_escalation_interval: Duration,
    pub health_check_interval: Duration,
    pub auto_recovery_enabled: bool,
    pub alert_threshold: FaultSeverity,
}

/// 恢复统计信息
#[derive(Debug, Clone, Default)]
pub struct RecoveryStats {
    pub total_faults: u64,
    pub recovered_faults: u64,
    pub failed_recoveries: u64,
    pub manual_interventions: u64,
    pub avg_recovery_time: Duration,
    pub success_rate: f64,
}

impl Default for FaultRecoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_concurrent_recoveries: 5,
            default_max_attempts: 3,
            default_retry_interval: Duration::from_secs(30),
            default_escalation_interval: Duration::from_secs(300), // 5 minutes
            health_check_interval: Duration::from_secs(10),
            auto_recovery_enabled: true,
            alert_threshold: FaultSeverity::High,
        }
    }
}

impl FaultInfo {
    pub fn new(
        fault_type: FaultType,
        severity: FaultSeverity,
        description: String,
        component: String,
    ) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut hasher);
        let random_component = hasher.finish() % 10000;

        let fault_id = format!("fault_{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            random_component
        );
        let now = Instant::now();

        Self {
            fault_id,
            fault_type,
            severity,
            status: FaultStatus::Active,
            description,
            component,
            occurred_at: now,
            last_updated: now,
            recovery_attempts: 0,
            max_recovery_attempts: 3,
            recovery_action: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    pub fn duration_since_occurred(&self) -> Duration {
        self.occurred_at.elapsed()
    }

    pub fn should_retry(&self) -> bool {
        self.recovery_attempts < self.max_recovery_attempts
    }

    pub fn mark_recovery_attempt(&mut self, action: String) {
        self.recovery_attempts += 1;
        self.recovery_action = Some(action);
        self.last_updated = Instant::now();
        self.status = FaultStatus::Recovering;
    }

    pub fn mark_recovered(&mut self) {
        self.status = FaultStatus::Recovered;
        self.last_updated = Instant::now();
    }

    pub fn mark_failed(&mut self) {
        self.status = FaultStatus::Active;
        self.last_updated = Instant::now();
    }
}

impl FaultRecoveryManager {
    pub fn new(config: FaultRecoveryConfig) -> Result<Self> {
        let (fault_events, fault_events_receiver) = mpsc::unbounded_channel();

        let manager = Self {
            config: Arc::new(config),
            active_faults: Arc::new(RwLock::new(HashMap::new())),
            recovery_strategies: Arc::new(RwLock::new(HashMap::new())),
            fault_events,
            fault_events_receiver: Arc::new(Mutex::new(fault_events_receiver)),
            health_check_interval: Duration::from_secs(10),
            recovery_stats: Arc::new(RwLock::new(RecoveryStats::default())),
        };

        // 在一个单独的函数中初始化默认恢复策略，避免在构造函数中使用await
        let manager_clone = manager.clone();
        tokio::spawn(async move {
            if let Err(e) = manager_clone.init_default_strategies().await {
                error!("初始化默认恢复策略失败: {}", e);
            }
        });

        Ok(manager)
    }

    /// 初始化默认恢复策略
    async fn init_default_strategies(&self) -> Result<()> {
        let mut strategies = self.recovery_strategies.write().await;

        // eBPF程序故障恢复策略
        strategies.insert(
            (FaultType::EbpfProgram, FaultSeverity::Medium),
            RecoveryStrategy {
                fault_type: FaultType::EbpfProgram,
                severity: FaultSeverity::Medium,
                max_attempts: 3,
                retry_interval: Duration::from_secs(10),
                escalation_interval: Duration::from_secs(120), // 2 minutes
                actions: vec![
                    RecoveryAction::Reinitialize,
                    RecoveryAction::CleanupResources,
                    RecoveryAction::SwitchToBackup,
                ],
            },
        );

        // 传输层故障恢复策略
        strategies.insert(
            (FaultType::Transport, FaultSeverity::High),
            RecoveryStrategy {
                fault_type: FaultType::Transport,
                severity: FaultSeverity::High,
                max_attempts: 5,
                retry_interval: Duration::from_secs(5),
                escalation_interval: Duration::from_secs(60), // 1 minute
                actions: vec![
                    RecoveryAction::RestartComponent("transport_manager".to_string()),
                    RecoveryAction::ReloadConfig,
                    RecoveryAction::DegradeService,
                ],
            },
        );

        // 系统资源不足恢复策略
        strategies.insert(
            (FaultType::SystemResource, FaultSeverity::Critical),
            RecoveryStrategy {
                fault_type: FaultType::SystemResource,
                severity: FaultSeverity::Critical,
                max_attempts: 2,
                retry_interval: Duration::from_secs(30),
                escalation_interval: Duration::from_secs(300),
                actions: vec![
                    RecoveryAction::CleanupResources,
                    RecoveryAction::DegradeService,
                    RecoveryAction::ManualIntervention,
                ],
            },
        );

        Ok(())
    }

    /// 报告故障
    pub async fn report_fault(&self, fault_info: FaultInfo) -> Result<()> {
        info!("报告故障: {} - {}", fault_info.fault_id, fault_info.description);

        // 添加到活跃故障列表
        {
            let mut active_faults = self.active_faults.write().await;
            active_faults.insert(fault_info.fault_id.clone(), fault_info.clone());
        }

        // 更新统计
        {
            let mut stats = self.recovery_stats.write().await;
            stats.total_faults += 1;
        }

        // 发送故障事件
        let _ = self.fault_events.send(FaultEvent::FaultOccurred(fault_info.clone()));

        // 如果启用了自动恢复，开始恢复流程
        if self.config.auto_recovery_enabled {
            self.start_recovery_process(fault_info).await?;
        }

        Ok(())
    }

    /// 开始恢复流程
    async fn start_recovery_process(&self, fault_info: FaultInfo) -> Result<()> {
        debug!("开始恢复流程: {}", fault_info.fault_id);

        let strategies = self.recovery_strategies.read().await;
        let strategy_key = (fault_info.fault_type.clone(), fault_info.severity.clone());

        if let Some(strategy) = strategies.get(&strategy_key) {
            let fault_id = fault_info.fault_id.clone();
            // 简化实现：同步执行恢复，避免生命周期问题
            self.execute_recovery(fault_id, strategy).await;
        } else {
            warn!("未找到故障恢复策略: {:?} - {:?}", fault_info.fault_type, fault_info.severity);
        }

        Ok(())
    }

    /// 执行恢复操作
    async fn execute_recovery(&self, fault_id: String, strategy: &RecoveryStrategy) {
        info!("执行故障恢复: {}", fault_id);

        for (attempt, action) in strategy.actions.iter().enumerate() {
            // 检查故障状态
            {
                let active_faults = self.active_faults.read().await;
                if let Some(fault) = active_faults.get(&fault_id) {
                    if fault.status == FaultStatus::Recovered {
                        info!("故障已恢复，停止恢复流程: {}", fault_id);
                        return;
                    }
                }
            }

            // 执行恢复动作
            match self.execute_recovery_action(action, &fault_id).await {
                Ok(_) => {
                    info!("恢复动作执行成功: {:?} - {}", action, fault_id);

                    // 标记故障已恢复
                    {
                        let mut active_faults = self.active_faults.write().await;
                        if let Some(fault) = active_faults.get_mut(&fault_id) {
                            fault.mark_recovered();
                        }
                    }

                    // 更新统计
                    {
                        let mut stats = self.recovery_stats.write().await;
                        stats.recovered_faults += 1;
                    }

                    // 发送恢复事件
                    let _ = self.fault_events.send(FaultEvent::FaultRecovered(fault_id.clone()));
                    break;
                }
                Err(e) => {
                    error!("恢复动作执行失败: {:?} - {} - {}", action, fault_id, e);

                    // 如果不是最后一次尝试，等待重试间隔
                    if attempt < strategy.actions.len() - 1 {
                        tokio::time::sleep(strategy.retry_interval).await;
                    }
                }
            }
        }

        // 如果所有恢复动作都失败，标记恢复失败
        {
            let mut active_faults = self.active_faults.write().await;
            if let Some(fault) = active_faults.get_mut(&fault_id) {
                fault.mark_failed();
            }
        }

        // 更新统计
        {
            let mut stats = self.recovery_stats.write().await;
            stats.failed_recoveries += 1;
        }

        let _ = self.fault_events.send(FaultEvent::RecoveryFailed(
            fault_id.clone(),
            "所有恢复动作均失败".to_string(),
        ));
    }

    /// 执行具体的恢复动作
    async fn execute_recovery_action(&self, action: &RecoveryAction, fault_id: &str) -> Result<()> {
        match action {
            RecoveryAction::RestartComponent(component) => {
                info!("重启组件: {} - {}", component, fault_id);
                // 这里需要根据具体的组件来实现重启逻辑
                // 可以通过事件总线或依赖注入来调用组件的重启方法
                self.restart_component(component).await
            }
            RecoveryAction::Reinitialize => {
                info!("重新初始化系统 - {}", fault_id);
                self.reinitialize_system().await
            }
            RecoveryAction::DegradeService => {
                info!("降级服务 - {}", fault_id);
                self.degrade_service().await
            }
            RecoveryAction::SwitchToBackup => {
                info!("切换到备用系统 - {}", fault_id);
                self.switch_to_backup().await
            }
            RecoveryAction::CleanupResources => {
                info!("清理资源 - {}", fault_id);
                self.cleanup_resources().await
            }
            RecoveryAction::ReloadConfig => {
                info!("重新加载配置 - {}", fault_id);
                self.reload_config().await
            }
            RecoveryAction::SendAlert => {
                warn!("发送告警 - {}", fault_id);
                self.send_alert(fault_id).await
            }
            RecoveryAction::ManualIntervention => {
                error!("需要人工干预 - {}", fault_id);
                {
                    let mut stats = self.recovery_stats.write().await;
                    stats.manual_interventions += 1;
                }
                Err(TlsKeyAgentError::Recovery("需要人工干预".to_string()).into())
            }
        }
    }

    /// 重启组件
    async fn restart_component(&self, component: &str) -> Result<()> {
        // 这里需要实现具体的组件重启逻辑
        // 可以通过组件注册表或依赖注入来找到并重启组件
        debug!("模拟重启组件: {}", component);
        Ok(())
    }

    /// 重新初始化系统
    async fn reinitialize_system(&self) -> Result<()> {
        debug!("模拟系统重新初始化");
        // 实现系统重新初始化逻辑
        Ok(())
    }

    /// 降级服务
    async fn degrade_service(&self) -> Result<()> {
        debug!("模拟服务降级");
        // 实现服务降级逻辑
        Ok(())
    }

    /// 切换到备用系统
    async fn switch_to_backup(&self) -> Result<()> {
        debug!("模拟切换到备用系统");
        // 实现备用系统切换逻辑
        Ok(())
    }

    /// 清理资源
    async fn cleanup_resources(&self) -> Result<()> {
        debug!("模拟资源清理");
        // 实现资源清理逻辑
        Ok(())
    }

    /// 重新加载配置
    async fn reload_config(&self) -> Result<()> {
        debug!("模拟配置重新加载");
        // 实现配置重新加载逻辑
        Ok(())
    }

    /// 发送告警
    async fn send_alert(&self, fault_id: &str) -> Result<()> {
        warn!("发送故障告警: {}", fault_id);
        // 实现告警发送逻辑
        Ok(())
    }

    /// 获取活跃故障列表
    pub async fn get_active_faults(&self) -> Vec<FaultInfo> {
        let active_faults = self.active_faults.read().await;
        active_faults.values().cloned().collect()
    }

    /// 手动标记故障已恢复
    pub async fn mark_fault_recovered(&self, fault_id: &str) -> Result<()> {
        info!("手动标记故障已恢复: {}", fault_id);

        {
            let mut active_faults = self.active_faults.write().await;
            if let Some(fault) = active_faults.get_mut(fault_id) {
                fault.mark_recovered();
            }
        }

        let _ = self.fault_events.send(FaultEvent::FaultRecovered(fault_id.to_string()));
        Ok(())
    }

    /// 获取恢复统计信息
    pub async fn get_recovery_stats(&self) -> RecoveryStats {
        let stats = self.recovery_stats.read().await;
        stats.clone()
    }

    /// 启动健康检查
    pub async fn start_health_check(&self) -> Result<()> {
        info!("启动故障恢复管理器健康检查");

        let manager = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(manager.health_check_interval);
            loop {
                interval.tick().await;
                manager.perform_health_check().await;
            }
        });

        Ok(())
    }

    /// 执行健康检查
    async fn perform_health_check(&self) {
        debug!("执行故障恢复管理器健康检查");

        let active_faults = self.active_faults.read().await;
        let _now = Instant::now();

        for (fault_id, fault) in active_faults.iter() {
            // 检查是否有长时间未恢复的故障
            if fault.status == FaultStatus::Active && fault.duration_since_occurred() > Duration::from_secs(600) { // 10 minutes
                warn!("长时间未恢复的故障: {} - {:?}", fault_id, fault.duration_since_occurred());

                // 可以在这里实现故障升级逻辑
                let _ = self.fault_events.send(FaultEvent::FaultEscalated(
                    fault_id.clone(),
                    FaultSeverity::Critical,
                ));
            }
        }
    }
}

// 为了支持 tokio::spawn，需要实现 Clone
impl Clone for FaultRecoveryManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            active_faults: self.active_faults.clone(),
            recovery_strategies: self.recovery_strategies.clone(),
            fault_events: self.fault_events.clone(),
            fault_events_receiver: self.fault_events_receiver.clone(),
            health_check_interval: self.health_check_interval,
            recovery_stats: self.recovery_stats.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fault_info_creation() {
        let fault = FaultInfo::new(
            FaultType::Transport,
            FaultSeverity::High,
            "测试故障".to_string(),
            "test_component".to_string(),
        );

        assert_eq!(fault.fault_type, FaultType::Transport);
        assert_eq!(fault.severity, FaultSeverity::High);
        assert_eq!(fault.status, FaultStatus::Active);
        assert_eq!(fault.recovery_attempts, 0);
    }

    #[tokio::test]
    async fn test_fault_recovery_manager() {
        let config = FaultRecoveryConfig::default();
        let manager = FaultRecoveryManager::new(config).unwrap();

        let fault = FaultInfo::new(
            FaultType::EbpfProgram,
            FaultSeverity::Medium,
            "eBPF程序故障".to_string(),
            "ebpf_hook".to_string(),
        );

        manager.report_fault(fault).await.unwrap();

        let active_faults = manager.get_active_faults().await;
        assert_eq!(active_faults.len(), 1);
    }
}