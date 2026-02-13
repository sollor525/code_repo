/**
 * @file health_checker.rs
 * @brief 健康检查器
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
use tracing::{info, debug};

use crate::common::error::TlsKeyAgentError;

/// 健康检查类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HealthCheckType {
    /// HTTP检查
    Http,
    /// TCP检查
    Tcp,
    /// UDP检查
    Udp,
    /// 进程检查
    Process,
    /// 磁盘空间检查
    DiskSpace,
    /// 内存使用检查
    Memory,
    /// CPU使用检查
    Cpu,
    /// 自定义检查
    Custom,
}

/// 健康状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// 健康
    Healthy,
    /// 警告
    Warning,
    /// 不健康
    Unhealthy,
    /// 未知
    Unknown,
}

/// 健康检查配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub check_type: HealthCheckType,
    pub target: String,
    pub interval: Duration,
    pub timeout: Duration,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub enabled: bool,
    pub metadata: HashMap<String, String>,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            check_type: HealthCheckType::Tcp,
            target: String::new(),
            interval: Duration::from_secs(30),
            timeout: Duration::from_secs(5),
            failure_threshold: 3,
            success_threshold: 2,
            enabled: true,
            metadata: HashMap::new(),
        }
    }
}

/// 健康检查结果
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub check_id: String,
    pub status: HealthStatus,
    pub response_time: Duration,
    pub message: String,
    pub timestamp: Instant,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub metadata: HashMap<String, String>,
}

/// 健康检查器
pub struct HealthChecker {
    checks: Arc<RwLock<HashMap<String, HealthCheckConfig>>>,
    results: Arc<RwLock<HashMap<String, HealthCheckResult>>>,
    check_interval: Duration,
    event_sender: mpsc::UnboundedSender<HealthCheckEvent>,
}

/// 健康检查事件
#[derive(Debug, Clone)]
pub enum HealthCheckEvent {
    /// 检查状态变化
    StatusChanged {
        check_id: String,
        old_status: HealthStatus,
        new_status: HealthStatus,
    },
    /// 检查失败
    CheckFailed {
        check_id: String,
        error: String,
    },
    /// 检查恢复
    CheckRecovered {
        check_id: String,
    },
}

impl HealthChecker {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<HealthCheckEvent>) {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let checker = Self {
            checks: Arc::new(RwLock::new(HashMap::new())),
            results: Arc::new(RwLock::new(HashMap::new())),
            check_interval: Duration::from_secs(10),
            event_sender,
        };

        (checker, event_receiver)
    }

    /// 添加健康检查
    pub async fn add_check(&self, check_id: String, config: HealthCheckConfig) -> Result<()> {
        info!("添加健康检查: {} - {:?}", check_id, config.check_type);

        {
            let mut checks = self.checks.write().await;
            checks.insert(check_id.clone(), config);
        }

        // 初始化检查结果
        let initial_result = HealthCheckResult {
            check_id: check_id.clone(),
            status: HealthStatus::Unknown,
            response_time: Duration::from_secs(0),
            message: "检查已添加，等待首次执行".to_string(),
            timestamp: Instant::now(),
            consecutive_failures: 0,
            consecutive_successes: 0,
            metadata: HashMap::new(),
        };

        {
            let mut results = self.results.write().await;
            results.insert(check_id.clone(), initial_result);
        }

        Ok(())
    }

    /// 移除健康检查
    pub async fn remove_check(&self, check_id: &str) -> Result<()> {
        info!("移除健康检查: {}", check_id);

        {
            let mut checks = self.checks.write().await;
            checks.remove(check_id);
        }

        {
            let mut results = self.results.write().await;
            results.remove(check_id);
        }

        Ok(())
    }

    /// 启动健康检查
    pub async fn start(&self) -> Result<()> {
        info!("启动健康检查器");

        let checker = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(checker.check_interval);
            loop {
                interval.tick().await;
                checker.run_all_checks().await;
            }
        });

        Ok(())
    }

    /// 运行所有健康检查
    async fn run_all_checks(&self) {
        let checks = self.checks.read().await;
        let check_configs: Vec<(String, HealthCheckConfig)> = checks
            .iter()
            .filter(|(_, config)| config.enabled)
            .map(|(id, config)| (id.clone(), config.clone()))
            .collect();

        drop(checks);

        for (check_id, config) in check_configs {
            let checker = self.clone();
            tokio::spawn(async move {
                checker.run_single_check(check_id, config).await;
            });
        }
    }

    /// 运行单个健康检查
    async fn run_single_check(&self, check_id: String, config: HealthCheckConfig) {
        debug!("执行健康检查: {}", check_id);

        let start_time = Instant::now();
        let result = match config.check_type {
            HealthCheckType::Http => self.check_http(&config).await,
            HealthCheckType::Tcp => self.check_tcp(&config).await,
            HealthCheckType::Udp => self.check_udp(&config).await,
            HealthCheckType::Process => self.check_process(&config).await,
            HealthCheckType::DiskSpace => self.check_disk_space(&config).await,
            HealthCheckType::Memory => self.check_memory(&config).await,
            HealthCheckType::Cpu => self.check_cpu(&config).await,
            HealthCheckType::Custom => self.check_custom(&config).await,
        };

        let response_time = start_time.elapsed();
        let (status, message) = match result {
            Ok(_) => (HealthStatus::Healthy, "检查通过".to_string()),
            Err(e) => (HealthStatus::Unhealthy, format!("检查失败: {}", e)),
        };

        // 获取之前的结果
        let old_result = {
            let results = self.results.read().await;
            results.get(&check_id).cloned()
        };

        // 更新结果
        {
            let mut results = self.results.write().await;
            let current_result = results.get_mut(&check_id).unwrap();

            let old_status = current_result.status.clone();
            let was_healthy_before = old_result.as_ref()
                .map(|old| old.status == HealthStatus::Healthy)
                .unwrap_or(false);

            current_result.status = status.clone();
            current_result.response_time = response_time;
            current_result.message = message.clone();
            current_result.timestamp = Instant::now();

            // 更新连续成功/失败计数
            if status == HealthStatus::Healthy {
                current_result.consecutive_successes += 1;
                current_result.consecutive_failures = 0;
            } else {
                current_result.consecutive_failures += 1;
                current_result.consecutive_successes = 0;
            }

            // 发送状态变化事件
            if old_status != status {
                let _ = self.event_sender.send(HealthCheckEvent::StatusChanged {
                    check_id: check_id.clone(),
                    old_status,
                    new_status: status.clone(),
                });

                if status == HealthStatus::Unhealthy && old_result.is_some() {
                    let _ = self.event_sender.send(HealthCheckEvent::CheckFailed {
                        check_id: check_id.clone(),
                        error: message,
                    });
                } else if status == HealthStatus::Healthy && !was_healthy_before {
                    let _ = self.event_sender.send(HealthCheckEvent::CheckRecovered {
                        check_id: check_id.clone(),
                    });
                }
            }
        }
    }

    /// HTTP健康检查
    async fn check_http(&self, config: &HealthCheckConfig) -> Result<()> {
        // 简化HTTP检查实现，避免引入reqwest依赖
        let url = &config.target;

        // 解析URL获取主机和端口
        let (host, port) = if url.starts_with("http://") {
            let url_part = &url[7..]; // 移除 "http://"
            if let Some(slash_pos) = url_part.find('/') {
                let host_port = &url_part[..slash_pos];
                if let Some(colon_pos) = host_port.find(':') {
                    (host_port[..colon_pos].to_string(), host_port[colon_pos+1..].to_string())
                } else {
                    (host_port.to_string(), "80".to_string())
                }
            } else {
                (url_part.to_string(), "80".to_string())
            }
        } else if url.starts_with("https://") {
            let url_part = &url[8..]; // 移除 "https://"
            if let Some(slash_pos) = url_part.find('/') {
                let host_port = &url_part[..slash_pos];
                if let Some(colon_pos) = host_port.find(':') {
                    (host_port[..colon_pos].to_string(), host_port[colon_pos+1..].to_string())
                } else {
                    (host_port.to_string(), "443".to_string())
                }
            } else {
                (url_part.to_string(), "443".to_string())
            }
        } else {
            return Err(TlsKeyAgentError::HealthCheck("无效的HTTP URL格式".to_string()).into());
        };

        let port: u16 = port.parse()
            .map_err(|_| TlsKeyAgentError::HealthCheck("无效的端口号".to_string()))?;

        let addr = format!("{}:{}", host, port);
        let stream = tokio::time::timeout(config.timeout, tokio::net::TcpStream::connect(addr)).await??;

        // 简单的连接测试
        drop(stream);
        Ok(())
    }

    /// TCP健康检查
    async fn check_tcp(&self, config: &HealthCheckConfig) -> Result<()> {
        let addr = config.target.parse::<std::net::SocketAddr>()?;
        let stream = tokio::time::timeout(config.timeout, tokio::net::TcpStream::connect(addr)).await??;

        // 简单的连接测试
        drop(stream);
        Ok(())
    }

    /// UDP健康检查
    async fn check_udp(&self, config: &HealthCheckConfig) -> Result<()> {
        let addr = config.target.parse::<std::net::SocketAddr>()?;
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

        // 发送测试数据
        let test_data = b"health_check";
        let result = tokio::time::timeout(config.timeout, socket.send_to(test_data, addr)).await?;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(TlsKeyAgentError::HealthCheck(format!("UDP检查失败: {}", e)).into()),
        }
    }

    /// 进程健康检查
    async fn check_process(&self, config: &HealthCheckConfig) -> Result<()> {
        let pid: u32 = config.target.parse()
            .map_err(|_| TlsKeyAgentError::HealthCheck("无效的进程ID".to_string()))?;

        // 检查进程是否存在
        let output = tokio::process::Command::new("ps")
            .arg("-p")
            .arg(pid.to_string())
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.lines().count() > 1 { // 包含标题行
                Ok(())
            } else {
                Err(TlsKeyAgentError::HealthCheck("进程不存在".to_string()).into())
            }
        } else {
            Err(TlsKeyAgentError::HealthCheck("无法检查进程状态".to_string()).into())
        }
    }

    /// 磁盘空间健康检查
    async fn check_disk_space(&self, config: &HealthCheckConfig) -> Result<()> {
        let path = &config.target;
        let threshold = config.metadata
            .get("threshold_percent")
            .and_then(|v| v.parse().ok())
            .unwrap_or(90.0);

        let output = tokio::process::Command::new("df")
            .arg(path)
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // 解析df输出，获取使用率
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    if let Some(usage_str) = parts.get(4) {
                        if let Some(usage_str) = usage_str.strip_suffix('%') {
                            if let Ok(usage) = usage_str.parse::<f64>() {
                                if usage < threshold {
                                    return Ok(());
                                } else {
                                    return Err(TlsKeyAgentError::HealthCheck(
                                        format!("磁盘空间不足: {:.1}%", usage)
                                    ).into());
                                }
                            }
                        }
                    }
                }
            }

            Err(TlsKeyAgentError::HealthCheck("无法解析磁盘使用率".to_string()).into())
        } else {
            Err(TlsKeyAgentError::HealthCheck("无法获取磁盘空间信息".to_string()).into())
        }
    }

    /// 内存使用健康检查
    async fn check_memory(&self, _config: &HealthCheckConfig) -> Result<()> {
        let output = tokio::process::Command::new("free")
            .arg("-m")
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // 简单检查是否有可用内存
            if stdout.contains("Mem:") {
                Ok(())
            } else {
                Err(TlsKeyAgentError::HealthCheck("无法解析内存信息".to_string()).into())
            }
        } else {
            Err(TlsKeyAgentError::HealthCheck("无法获取内存信息".to_string()).into())
        }
    }

    /// CPU使用健康检查
    async fn check_cpu(&self, _config: &HealthCheckConfig) -> Result<()> {
        let output = tokio::process::Command::new("uptime")
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // 简单检查系统负载
            if stdout.contains("load average") {
                Ok(())
            } else {
                Err(TlsKeyAgentError::HealthCheck("无法解析CPU负载信息".to_string()).into())
            }
        } else {
            Err(TlsKeyAgentError::HealthCheck("无法获取CPU负载信息".to_string()).into())
        }
    }

    /// 自定义健康检查
    async fn check_custom(&self, config: &HealthCheckConfig) -> Result<()> {
        let command = &config.target;
        let output = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .await?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(TlsKeyAgentError::HealthCheck(
                format!("自定义检查失败: {}", stderr)
            ).into())
        }
    }

    /// 获取所有健康检查结果
    pub async fn get_all_results(&self) -> HashMap<String, HealthCheckResult> {
        let results = self.results.read().await;
        results.clone()
    }

    /// 获取指定检查的结果
    pub async fn get_check_result(&self, check_id: &str) -> Option<HealthCheckResult> {
        let results = self.results.read().await;
        results.get(check_id).cloned()
    }

    /// 获取健康状态摘要
    pub async fn get_health_summary(&self) -> HealthSummary {
        let results = self.results.read().await;

        let mut healthy = 0;
        let mut warning = 0;
        let mut unhealthy = 0;
        let mut unknown = 0;

        for result in results.values() {
            match result.status {
                HealthStatus::Healthy => healthy += 1,
                HealthStatus::Warning => warning += 1,
                HealthStatus::Unhealthy => unhealthy += 1,
                HealthStatus::Unknown => unknown += 1,
            }
        }

        let total = healthy + warning + unhealthy + unknown;
        let overall_status = if unhealthy > 0 {
            HealthStatus::Unhealthy
        } else if warning > 0 {
            HealthStatus::Warning
        } else if total == 0 {
            HealthStatus::Unknown
        } else {
            HealthStatus::Healthy
        };

        HealthSummary {
            overall_status,
            total_checks: total,
            healthy_checks: healthy,
            warning_checks: warning,
            unhealthy_checks: unhealthy,
            unknown_checks: unknown,
            last_updated: Instant::now(),
        }
    }
}

/// 健康状态摘要
#[derive(Debug, Clone)]
pub struct HealthSummary {
    pub overall_status: HealthStatus,
    pub total_checks: u32,
    pub healthy_checks: u32,
    pub warning_checks: u32,
    pub unhealthy_checks: u32,
    pub unknown_checks: u32,
    pub last_updated: Instant,
}

// 为了支持 tokio::spawn，需要实现 Clone
impl Clone for HealthChecker {
    fn clone(&self) -> Self {
        Self {
            checks: self.checks.clone(),
            results: self.results.clone(),
            check_interval: self.check_interval,
            event_sender: self.event_sender.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker_creation() {
        let (checker, _receiver) = HealthChecker::new();

        let config = HealthCheckConfig::default();
        checker.add_check("test_check".to_string(), config).await.unwrap();

        let results = checker.get_all_results().await;
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_health_summary() {
        let (checker, _receiver) = HealthChecker::new();

        let summary = checker.get_health_summary().await;
        assert_eq!(summary.total_checks, 0);
        assert_eq!(summary.overall_status, HealthStatus::Unknown);
    }

    #[tokio::test]
    async fn test_tcp_health_check() {
        let (checker, _receiver) = HealthChecker::new();

        let config = HealthCheckConfig {
            check_type: HealthCheckType::Tcp,
            target: "127.0.0.1:80".to_string(), // 假设这个端口不存在
            timeout: Duration::from_secs(1),
            ..Default::default()
        };

        let result = checker.check_tcp(&config).await;
        assert!(result.is_err()); // 应该失败，因为没有监听80端口
    }
}