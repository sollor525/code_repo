/**
 * @file seamless_injection.rs
 * @brief 无感注入机制实现
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-11-05
 */

use std::collections::HashMap;
use std::path::Path;
use std::fs;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, error, debug, warn};
use anyhow::Result;

use crate::common::error::TlsKeyAgentError;
use crate::config::Config;
use crate::injector::TargetProcess;

/// 无感注入器
pub struct SeamlessInjector {
    config: std::sync::Arc<Config>,
    preload_injector: std::sync::Arc<tokio::sync::RwLock<crate::injector::preload::PreloadInjector>>,
    ebpf_injector: std::sync::Arc<tokio::sync::RwLock<crate::injector::ebpf::EbpfSslHook>>,
    detector: std::sync::Arc<crate::injector::detector::ProcessDetector>,
    current_method: crate::injector::InjectionMethod,
    monitor_interval: Duration,
    last_scan: RwLock<Instant>,
    injected_pids: RwLock<HashMap<u32, Instant>>,
    blacklist: Vec<String>,
}

impl SeamlessInjector {
    /// 创建新的无感注入器
    pub async fn new(
        config: std::sync::Arc<Config>,
        preload_injector: std::sync::Arc<tokio::sync::RwLock<crate::injector::preload::PreloadInjector>>,
        ebpf_injector: std::sync::Arc<tokio::sync::RwLock<crate::injector::ebpf::EbpfSslHook>>,
        detector: std::sync::Arc<crate::injector::detector::ProcessDetector>,
        current_method: crate::injector::InjectionMethod,
    ) -> Result<Self> {
        let monitor_interval = Duration::from_secs(config.injection.process_discovery_interval);

        // 关键进程黑名单
        let blacklist = vec![
            "kthreadd".to_string(),
            "ksoftirqd".to_string(),
            "migration".to_string(),
            "rcu_gp".to_string(),
            "rcu_par_gp".to_string(),
            "kworker".to_string(),
            "kdevtmpfs".to_string(),
            "systemd".to_string(),
            "init".to_string(),
        ];

        Ok(Self {
            config,
            preload_injector,
            ebpf_injector,
            detector,
            current_method,
            monitor_interval,
            last_scan: RwLock::new(Instant::now() - monitor_interval),
            injected_pids: RwLock::new(HashMap::new()),
            blacklist,
        })
    }

    /// 启动无感注入
    pub async fn start(&self) -> Result<()> {
        info!("启动无感注入机制");

        // 首次扫描已存在的TLS进程
        self.inject_existing_processes().await?;

        // 启动后台监控任务
        self.start_continuous_monitoring().await?;

        info!("无感注入机制启动成功");
        Ok(())
    }

    /// 停止无感注入
    pub async fn stop(&self) -> Result<()> {
        info!("停止无感注入机制");

        // 清理注入记录
        let mut injected_pids = self.injected_pids.write().await;
        injected_pids.clear();

        info!("无感注入机制已停止");
        Ok(())
    }

    /// 注入已存在的TLS进程
    async fn inject_existing_processes(&self) -> Result<()> {
        info!("扫描并注入已存在的TLS进程");

        match self.detector.discover_tls_processes().await {
            Ok(processes) => {
                let mut injected_count = 0;
                let mut error_count = 0;

                for process in &processes {
                    if self.should_inject_process(process) {
                        match self.inject_process_seamlessly(process).await {
                            Ok(_) => {
                                injected_count += 1;
                                info!("成功注入现有进程 {}: {}", process.pid, process.name);
                            }
                            Err(e) => {
                                error_count += 1;
                                error!("注入进程 {} 失败: {}", process.pid, e);
                            }
                        }
                    }
                }

                info!("现有进程注入完成: 成功 {} 个，失败 {} 个", injected_count, error_count);
            }
            Err(e) => {
                error!("扫描TLS进程失败: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// 启动连续监控
    async fn start_continuous_monitoring(&self) -> Result<()> {
        let injector = self.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(injector.monitor_interval);

            loop {
                interval.tick().await;

                debug!("执行定期进程扫描");
                if let Err(e) = injector.scan_and_inject_new_processes().await {
                    error!("定期扫描失败: {}", e);
                }
            }
        });

        info!("连续监控已启动");
        Ok(())
    }

    /// 扫描并注入新进程
    async fn scan_and_inject_new_processes(&self) -> Result<()> {
        // 检查扫描间隔
        {
            let last_scan = self.last_scan.read().await;
            if last_scan.elapsed() < self.monitor_interval {
                return Ok(());
            }
        }

        let processes = self.detector.discover_tls_processes().await?;
        let mut newly_injected = 0;

        for process in &processes {
            if self.should_inject_process(process) {
                // 检查是否已经注入
                {
                    let injected_pids = self.injected_pids.read().await;
                    if injected_pids.contains_key(&process.pid) {
                        continue;
                    }
                }

                match self.inject_process_seamlessly(process).await {
                    Ok(_) => {
                        newly_injected += 1;
                        info!("自动注入新进程 {}: {}", process.pid, process.name);
                    }
                    Err(e) => {
                        warn!("自动注入进程 {} 失败: {}", process.pid, e);
                    }
                }
            }
        }

        // 更新扫描时间
        {
            let mut last_scan = self.last_scan.write().await;
            *last_scan = Instant::now();
        }

        if newly_injected > 0 {
            info!("本轮扫描发现并注入 {} 个新进程", newly_injected);
        }

        Ok(())
    }

    /// 判断是否应该注入进程
    fn should_inject_process(&self, process: &TargetProcess) -> bool {
        // 检查进程是否使用TLS
        if !process.uses_tls {
            return false;
        }

        // 检查是否已注入
        if process.is_injected {
            return false;
        }

        // 检查是否在黑名单中
        if self.blacklist.contains(&process.name) {
            debug!("跳过黑名单进程: {}", process.name);
            return false;
        }

        // 检查关键进程
        if self.is_critical_process(process.pid) {
            debug!("跳过关键进程 PID: {}", process.pid);
            return false;
        }

        true
    }

    /// 无感注入单个进程
    async fn inject_process_seamlessly(&self, process: &TargetProcess) -> Result<()> {
        info!("无感注入进程 {}: {}", process.pid, process.name);

        // 检查进程是否安全可注入
        if !self.is_process_safe_for_injection(process.pid) {
            return Err(TlsKeyAgentError::Injection(
                format!("进程 {} 不安全，跳过注入", process.pid)
            ).into());
        }

        // 执行注入
        match self.inject_process_with_current_method(process).await {
            Ok(_) => {
                // 记录注入时间
                let mut injected_pids = self.injected_pids.write().await;
                injected_pids.insert(process.pid, Instant::now());

                info!("成功无感注入进程 {}", process.pid);
                Ok(())
            }
            Err(e) => {
                error!("无感注入进程 {} 失败: {}", process.pid, e);
                Err(e)
            }
        }
    }

    /// 检查进程是否安全可注入
    fn is_process_safe_for_injection(&self, pid: u32) -> bool {
        // 检查进程是否存在
        let proc_path = format!("/proc/{}", pid);
        if !Path::new(&proc_path).exists() {
            return false;
        }

        // 检查进程状态
        if let Ok(stat_content) = fs::read_to_string(format!("{}/stat", proc_path)) {
            let fields: Vec<&str> = stat_content.split_whitespace().collect();
            if fields.len() >= 3 {
                let state = fields[2];
                match state {
                    "R" | "S" => return true, // 运行或睡眠状态
                    "Z" => return false,      // 僵尸进程
                    "T" => {
                        warn!("进程 {} 已停止，可能不安全", pid);
                        return true; // 仍然尝试，但给出警告
                    },
                    _ => {
                        warn!("进程 {} 状态未知: {}", pid, state);
                        return true;
                    }
                }
            }
        }

        false
    }

    /// 检查是否为关键进程
    fn is_critical_process(&self, pid: u32) -> bool {
        let critical_processes = vec![1, 2, 3, 4, 5]; // init, kthreadd等系统关键进程
        critical_processes.contains(&pid)
    }

    /// 使用当前注入方法注入进程
    async fn inject_process_with_current_method(&self, process: &TargetProcess) -> Result<()> {
        match self.current_method {
            crate::injector::InjectionMethod::LdPreload => {
                let injector = self.preload_injector.read().await;
                injector.inject_process(process).await
            }
            crate::injector::InjectionMethod::Ebpf => {
                // eBPF是系统级Hook，不需要针对特定进程注入
                // 只需要确保eBPF程序正在运行即可
                let injector = self.ebpf_injector.read().await;
                if injector.is_running() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("eBPF Hook未运行"))
                }
            }
            crate::injector::InjectionMethod::Auto => {
                // 先尝试eBPF，失败则使用LD_PRELOAD
                let injector = self.ebpf_injector.read().await;
                if injector.is_running() {
                    Ok(())
                } else {
                    warn!("eBPF Hook未运行，切换到LD_PRELOAD");
                    self.preload_injector.read().await.inject_process(process).await
                }
            }
        }
    }

    /// 获取注入统计信息
    pub async fn get_injection_stats(&self) -> InjectionStats {
        let injected_pids = self.injected_pids.read().await;
        let now = Instant::now();

        let recent_injections = injected_pids.iter()
            .filter(|(_, &time)| now.duration_since(time) < Duration::from_secs(300))
            .count();

        InjectionStats {
            total_injected: injected_pids.len(),
            recent_injections,
            monitor_interval: self.monitor_interval.as_secs(),
        }
    }

    /// 清理过期的注入记录
    pub async fn cleanup_expired_records(&self) {
        let mut injected_pids = self.injected_pids.write().await;
        let now = Instant::now();
        let expiration = Duration::from_secs(3600); // 1小时过期

        let expired_pids: Vec<u32> = injected_pids.iter()
            .filter(|(_, &time)| now.duration_since(time) > expiration)
            .map(|(&pid, _)| pid)
            .collect();

        let expired_count = expired_pids.len();
        for pid in expired_pids {
            injected_pids.remove(&pid);
            debug!("清理过期注入记录: PID {}", pid);
        }

        if expired_count > 0 {
            debug!("清理了 {} 个过期注入记录", expired_count);
        }
    }
}

impl Clone for SeamlessInjector {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            preload_injector: self.preload_injector.clone(),
            ebpf_injector: self.ebpf_injector.clone(),
            detector: self.detector.clone(),
            current_method: self.current_method.clone(),
            monitor_interval: self.monitor_interval,
            last_scan: RwLock::new(Instant::now()),
            injected_pids: RwLock::new(HashMap::new()),
            blacklist: self.blacklist.clone(),
        }
    }
}

/// 注入统计信息
#[derive(Debug, Clone)]
pub struct InjectionStats {
    pub total_injected: usize,
    pub recent_injections: usize,
    pub monitor_interval: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    
    /// 测试辅助函数：创建SeamlessInjector实例
    async fn create_test_injector() -> SeamlessInjector {
        let config = Arc::new(Config::default());

        // 创建所需的组件
        let preload_injector = Arc::new(tokio::sync::RwLock::new(
            crate::injector::preload::PreloadInjector::new(config.clone())
        ));
        let ebpf_injector = Arc::new(tokio::sync::RwLock::new(
            crate::injector::ebpf::EbpfSslHook::new(config.clone())
        ));
        let detector = Arc::new(crate::injector::detector::ProcessDetector::new());
        let current_method = crate::injector::InjectionMethod::Auto;

        SeamlessInjector::new(
            config,
            preload_injector,
            ebpf_injector,
            detector,
            current_method
        ).await.unwrap()
    }

    #[tokio::test]
    async fn test_seamless_injector_creation() {
        let injector = create_test_injector().await;

        // 验证基本属性
        assert!(injector.monitor_interval.as_secs() > 0);
        assert!(!injector.blacklist.is_empty());
    }

    #[tokio::test]
    async fn test_process_safety_check() {
        let injector = create_test_injector().await;

        // 测试关键进程检查
        assert!(injector.is_critical_process(1));
        assert!(injector.is_critical_process(2));
        assert!(!injector.is_critical_process(12345));

        // 测试安全检查
        let is_safe = injector.is_process_safe_for_injection(1);
        // init进程应该存在，但可能不安全注入
        debug!("PID 1 安全状态: {}", is_safe);
    }

    #[tokio::test]
    async fn test_injection_stats() {
        let injector = create_test_injector().await;

        let stats = injector.get_injection_stats().await;
        assert_eq!(stats.total_injected, 0);
        assert_eq!(stats.recent_injections, 0);
        assert_eq!(stats.monitor_interval, 5); // 默认5秒间隔
    }

    #[tokio::test]
    async fn test_should_inject_process() {
        let injector = create_test_injector().await;

        // 测试黑名单进程
        let blacklisted_process = TargetProcess {
            pid: 12345,
            name: "systemd".to_string(),
            cmdline: "/sbin/init".to_string(),
            uses_tls: true,
            ssl_lib_path: None,
            is_injected: false,
            injection_time: None,
        };
        assert!(!injector.should_inject_process(&blacklisted_process));

        // 测试非TLS进程
        let non_tls_process = TargetProcess {
            pid: 12346,
            name: "bash".to_string(),
            cmdline: "/bin/bash".to_string(),
            uses_tls: false,
            ssl_lib_path: None,
            is_injected: false,
            injection_time: None,
        };
        assert!(!injector.should_inject_process(&non_tls_process));

        // 测试已注入进程
        let already_injected_process = TargetProcess {
            pid: 12347,
            name: "nginx".to_string(),
            cmdline: "nginx: master process".to_string(),
            uses_tls: true,
            ssl_lib_path: Some("/usr/lib/x86_64-linux-gnu/libssl.so".to_string()),
            is_injected: true,
            injection_time: None,
        };
        assert!(!injector.should_inject_process(&already_injected_process));

        // 测试应该注入的进程
        let should_inject_process = TargetProcess {
            pid: 12348,
            name: "nginx".to_string(),
            cmdline: "nginx: worker process".to_string(),
            uses_tls: true,
            ssl_lib_path: Some("/usr/lib/x86_64-linux-gnu/libssl.so".to_string()),
            is_injected: false,
            injection_time: None,
        };
        assert!(injector.should_inject_process(&should_inject_process));
    }
}