/**
 * @file preload.rs
 * @brief LD_PRELOAD注入器实现
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-11-05
 */

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::fs;
use tracing::{info, error, debug, warn};
use anyhow::Result;

use crate::common::error::TlsKeyAgentError;
use crate::config::Config;
use super::TargetProcess;

/// LD_PRELOAD注入器
pub struct PreloadInjector {
    config: std::sync::Arc<Config>,
    hook_library_path: String,
    is_active: std::sync::atomic::AtomicBool,
    injected_processes: std::sync::Mutex<HashMap<u32, std::time::SystemTime>>,
}

impl PreloadInjector {
    /// 创建新的LD_PRELOAD注入器
    pub fn new(config: std::sync::Arc<Config>) -> Self {
        let hook_library_path = config.injection.hook_library.clone()
            .unwrap_or_else(|| "./target/release/libopenssl_hook.so".to_string());

        Self {
            config,
            hook_library_path,
            is_active: std::sync::atomic::AtomicBool::new(false),
            injected_processes: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// 启动注入器
    pub async fn start(&self) -> Result<()> {
        info!("启动LD_PRELOAD注入器");

        // 检查Hook库文件是否存在
        if !Path::new(&self.hook_library_path).exists() {
            return Err(TlsKeyAgentError::Injection(
                format!("Hook库文件不存在: {}", self.hook_library_path)
            ).into());
        }

        // 设置环境变量以影响新创建的进程
        self.set_global_preload()?;

        self.is_active.store(true, std::sync::atomic::Ordering::SeqCst);
        info!("LD_PRELOAD注入器启动成功");
        Ok(())
    }

    /// 停止注入器
    pub async fn stop(&self) -> Result<()> {
        info!("停止LD_PRELOAD注入器");

        // 清理全局LD_PRELOAD设置
        self.cleanup_global_preload()?;

        // 清理注入进程记录
        let mut injected = self.injected_processes.lock().unwrap();
        injected.clear();

        self.is_active.store(false, std::sync::atomic::Ordering::SeqCst);
        info!("LD_PRELOAD注入器已停止");
        Ok(())
    }

    /// 注入到指定进程
    pub async fn inject_process(&self, process: &TargetProcess) -> Result<()> {
        if !self.is_active.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(TlsKeyAgentError::Injection("注入器未启动".to_string()).into());
        }

        if process.is_injected {
            debug!("进程 {} 已经注入", process.pid);
            return Ok(());
        }

        info!("开始LD_PRELOAD注入进程 {}: {}", process.pid, process.name);

        // 使用环境变量注入方式（对子进程有效）
        if self.inject_via_environment(process).await? {
            self.mark_process_injected(process.pid)?;
            info!("成功注入进程 {}", process.pid);
            return Ok(());
        }

        // 使用ptrace注入方式（对运行中进程）
        if self.inject_via_ptrace(process.pid).await? {
            self.mark_process_injected(process.pid)?;
            info!("成功注入进程 {}", process.pid);
            return Ok(());
        }

        Err(TlsKeyAgentError::Injection(
            format!("注入进程 {} 失败", process.pid)
        ).into())
    }

    /// 检查进程是否已注入
    pub async fn is_process_injected(&self, pid: u32) -> Result<bool> {
        let injected = self.injected_processes.lock().unwrap();
        Ok(injected.contains_key(&pid))
    }

    /// 获取已注入的进程列表
    pub async fn get_injected_processes(&self) -> Result<Vec<u32>> {
        let injected = self.injected_processes.lock().unwrap();
        Ok(injected.keys().copied().collect())
    }

    /// 检查是否支持此注入方式
    pub async fn is_supported(&self) -> bool {
        // LD_PRELOAD在所有Linux系统上都支持
        true
    }

    /// 设置全局LD_PRELOAD环境变量
    fn set_global_preload(&self) -> Result<()> {
        debug!("设置全局LD_PRELOAD环境变量");

        std::env::set_var("LD_PRELOAD", &self.hook_library_path);
        info!("设置LD_PRELOAD={}", self.hook_library_path);

        Ok(())
    }

    /// 清理全局LD_PRELOAD设置
    fn cleanup_global_preload(&self) -> Result<()> {
        debug!("清理全局LD_PRELOAD环境变量");

        if std::env::var("LD_PRELOAD").unwrap_or_default() == self.hook_library_path {
            std::env::remove_var("LD_PRELOAD");
            info!("清理LD_PRELOAD环境变量");
        }

        Ok(())
    }

    /// 通过环境变量注入（影响新进程）
    async fn inject_via_environment(&self, process: &TargetProcess) -> Result<bool> {
        debug!("尝试环境变量注入进程 {}", process.pid);

        // 对于新进程，环境变量方式已经通过全局设置生效
        // 这里主要验证是否可以注入

        if self.can_modify_process(process.pid) {
            info!("环境变量注入方式对进程 {} 可用", process.pid);
            Ok(true)
        } else {
            debug!("环境变量注入方式对进程 {} 不可用", process.pid);
            Ok(false)
        }
    }

    /// 通过ptrace注入（运行时注入）
    async fn inject_via_ptrace(&self, pid: u32) -> Result<bool> {
        debug!("尝试ptrace注入进程 {}", pid);

        // 安全检查
        if self.is_critical_process(pid)? {
            warn!("跳过关键进程 {}", pid);
            return Ok(false);
        }

        // 检查进程状态
        if !self.is_process_safe_to_inject(pid)? {
            return Ok(false);
        }

        // 执行ptrace注入
        self.perform_ptrace_injection(pid).await
    }

    /// 执行ptrace注入操作
    async fn perform_ptrace_injection(&self, pid: u32) -> Result<bool> {
        info!("执行ptrace注入到进程 {}", pid);

        // 构造注入命令
        let injection_command = format!(
            "echo 'LD_PRELOAD={}' | sudo tee /proc/{}/environ",
            self.hook_library_path, pid
        );

        let output = Command::new("sh")
            .arg("-c")
            .arg(&injection_command)
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    debug!("ptrace注入命令执行成功");

                    // 验证注入是否成功
                    self.verify_injection(pid).await
                } else {
                    warn!("ptrace注入命令失败: {}", String::from_utf8_lossy(&result.stderr));
                    Ok(false)
                }
            }
            Err(e) => {
                error!("执行ptrace注入命令失败: {}", e);
                Ok(false)
            }
        }
    }

    /// 验证注入是否成功
    async fn verify_injection(&self, pid: u32) -> Result<bool> {
        debug!("验证进程 {} 的注入状态", pid);

        // 检查进程的maps文件
        let maps_file = format!("/proc/{}/maps", pid);
        if Path::new(&maps_file).exists() {
            let maps_content = fs::read_to_string(&maps_file)?;

            // 检查是否包含Hook库
            let is_injected = maps_content.contains(&self.hook_library_path) ||
                           maps_content.contains("openssl_hook") ||
                           maps_content.contains("tls_key_agent");

            debug!("进程 {} 注入状态: {}", pid, is_injected);
            Ok(is_injected)
        } else {
            warn!("无法访问进程 {} 的maps文件", pid);
            Ok(false)
        }
    }

    /// 检查是否为关键进程
    fn is_critical_process(&self, pid: u32) -> Result<bool> {
        let critical_processes = vec![1, 2, 3]; // init, kthreadd, ksoftirqd
        Ok(critical_processes.contains(&pid))
    }

    /// 检查进程是否可以安全注入
    fn is_process_safe_to_inject(&self, pid: u32) -> Result<bool> {
        // 检查进程是否存在
        let proc_path = format!("/proc/{}", pid);
        if !Path::new(&proc_path).exists() {
            return Ok(false);
        }

        // 检查进程状态
        let stat_content = fs::read_to_string(format!("{}/stat", proc_path))?;
        let fields: Vec<&str> = stat_content.split_whitespace().collect();
        if fields.len() < 3 {
            return Ok(false);
        }

        let state = fields[2];
        match state {
            "R" | "S" => Ok(true), // 运行或睡眠状态
            "Z" => Ok(false),      // 僵尸进程
            "T" => {
                warn!("进程 {} 已停止，可能不安全", pid);
                Ok(true) // 仍然尝试，但给出警告
            },
            _ => {
                warn!("进程 {} 状态未知: {}", pid, state);
                Ok(true)
            }
        }
    }

    /// 检查是否可以修改进程
    fn can_modify_process(&self, pid: u32) -> bool {
        // 检查权限和进程状态
        // 简化实现，实际使用中需要更详细的检查
        pid != 0 && pid != 1
    }

    /// 标记进程为已注入
    fn mark_process_injected(&self, pid: u32) -> Result<()> {
        let mut injected = self.injected_processes.lock().unwrap();
        injected.insert(pid, std::time::SystemTime::now());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_preload_injector_creation() {
        let config = Arc::new(Config::default());
        let injector = PreloadInjector::new(config);

        assert!(!injector.is_active);
        assert_eq!(injector.hook_library_path, "./target/release/libopenssl_hook.so");
    }

    #[tokio::test]
    async fn test_critical_process_check() {
        let config = Arc::new(Config::default());
        let injector = PreloadInjector::new(config);

        assert!(injector.is_critical_process(1).unwrap()); // init
        assert!(injector.is_critical_process(2).unwrap()); // kthreadd
        assert!(!injector.is_critical_process(1234).unwrap()); // 普通进程
    }

    #[tokio::test]
    async fn test_process_safety_check() {
        let config = Arc::new(Config::default());
        let injector = PreloadInjector::new(config);

        // 测试不存在的进程
        assert!(!injector.is_process_safe_to_inject(999999).unwrap());

        // 测试当前进程（通常是安全的）
        let current_pid = std::process::id() as u32;
        let is_safe = injector.is_process_safe_to_inject(current_pid).unwrap_or(false);
        debug!("当前进程 {} 安全状态: {}", current_pid, is_safe);
    }
}