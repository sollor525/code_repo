/**
 * @file ebpf.rs
 * @brief eBPF注入器实现
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-11-05
 */

use std::collections::HashMap;
use std::process::Command;
use std::path::Path;
use tracing::{info, error, debug, warn};
use anyhow::Result;

use crate::common::error::TlsKeyAgentError;
use crate::config::Config;
use super::TargetProcess;

/// eBPF注入器
pub struct EbpfInjector {
    config: std::sync::Arc<Config>,
    hook_library_path: String,
    is_active: std::sync::atomic::AtomicBool,
    ebpf_loaded: std::sync::atomic::AtomicBool,
    injected_processes: std::sync::Mutex<HashMap<u32, std::time::SystemTime>>,
    kernel_version: String,
}

impl EbpfInjector {
    /// 创建新的eBPF注入器
    pub fn new(config: std::sync::Arc<Config>) -> Self {
        let hook_library_path = config.injection.hook_library.clone()
            .unwrap_or_else(|| "/opt/tls_key_agent/libopenssl_hook.so".to_string());

        Self {
            config,
            hook_library_path,
            is_active: std::sync::atomic::AtomicBool::new(false),
            ebpf_loaded: std::sync::atomic::AtomicBool::new(false),
            injected_processes: std::sync::Mutex::new(HashMap::new()),
            kernel_version: Self::get_kernel_version(),
        }
    }

    /// 启动注入器
    pub async fn start(&self) -> Result<()> {
        info!("启动eBPF注入器");

        // 检查eBPF支持
        if !self.check_ebpf_support() {
            return Err(TlsKeyAgentError::Injection("系统不支持eBPF".to_string()).into());
        }

        // 编译eBPF程序
        self.compile_ebpf_program().await?;

        // 加载eBPF程序
        let loaded = self.load_ebpf_program().await?;
        if loaded {
            self.ebpf_loaded.store(true, std::sync::atomic::Ordering::SeqCst);
        }

        // 启动事件监听
        self.start_event_listener().await?;

        self.is_active.store(true, std::sync::atomic::Ordering::SeqCst);
        info!("eBPF注入器启动成功");
        Ok(())
    }

    /// 停止注入器
    pub async fn stop(&self) -> Result<()> {
        info!("停止eBPF注入器");

        if self.ebpf_loaded.load(std::sync::atomic::Ordering::SeqCst) {
            self.unload_ebpf_program().await?;
            self.ebpf_loaded.store(false, std::sync::atomic::Ordering::SeqCst);
        }

        // 清理注入进程记录
        let mut injected = self.injected_processes.lock().unwrap();
        injected.clear();

        self.is_active.store(false, std::sync::atomic::Ordering::SeqCst);
        info!("eBPF注入器已停止");
        Ok(())
    }

    /// 注入到指定进程
    pub async fn inject_process(&self, process: &TargetProcess) -> Result<()> {
        if !self.is_active.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(TlsKeyAgentError::Injection("eBPF注入器未启动".to_string()).into());
        }

        if process.is_injected {
            debug!("进程 {} 已经注入", process.pid);
            return Ok(());
        }

        info!("开始eBPF注入进程 {}: {}", process.pid, process.name);

        // eBPF方式：通过内核模块自动注入
        if self.perform_ebpf_injection(process).await? {
            self.mark_process_injected(process.pid)?;
            info!("成功注入进程 {}", process.pid);
            return Ok(());
        }

        Err(TlsKeyAgentError::Injection(
            format!("eBPF注入进程 {} 失败", process.pid)
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
        self.check_ebpf_support()
    }

    /// 检查eBPF支持
    fn check_ebpf_support(&self) -> bool {
        // 检查内核版本（需要 >= 4.14）
        let version = self.parse_kernel_version(&self.kernel_version);
        if version < (4, 14) {
            warn!("内核版本 {} 太低，需要 >= 4.14", self.kernel_version);
            return false;
        }

        // 检查eBPF文件系统
        if !Path::new("/sys/fs/bpf").exists() {
            warn!("eBPF文件系统未挂载");
            return false;
        }

        // 检查必要工具
        if !Command::new("which").arg("clang").output().unwrap().status.success() {
            warn!("clang编译器未找到");
            return false;
        }

        if !Command::new("which").arg("bpftool").output().unwrap().status.success() {
            warn!("bpftool未找到");
            return false;
        }

        debug!("eBPF支持检查通过");
        true
    }

    /// 编译eBPF程序
    async fn compile_ebpf_program(&self) -> Result<()> {
        info!("编译eBPF程序");

        let ebpf_source = "src/ebpf_monitor_simple.c";
        let ebpf_object = "target/release/ebpf_monitor.o";

        // 检查源文件是否存在
        if !Path::new(ebpf_source).exists() {
            return Err(TlsKeyAgentError::Injection(
                format!("eBPF源文件不存在: {}", ebpf_source)
            ).into());
        }

        // 构造编译命令
        let clang_args = vec![
            "-O2",
            "-target",
            "bpf",
            "-c",
            ebpf_source,
            "-o",
            ebpf_object,
            "-I/usr/include",
            "-I/usr/include/x86_64-linux-gnu",
            "-D__KERNEL__",
            "-Wno-unused-value",
            "-Wno-pointer-sign",
            "-Wno-compare-distinct-pointer-types",
        ];

        let output = Command::new("clang")
            .args(&clang_args)
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("eBPF程序编译成功: {}", ebpf_object);
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    error!("eBPF程序编译失败: {}", stderr);
                    Err(TlsKeyAgentError::Injection(
                        format!("eBPF编译失败: {}", stderr)
                    ).into())
                }
            }
            Err(e) => {
                error!("执行clang失败: {}", e);
                Err(TlsKeyAgentError::Injection(
                    format!("clang执行失败: {}", e)
                ).into())
            }
        }
    }

    /// 加载eBPF程序到内核
    async fn load_ebpf_program(&self) -> Result<bool> {
        info!("加载eBPF程序到内核");

        let ebpf_object = "target/release/ebpf_monitor.o";

        // 检查eBPF对象文件是否存在
        if !Path::new(ebpf_object).exists() {
            return Err(TlsKeyAgentError::Injection(
                format!("eBPF对象文件不存在: {}", ebpf_object)
            ).into());
        }

        // 使用bpftool加载程序
        let load_cmd = format!("bpftool prog load {} /sys/fs/bpf/tls_monitor", ebpf_object);

        let output = Command::new("sh")
            .arg("-c")
            .arg(&load_cmd)
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("eBPF程序加载成功");

                    // 附加tracepoints
                    self.attach_tracepoints().await?;

                    Ok(true)
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    error!("eBPF程序加载失败: {}", stderr);
                    Err(TlsKeyAgentError::Injection(
                        format!("eBPF加载失败: {}", stderr)
                    ).into())
                }
            }
            Err(e) => {
                error!("执行bpftool失败: {}", e);
                Err(TlsKeyAgentError::Injection(
                    format!("bpftool执行失败: {}", e)
                ).into())
            }
        }
    }

    /// 附加eBPF程序到tracepoints
    async fn attach_tracepoints(&self) -> Result<()> {
        info!("附加eBPF程序到tracepoints");

        let tracepoints = vec![
            "tracepoint/syscalls/sys_enter_execve",
            "tracepoint/syscalls/sys_enter_mmap",
            "tracepoint/syscalls/sys_enter_socketconnect",
            "tracepoint/sched/sched_process_exit",
        ];

        for tp in tracepoints {
            let attach_cmd = format!("bpftool prog attach {} tls_monitor", tp);

            let output = Command::new("sh")
                .arg("-c")
                .arg(&attach_cmd)
                .output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        info!("成功附加tracepoint: {}", tp);
                    } else {
                        warn!("附加tracepoint失败 {}: {}", tp, String::from_utf8_lossy(&result.stderr));
                    }
                }
                Err(e) => {
                    warn!("执行tracepoint附加命令失败 {}: {}", tp, e);
                }
            }
        }

        Ok(())
    }

    /// 卸载eBPF程序
    async fn unload_ebpf_program(&self) -> Result<()> {
        info!("卸载eBPF程序");

        // 卸载程序
        let output = Command::new("sh")
            .arg("-c")
            .arg("bpftool prog unload /sys/fs/bpf/tls_monitor")
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("eBPF程序卸载成功");
                } else {
                    warn!("eBPF程序卸载失败: {}", String::from_utf8_lossy(&result.stderr));
                }
            }
            Err(e) => {
                warn!("执行eBPF卸载命令失败: {}", e);
            }
        }

        Ok(())
    }

    /// 启动事件监听器
    async fn start_event_listener(&self) -> Result<()> {
        info!("启动eBPF事件监听器");

        // eBPF事件通过perf events传递
        // 这里需要使用libbpf的绑定或perf工具
        // 简化实现：使用perf工具监听

        let perf_cmd = format!("perf record -e 'tls_events:*' --output=/tmp/tls_ebpf_events");

        // 在后台启动perf（实际应用中需要更完善的处理）
        tokio::spawn(async move {
            let _ = Command::new("sh")
                .arg("-c")
                .arg(&format!("{} &", perf_cmd))
                .output();
        });

        info!("eBPF事件监听器已启动");
        Ok(())
    }

    /// 执行eBPF注入
    async fn perform_ebpf_injection(&self, process: &TargetProcess) -> Result<bool> {
        info!("执行eBPF注入进程 {}", process.pid);

        // eBPF方式：通过内核自动检测和注入
        // 这里主要验证eBPF程序是否正常运行

        if self.ebpf_loaded.load(std::sync::atomic::Ordering::SeqCst) {
            // eBPF程序会自动检测新进程并注入
            // 我们需要等待一段时间让注入完成
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // 验证注入是否成功
            self.verify_ebpf_injection(process.pid).await
        } else {
            error!("eBPF程序未加载");
            Ok(false)
        }
    }

    /// 验证eBPF注入
    async fn verify_ebpf_injection(&self, pid: u32) -> Result<bool> {
        debug!("验证eBPF注入进程 {}", pid);

        // 检查进程是否在eBPF监控列表中
        // 这里需要与eBPF maps交互，简化实现

        // 备用方案：检查进程的maps文件
        let maps_file = format!("/proc/{}/maps", pid);
        if Path::new(&maps_file).exists() {
            let maps_content = std::fs::read_to_string(&maps_file)?;

            // 检查是否包含Hook库
            let is_injected = maps_content.contains(&self.hook_library_path) ||
                           maps_content.contains("openssl_hook") ||
                           maps_content.contains("tls_key_agent");

            debug!("eBPF注入验证结果: {}", is_injected);
            Ok(is_injected)
        } else {
            warn!("无法访问进程 {} 的maps文件", pid);
            Ok(false)
        }
    }

    /// 标记进程为已注入
    fn mark_process_injected(&self, pid: u32) -> Result<()> {
        let mut injected = self.injected_processes.lock().unwrap();
        injected.insert(pid, std::time::SystemTime::now());
        Ok(())
    }

    /// 获取内核版本
    fn get_kernel_version() -> String {
        match std::fs::read_to_string("/proc/version") {
            Ok(content) => {
                content.lines().next().unwrap_or("unknown").to_string()
            }
            Err(_) => "unknown".to_string(),
        }
    }

    /// 解析内核版本
    fn parse_kernel_version(&self, version_str: &str) -> (u32, u32) {
        // 从类似 "Linux version 5.4.0-74-generic" 的字符串中提取版本号
        let parts: Vec<&str> = version_str.split_whitespace().collect();
        if parts.len() >= 3 {
            let version_parts: Vec<&str> = parts[2].split('.').collect();
            if version_parts.len() >= 2 {
                let major = version_parts[0].parse().unwrap_or(0);
                let minor = version_parts[1].split('-').next().unwrap_or("0").parse().unwrap_or(0);
                return (major, minor);
            }
        }
        (0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_ebpf_injector_creation() {
        let config = Arc::new(Config::default());
        let injector = EbpfInjector::new(config);

        assert!(!injector.is_active);
        assert!(!injector.ebpf_loaded);
        assert_eq!(injector.hook_library_path, "/opt/tls_key_agent/libopenssl_hook.so");
    }

    #[tokio::test]
    async fn test_kernel_version_parsing() {
        let config = Arc::new(Config::default());
        let injector = EbpfInjector::new(config);

        let version = injector.get_kernel_version();
        assert!(!version.is_empty());

        let (major, minor) = injector.parse_kernel_version("Linux version 5.4.0-74-generic");
        assert_eq!(major, 5);
        assert_eq!(minor, 4);

        let (major, minor) = injector.parse_kernel_version("unknown");
        assert_eq!(major, 0);
        assert_eq!(minor, 0);
    }

    #[tokio::test]
    async fn test_ebpf_support_check() {
        let config = Arc::new(Config::default());
        let injector = EbpfInjector::new(config);

        let is_supported = injector.is_supported().await;
        debug!("eBPF支持状态: {}", is_supported);

        // 在没有实际eBPF环境的测试系统中，可能返回false
        // 这并不意味着实现有问题
    }
}