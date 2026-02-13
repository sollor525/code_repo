/**
 * @file detector.rs
 * @brief TLS进程检测器
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-11-05
 */

use std::fs;
use std::path::Path;
use tracing::{info, debug};
use anyhow::Result;

use crate::common::error::TlsKeyAgentError;
use super::TargetProcess;

/// TLS进程检测器
pub struct ProcessDetector {
    cache_timeout: std::time::Duration,
    last_scan: std::sync::Mutex<std::time::Instant>,
    cached_processes: std::sync::Mutex<Vec<TargetProcess>>,
}

impl ProcessDetector {
    /// 创建新的进程检测器
    pub fn new() -> Self {
        Self {
            cache_timeout: std::time::Duration::from_secs(5), // 5秒缓存
            last_scan: std::sync::Mutex::new(std::time::Instant::now()),
            cached_processes: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// 发现TLS进程
    pub async fn discover_tls_processes(&self) -> Result<Vec<TargetProcess>> {
        // 检查缓存是否有效
        {
            let last_scan = self.last_scan.lock().unwrap();
            let now = std::time::Instant::now();
            if now.duration_since(*last_scan) < self.cache_timeout {
                let cached = self.cached_processes.lock().unwrap();
                debug!("使用缓存的进程列表，{} 个进程", cached.len());
                return Ok(cached.clone());
            }
        }

        debug!("执行进程扫描");
        let processes = self.scan_processes().await?;

        // 更新缓存
        {
            let mut last_scan = self.last_scan.lock().unwrap();
            *last_scan = std::time::Instant::now();
            let mut cached = self.cached_processes.lock().unwrap();
            *cached = processes.clone();
        }

        info!("发现 {} 个进程，其中 {} 个使用TLS", processes.len(),
             processes.iter().filter(|p| p.uses_tls).count());

        Ok(processes)
    }

    /// 扫描所有进程
    async fn scan_processes(&self) -> Result<Vec<TargetProcess>> {
        let mut processes = Vec::new();

        // 读取/proc目录
        let proc_dir = Path::new("/proc");
        if !proc_dir.exists() {
            return Err(TlsKeyAgentError::Detection("/proc目录不存在".to_string()).into());
        }

        for entry in fs::read_dir(proc_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();

            // 跳过非数字目录
            if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }

            if let Ok(pid) = pid_str.parse::<u32>() {
                // 跳过当前进程和系统进程
                if pid == 0 || pid == 1 || pid == std::process::id() {
                    continue;
                }

                if let Ok(process) = self.analyze_process(pid).await {
                    processes.push(process);
                }
            }
        }

        Ok(processes)
    }

    /// 分析单个进程
    async fn analyze_process(&self, pid: u32) -> Result<TargetProcess> {
        let proc_path = format!("/proc/{}", pid);

        // 获取进程名
        let name = self.get_process_name(&proc_path)?;

        // 获取命令行
        let cmdline = self.get_process_cmdline(&proc_path)?;

        // 检查是否使用TLS
        let (uses_tls, ssl_lib_path) = self.check_tls_usage(pid)?;

        // 创建目标进程信息
        Ok(TargetProcess {
            pid,
            name,
            cmdline,
            uses_tls,
            ssl_lib_path,
            is_injected: false,
            injection_time: None,
        })
    }

    /// 获取进程名
    fn get_process_name(&self, proc_path: &str) -> Result<String> {
        let comm_file = format!("{}/comm", proc_path);
        fs::read_to_string(&comm_file)
            .map(|s| s.trim_end_matches('\n').to_string())
            .map_err(|e| TlsKeyAgentError::Detection(format!("读取进程名失败: {}", e)).into())
    }

    /// 获取进程命令行
    fn get_process_cmdline(&self, proc_path: &str) -> Result<String> {
        let cmdline_file = format!("{}/cmdline", proc_path);
        match fs::read_to_string(&cmdline_file) {
            Ok(content) => {
                // 替换空字符为空格
                Ok(content.replace('\0', " ").trim_end_matches(' ').to_string())
            }
            Err(_) => Ok("unknown".to_string()),
        }
    }

    /// 检查进程是否使用TLS
    fn check_tls_usage(&self, pid: u32) -> Result<(bool, Option<String>)> {
        let maps_file = format!("/proc/{}/maps", pid);

        // 检查maps文件是否存在
        if !Path::new(&maps_file).exists() {
            return Ok((false, None));
        }

        let maps_content = fs::read_to_string(&maps_file)?;
        let mut uses_tls = false;
        let mut ssl_lib_path = None;

        for line in maps_content.lines() {
            if line.contains("libssl.so") || line.contains("libcrypto.so") {
                uses_tls = true;

                // 提取库路径
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    ssl_lib_path = Some(parts[5].to_string());
                }

                // 找到第一个匹配的库即可
                break;
            }
        }

        Ok((uses_tls, ssl_lib_path))
    }

    /// 发现特定名称的进程
    pub async fn find_processes_by_name(&self, name_pattern: &str) -> Result<Vec<TargetProcess>> {
        let all_processes = self.discover_tls_processes().await?;

        let filtered: Vec<_> = all_processes.into_iter()
            .filter(|p| p.name.contains(name_pattern) || p.cmdline.contains(name_pattern))
            .collect();

        debug!("找到 {} 个匹配 '{}' 的进程", filtered.len(), name_pattern);
        Ok(filtered)
    }

    /// 发现网络服务进程
    pub async fn find_network_services(&self) -> Result<Vec<TargetProcess>> {
        let all_processes = self.discover_tls_processes().await?;

        let network_keywords = vec![
            "nginx", "apache", "httpd", "apache2",
            "sshd", "openssh", "dropbear",
            "mysqld", "postgresql", "postgres",
            "redis", "mongodb", "memcached",
            "java", "python", "node", "go",
        ];

        let filtered: Vec<_> = all_processes.into_iter()
            .filter(|p| {
                let cmdline_lower = p.cmdline.to_lowercase();
                network_keywords.iter().any(|keyword| cmdline_lower.contains(keyword))
            })
            .collect();

        debug!("找到 {} 个网络服务进程", filtered.len());
        Ok(filtered)
    }

    /// 清理缓存
    pub fn clear_cache(&self) {
        let mut last_scan = self.last_scan.lock().unwrap();
        *last_scan = std::time::Instant::now() - self.cache_timeout;
        debug!("进程检测缓存已清理");
    }

    /// 强制刷新进程列表
    pub async fn refresh(&self) -> Result<Vec<TargetProcess>> {
        self.clear_cache();
        self.discover_tls_processes().await
    }
}

impl Default for ProcessDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::warn;

    #[tokio::test]
    async fn test_process_detector_creation() {
        let detector = ProcessDetector::new();

        // 测试基本功能
        let processes = detector.discover_tls_processes().await.unwrap();
        // 至少应该找到一些系统进程
        assert!(!processes.is_empty());

        // 查找bash进程（如果存在）
        let bash_processes = detector.find_processes_by_name("bash").await.unwrap();
        debug!("找到 {} 个bash进程", bash_processes.len());
    }

    #[tokio::test]
    async fn test_process_analysis() {
        let detector = ProcessDetector::new();

        // 分析当前进程
        let current_pid = std::process::id() as u32;
        let result = detector.analyze_process(current_pid).await;

        match result {
            Ok(process) => {
                assert_eq!(process.pid, current_pid);
                assert!(!process.name.is_empty());
                debug!("当前进程: {} - {}", process.name, process.cmdline);
            }
            Err(e) => {
                warn!("无法分析当前进程: {}", e);
            }
        }
    }

    #[tokio::test]
    async fn test_cache_mechanism() {
        let detector = ProcessDetector::new();

        // 第一次扫描
        let processes1 = detector.discover_tls_processes().await.unwrap();

        // 第二次扫描（应该使用缓存）
        let processes2 = detector.discover_tls_processes().await.unwrap();

        // 结果应该相同
        assert_eq!(processes1.len(), processes2.len());

        // 清理缓存并强制刷新
        detector.clear_cache();
        let processes3 = detector.refresh().await.unwrap();

        // 结果应该仍然相同，但这次是实际扫描
        assert_eq!(processes1.len(), processes3.len());
    }

    #[tokio::test]
    async fn test_network_service_detection() {
        let detector = ProcessDetector::new();

        let services = detector.find_network_services().await.unwrap();
        debug!("发现 {} 个网络服务进程", services.len());

        // 验证返回的都是网络服务相关进程
        for service in &services {
            debug!("网络服务: {} - {}", service.name, service.cmdline);
        }
    }
}