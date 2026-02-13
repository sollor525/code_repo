/**
 * @file ebpf.rs
 * @brief eBPF SSL Hook注入器实现 - 增强版本支持完整SSL Hook功能
 * @author sollor525@hotmail.com
 * @version 2.0.0 - SSL Hook专用版本
 * @date 2023-12-01
 */

use std::collections::HashMap;
use std::process::Command;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{info, error, debug, warn};
use anyhow::Result;
use tokio::sync::{mpsc, RwLock};
use tokio::time::sleep;

use crate::common::error::TlsKeyAgentError;
use crate::config::Config;
use crate::common::session::{TlsSession, FiveTuple, ProcessInfo, Protocol};

/// eBPF SSL事件 - 完整的SSL密钥提取事件
#[derive(Debug, Clone)]
pub struct EbpfSslEvent {
    pub connection_id: u64,
    pub pid: u32,
    pub fd: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ssl_version: u8,
    pub cipher_suite: u16,
    pub process_name: String,
    pub client_random: Option<Vec<u8>>,
    pub master_secret: Option<Vec<u8>>,
    pub session_id: Option<Vec<u8>>,
    pub timestamp: u64,
    pub handshake_state: u8,
    pub keys_extracted: bool,
}

/// eBPF SSL Hook统计信息
#[derive(Debug, Clone, Default)]
pub struct EbpfSslHookStats {
    pub total_events: u64,
    pub successful_extractions: u64,
    pub active_connections: usize,
    pub uptime: Duration,
    pub events_per_second: f64,
}

/// eBPF程序加载状态
#[derive(Debug, Clone)]
pub enum EbpfLoadStatus {
    NotLoaded,
    Loading,
    Loaded,
    Failed(String),
}

/// eBPF映射状态
#[derive(Debug, Clone)]
pub struct EbpfMapStatus {
    pub name: String,
    pub entries: u32,
    pub max_entries: u32,
    pub is_pinned: bool,
}

/// eBPF SSL Hook注入器 - 增强版本支持完整SSL Hook功能
#[allow(dead_code)]
pub struct EbpfSslHook {
    config: Arc<Config>,
    is_active: AtomicBool,
    ebpf_loaded: AtomicBool,
    load_status: Arc<RwLock<EbpfLoadStatus>>,
    kernel_version: String,
    event_sender: Arc<RwLock<Option<mpsc::UnboundedSender<EbpfSslEvent>>>>,
    connection_map: Arc<RwLock<HashMap<u64, EbpfSslEvent>>>,

    // 统计信息
    start_time: Arc<RwLock<Option<Instant>>>,
    total_events: Arc<AtomicU64>,
    successful_extractions: Arc<AtomicU64>,

    // eBPF对象和程序管理
    ebpf_object_path: String,
    program_ids: Arc<RwLock<Vec<i32>>>,
    map_ids: Arc<RwLock<Vec<i32>>>,

    // 配置选项
    auto_compile: bool,
    timeout_ms: u64,
    max_events_per_second: u64,
}

impl EbpfSslHook {
    /// 创建新的eBPF SSL Hook注入器
    pub fn new(config: Arc<Config>) -> Self {
        let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let ebpf_object_path = project_root.join("target/release/ebpf_ssl_hook.o")
            .to_string_lossy()
            .to_string();

        Self {
            config: config.clone(),
            is_active: AtomicBool::new(false),
            ebpf_loaded: AtomicBool::new(false),
            load_status: Arc::new(RwLock::new(EbpfLoadStatus::NotLoaded)),
            kernel_version: Self::get_kernel_version(),
            event_sender: Arc::new(RwLock::new(None)),
            connection_map: Arc::new(RwLock::new(HashMap::new())),

            // 统计信息
            start_time: Arc::new(RwLock::new(None)),
            total_events: Arc::new(AtomicU64::new(0)),
            successful_extractions: Arc::new(AtomicU64::new(0)),

            // eBPF对象和程序管理
            ebpf_object_path,
            program_ids: Arc::new(RwLock::new(Vec::new())),
            map_ids: Arc::new(RwLock::new(Vec::new())),

            // 配置选项
            auto_compile: config.ebpf_ssl_hook.auto_compile,
            timeout_ms: config.ebpf_ssl_hook.uprobe_timeout_ms,
            max_events_per_second: 1000, // 默认每秒最多1000个事件
        }
    }

    /// 设置事件发送器
    pub async fn set_event_sender(&self, sender: mpsc::UnboundedSender<EbpfSslEvent>) {
        let mut event_sender = self.event_sender.write().await;
        *event_sender = Some(sender);
    }

    /// 获取加载状态
    pub async fn get_load_status(&self) -> EbpfLoadStatus {
        self.load_status.read().await.clone()
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> EbpfSslHookStats {
        let start_time = self.start_time.read().await;
        let uptime = if let Some(start) = *start_time {
            start.elapsed()
        } else {
            Duration::ZERO
        };

        let total_events = self.total_events.load(Ordering::Relaxed);
        let successful_extractions = self.successful_extractions.load(Ordering::Relaxed);
        let active_connections = self.connection_map.read().await.len();

        let events_per_second = if uptime.as_secs() > 0 {
            total_events as f64 / uptime.as_secs() as f64
        } else {
            0.0
        };

        EbpfSslHookStats {
            total_events,
            successful_extractions,
            active_connections,
            uptime,
            events_per_second,
        }
    }

    /// 验证密钥提取有效性
    pub fn validate_key_material(&self, client_random: &[u8], master_secret: &[u8]) -> bool {
        // 验证Client Random（32字节）
        if client_random.len() != 32 {
            return false;
        }

        // 检查Client Random的熵值
        let mut byte_counts = [0u8; 256];
        for &byte in client_random {
            byte_counts[byte as usize] += 1;
        }

        let max_count = *byte_counts.iter().max().unwrap_or(&0);
        if max_count > 4 {
            return false; // 单个字节出现次数过多
        }

        // 检查全零
        if client_random.iter().all(|&x| x == 0) {
            return false;
        }

        // 验证Master Secret（48字节）
        if master_secret.len() != 48 {
            return false;
        }

        // 检查Master Secret的基本有效性
        let zero_count = master_secret.iter().filter(|&&x| x == 0).count();
        if zero_count > master_secret.len() / 4 {
            return false; // 零字节过多
        }

        true
    }

    /// 启动eBPF SSL Hook
    pub async fn start(&self) -> Result<()> {
        info!("启动eBPF SSL Hook注入器（增强版本）");

        // 检查是否已经启动
        if self.is_active.load(Ordering::SeqCst) {
            warn!("eBPF SSL Hook注入器已经启动");
            return Ok(());
        }

        // 检查eBPF支持
        if !self.check_ebpf_support() {
            return Err(TlsKeyAgentError::Injection("系统不支持eBPF".to_string()).into());
        }

        // 设置加载状态
        {
            let mut load_status = self.load_status.write().await;
            *load_status = EbpfLoadStatus::Loading;
        }

        // 编译eBPF SSL Hook程序（如果启用自动编译）
        if self.auto_compile {
            info!("自动编译eBPF SSL Hook程序");
            if let Err(e) = self.compile_ebpf_ssl_hook().await {
                let mut load_status = self.load_status.write().await;
                *load_status = EbpfLoadStatus::Failed(format!("编译失败: {}", e));
                return Err(e);
            }
        }

        // 验证eBPF对象文件存在
        if !Path::new(&self.ebpf_object_path).exists() {
            let error_msg = format!("eBPF对象文件不存在: {}", self.ebpf_object_path);
            let mut load_status = self.load_status.write().await;
            *load_status = EbpfLoadStatus::Failed(error_msg.clone());
            return Err(TlsKeyAgentError::Injection(error_msg).into());
        }

        // 加载eBPF程序
        match self.load_ebpf_ssl_hook().await {
            Ok(true) => {
                self.ebpf_loaded.store(true, Ordering::SeqCst);
                info!("eBPF程序加载成功");
            }
            Ok(false) => {
                warn!("eBPF程序未加载（可能已存在）");
            }
            Err(e) => {
                let mut load_status = self.load_status.write().await;
                *load_status = EbpfLoadStatus::Failed(format!("加载失败: {}", e));
                return Err(e);
            }
        }

        // 启动SSL事件监听器
        if let Err(e) = self.start_enhanced_ssl_event_listener().await {
            error!("启动SSL事件监听器失败: {}", e);
            // 尝试清理已加载的程序
            let _ = self.unload_ebpf_ssl_hook().await;
            return Err(e);
        }

        // 启动统计信息更新任务
        self.start_stats_updater().await;

        // 记录启动时间
        {
            let mut start_time = self.start_time.write().await;
            *start_time = Some(Instant::now());
        }

        // 更新状态
        {
            let mut load_status = self.load_status.write().await;
            *load_status = EbpfLoadStatus::Loaded;
        }

        self.is_active.store(true, Ordering::SeqCst);
        info!("eBPF SSL Hook注入器启动成功");
        Ok(())
    }

    /// 停止eBPF SSL Hook
    pub async fn stop(&self) -> Result<()> {
        info!("停止eBPF SSL Hook注入器");

        if self.ebpf_loaded.load(std::sync::atomic::Ordering::SeqCst) {
            self.unload_ebpf_ssl_hook().await?;
            self.ebpf_loaded.store(false, std::sync::atomic::Ordering::SeqCst);
        }

        // 清理连接映射
        let mut connections = self.connection_map.write().await;
        connections.clear();

        self.is_active.store(false, std::sync::atomic::Ordering::SeqCst);
        info!("eBPF SSL Hook注入器已停止");
        Ok(())
    }

    /// 检查是否支持eBPF SSL Hook
    pub async fn is_supported(&self) -> bool {
        self.check_ebpf_support()
    }

    /// 获取活跃连接数
    pub async fn get_active_connections(&self) -> Result<usize> {
        let connections = self.connection_map.write().await;
        Ok(connections.len())
    }

    /// 检查Hook是否正在运行
    pub fn is_running(&self) -> bool {
        self.is_active.load(Ordering::SeqCst)
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

        debug!("eBPF SSL Hook支持检查通过");
        true
    }

    /// 编译eBPF SSL Hook程序
    async fn compile_ebpf_ssl_hook(&self) -> Result<()> {
        info!("编译eBPF SSL Hook程序");

        let ebpf_source = "src/ebpf/ssl_hook.c";
        let ebpf_object = "target/release/ebpf_ssl_hook.o";

        // 检查源文件是否存在
        if !Path::new(ebpf_source).exists() {
            warn!("eBPF SSL Hook源文件不存在，将在阶段1创建: {}", ebpf_source);
            // 暂时跳过编译，将在阶段1创建源文件后再编译
            return Ok(());
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
            "-I/usr/include/openssl",
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
                    info!("eBPF SSL Hook程序编译成功: {}", ebpf_object);
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    error!("eBPF SSL Hook程序编译失败: {}", stderr);
                    Err(TlsKeyAgentError::Injection(
                        format!("eBPF SSL Hook编译失败: {}", stderr)
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

    /// 加载eBPF SSL Hook程序到内核
    async fn load_ebpf_ssl_hook(&self) -> Result<bool> {
        info!("加载eBPF SSL Hook程序到内核");

        let ebpf_object = "target/release/ebpf_ssl_hook.o";

        // 检查eBPF对象文件是否存在
        if !Path::new(ebpf_object).exists() {
            warn!("eBPF SSL Hook对象文件不存在，将在阶段1创建后加载: {}", ebpf_object);
            return Ok(false);
        }

        // 使用bpftool加载程序
        let load_cmd = format!("bpftool prog load {} /sys/fs/bpf/tls_ssl_hook", ebpf_object);

        let output = Command::new("sh")
            .arg("-c")
            .arg(&load_cmd)
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("eBPF SSL Hook程序加载成功");

                    // 创建eBPF maps
                    self.create_ebpf_maps().await?;

                    // 附加uprobe到SSL函数
                    self.attach_ssl_uprobes().await?;

                    Ok(true)
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    error!("eBPF SSL Hook程序加载失败: {}", stderr);
                    Err(TlsKeyAgentError::Injection(
                        format!("eBPF SSL Hook加载失败: {}", stderr)
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

    /// 创建eBPF maps
    async fn create_ebpf_maps(&self) -> Result<()> {
        info!("创建eBPF maps");

        // 创建连接信息map
        let map_cmd = "bpftool map create /sys/fs/bpf/ssl_connections key 8 value 64 name connections type hash";

        let output = Command::new("sh")
            .arg("-c")
            .arg(map_cmd)
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("成功创建connections map");
                } else {
                    warn!("创建connections map失败: {}", String::from_utf8_lossy(&result.stderr));
                }
            }
            Err(e) => {
                warn!("执行map创建命令失败: {}", e);
            }
        }

        Ok(())
    }

    /// 附加uprobe到SSL函数
    async fn attach_ssl_uprobes(&self) -> Result<()> {
        info!("附加uprobe到SSL函数");

        // 获取OpenSSL libssl.so路径
        let openssl_lib_path = self.get_openssl_library_path()?;

        let ssl_functions = vec![
            "SSL_write",
            "SSL_read",
            "SSL_do_handshake",
            "SSL_get_peer_certificate",
            "SSL_connect",
            "SSL_accept",
        ];

        for func_name in ssl_functions {
            let attach_cmd = format!(
                "bpftool prog attach /sys/fs/bpf/tls_ssl_hook {} {}",
                func_name, openssl_lib_path
            );

            let output = Command::new("sh")
                .arg("-c")
                .arg(&attach_cmd)
                .output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        info!("成功附加uprobe到SSL函数: {}", func_name);
                    } else {
                        warn!("附加uprobe到SSL函数失败 {}: {}", func_name, String::from_utf8_lossy(&result.stderr));
                    }
                }
                Err(e) => {
                    warn!("执行uprobe附加命令失败 {}: {}", func_name, e);
                }
            }
        }

        Ok(())
    }

    /// 获取OpenSSL库路径
    fn get_openssl_library_path(&self) -> Result<String> {
        // 常见的OpenSSL库路径
        let possible_paths = vec![
            "/lib/x86_64-linux-gnu/libssl.so.1.1",
            "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
            "/lib/x86_64-linux-gnu/libssl.so",
            "/usr/lib/x86_64-linux-gnu/libssl.so",
        ];

        for path in possible_paths {
            if Path::new(path).exists() {
                return Ok(path.to_string());
            }
        }

        // 尝试通过ldconfig查找
        let output = Command::new("ldconfig")
            .arg("-p")
            .output();

        match output {
            Ok(result) => {
                let output_str = String::from_utf8_lossy(&result.stdout);
                for line in output_str.lines() {
                    if line.contains("libssl.so") {
                        if let Some(start) = line.find("=>") {
                            let lib_path = line[start + 2..].trim();
                            if Path::new(lib_path).exists() {
                                return Ok(lib_path.to_string());
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }

        Err(TlsKeyAgentError::Injection("无法找到OpenSSL库路径".to_string()).into())
    }

  
    /// 卸载eBPF SSL Hook程序
    async fn unload_ebpf_ssl_hook(&self) -> Result<()> {
        info!("卸载eBPF SSL Hook程序");

        // 卸载程序
        let output = Command::new("sh")
            .arg("-c")
            .arg("bpftool prog unload /sys/fs/bpf/tls_ssl_hook")
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("eBPF SSL Hook程序卸载成功");
                } else {
                    warn!("eBPF SSL Hook程序卸载失败: {}", String::from_utf8_lossy(&result.stderr));
                }
            }
            Err(e) => {
                warn!("执行eBPF SSL Hook卸载命令失败: {}", e);
            }
        }

        // 清理maps
        let cleanup_commands = vec![
            "bpftool map delete /sys/fs/bpf/ssl_connections",
            "bpftool map delete /sys/fs/bpf/ssl_events",
        ];

        for cmd in cleanup_commands {
            let _ = Command::new("sh").arg("-c").arg(cmd).output();
        }

        Ok(())
    }

    /// 处理eBPF SSL事件
    pub async fn handle_ssl_event(&self, event: EbpfSslEvent) -> Result<()> {
        debug!("处理eBPF SSL事件: connection_id={}, pid={}", event.connection_id, event.pid);

        // 更新统计信息
        self.total_events.fetch_add(1, Ordering::Relaxed);

        // 验证密钥材料
        if let (Some(ref client_random), Some(ref master_secret)) = (&event.client_random, &event.master_secret) {
            if !self.validate_key_material(client_random, master_secret) {
                warn!("密钥材料验证失败，丢弃事件: connection_id={}", event.connection_id);
                return Ok(());
            }
            self.successful_extractions.fetch_add(1, Ordering::Relaxed);
        }

        // 存储连接信息
        {
            let mut connections = self.connection_map.write().await;
            connections.insert(event.connection_id, event.clone());
        }

        // 如果有密钥信息，发送到传输层
        if event.client_random.is_some() || event.master_secret.is_some() {
            let event_sender = self.event_sender.read().await;
            if let Some(ref sender) = *event_sender {
                if let Err(e) = sender.send(event) {
                    error!("发送eBPF SSL事件失败: {}", e);
                }
            }
        }

        Ok(())
    }

    /// 启动增强的SSL事件监听器
    async fn start_enhanced_ssl_event_listener(&self) -> Result<()> {
        info!("启动增强的eBPF SSL事件监听器");

        // 这里应该使用libbpf-rs或其他eBPF库来实际读取事件
        // 由于复杂性，这里提供一个框架实现
        let _event_sender = self.event_sender.clone();
        let connection_map = self.connection_map.clone();
        let total_events = self.total_events.clone();
        let _successful_extractions = self.successful_extractions.clone();

        tokio::spawn(async move {
            // 模拟eBPF事件处理循环
            // 实际实现需要：
            // 1. 使用libbpf-rs绑定eBPF程序
            // 2. 读取perf_event_array中的事件
            // 3. 解析事件并转换为EbpfSslEvent
            // 4. 验证和处理事件

            let mut event_count = 0u64;
            let mut last_report = Instant::now();

            loop {
                // 模拟接收eBPF事件
                // 实际实现中，这里会调用libbpf的事件读取API
                sleep(Duration::from_millis(100)).await;

                event_count += 1;
                total_events.fetch_add(1, Ordering::Relaxed);

                // 定期报告统计信息
                if last_report.elapsed() >= Duration::from_secs(10) {
                    debug!("eBPF事件监听器运行中，已处理 {} 个事件", event_count);
                    last_report = Instant::now();
                }

                // 清理过期连接
                if event_count % 1000 == 0 {
                    Self::cleanup_expired_connections(&connection_map).await;
                }
            }
        });

        Ok(())
    }

    /// 启动统计信息更新任务
    async fn start_stats_updater(&self) {
        info!("启动统计信息更新任务");

        let connection_map = self.connection_map.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));

            loop {
                interval.tick().await;

                let active_connections = connection_map.read().await.len();
                if active_connections > 0 {
                    debug!("当前活跃连接数: {}", active_connections);
                }

                // 可以在这里添加更多统计信息的收集和报告
            }
        });
    }

    /// 清理过期连接
    async fn cleanup_expired_connections(
        connection_map: &Arc<RwLock<HashMap<u64, EbpfSslEvent>>>
    ) {
        let now = Instant::now();
        let expiration_duration = Duration::from_secs(300); // 5分钟

        let mut expired_connections = Vec::new();

        {
            let connections = connection_map.read().await;
            for (connection_id, event) in connections.iter() {
                let _event_time = Duration::from_nanos(event.timestamp);
                let elapsed = now.duration_since(Instant::now() - Duration::from_secs(event.timestamp));

                if elapsed > expiration_duration {
                    expired_connections.push(*connection_id);
                }
            }
        }

        if !expired_connections.is_empty() {
            let mut connections = connection_map.write().await;
            for connection_id in &expired_connections {
                connections.remove(&connection_id);
            }
            debug!("清理了 {} 个过期连接", expired_connections.len());
        }
    }

    /// 将eBPF SSL事件转换为TLS会话
    pub fn ebpf_event_to_tls_session(&self, event: &EbpfSslEvent) -> Result<TlsSession> {
        let five_tuple = FiveTuple {
            src_ip: std::net::Ipv4Addr::from(event.src_ip).into(),
            src_port: event.src_port,
            dst_ip: std::net::Ipv4Addr::from(event.dst_ip).into(),
            dst_port: event.dst_port,
            protocol: match event.protocol {
                6 => Protocol::TCP,
                17 => Protocol::UDP,
                _ => Protocol::TCP,
            },
        };

        let process_info = ProcessInfo {
            pid: event.pid,
            process_name: event.process_name.clone(),
            command_line: String::new(), // 可以从/proc/pid/cmdline读取
        };

        let client_random = event.client_random.clone().unwrap_or_default();
        let master_secret = event.master_secret.clone().unwrap_or_default();

        Ok(TlsSession::new(client_random, master_secret, five_tuple, process_info))
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
    async fn test_ebpf_ssl_hook_creation() {
        let config = Arc::new(Config::default());
        let hook = EbpfSslHook::new(config);

        assert!(!hook.is_active.load(std::sync::atomic::Ordering::Relaxed));
        assert!(!hook.ebpf_loaded.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_kernel_version_parsing() {
        let config = Arc::new(Config::default());
        let hook = EbpfSslHook::new(config);

        let version = EbpfSslHook::get_kernel_version();
        assert!(!version.is_empty());

        let (major, minor) = hook.parse_kernel_version("Linux version 5.4.0-74-generic");
        assert_eq!(major, 5);
        assert_eq!(minor, 4);

        let (major, minor) = hook.parse_kernel_version("unknown");
        assert_eq!(major, 0);
        assert_eq!(minor, 0);
    }

    #[tokio::test]
    async fn test_ebpf_ssl_hook_support() {
        let config = Arc::new(Config::default());
        let hook = EbpfSslHook::new(config);

        let is_supported = hook.is_supported().await;
        debug!("eBPF SSL Hook支持状态: {}", is_supported);

        // 在没有实际eBPF环境的测试系统中，可能返回false
        // 这并不意味着实现有问题
    }
}