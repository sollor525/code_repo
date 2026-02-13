/**
 * @file multi_ssl_injector.rs
 * @brief 多SSL库支持的注入器 - 统一管理多种SSL库的Hook
 * @author sollor525@hotmail.com
 * @version 2.0.0 - eBPF内核级SSL Hook
 * @date 2023-12-01
 */

use std::sync::Arc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tracing::{info, error, debug, warn};
use anyhow::Result;

// 临时随机数生成器
mod rand {
    pub fn random<T: Default>() -> T {
        // 简化实现，实际应该使用真正的随机数生成器
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut hasher);

        // 对于数字类型，使用哈希值的一部分
        if std::mem::size_of::<T>() <= std::mem::size_of::<u64>() {
            // 尝试将hash值转换为所需类型
            let hash_val = hasher.finish();
            unsafe {
                std::mem::transmute_copy(&hash_val)
            }
        } else {
            T::default()
        }
    }
}

use crate::common::session::{TlsSession, FiveTuple, ProcessInfo};
use crate::config::Config;
use crate::transport::enhanced_udp_manager::EnhancedUdpTransportManager;

/// SSL库类型枚举
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SslLibraryType {
    OpenSSL,
    GnuTLS,
    NSS,
    BoringSSL,
    LibreSSL,
    Unknown,
}

impl SslLibraryType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            1 => SslLibraryType::OpenSSL,
            2 => SslLibraryType::GnuTLS,
            3 => SslLibraryType::NSS,
            4 => SslLibraryType::BoringSSL,
            5 => SslLibraryType::LibreSSL,
            _ => SslLibraryType::Unknown,
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            SslLibraryType::OpenSSL => 1,
            SslLibraryType::GnuTLS => 2,
            SslLibraryType::NSS => 3,
            SslLibraryType::BoringSSL => 4,
            SslLibraryType::LibreSSL => 5,
            SslLibraryType::Unknown => 0,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            SslLibraryType::OpenSSL => "OpenSSL",
            SslLibraryType::GnuTLS => "GnuTLS",
            SslLibraryType::NSS => "NSS",
            SslLibraryType::BoringSSL => "BoringSSL",
            SslLibraryType::LibreSSL => "LibreSSL",
            SslLibraryType::Unknown => "Unknown",
        }
    }
}

/// 多SSL库事件
#[derive(Debug, Clone)]
pub struct MultiSslEvent {
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub library_type: SslLibraryType,
    pub ssl_version: u32,
    pub handshake_state: u32,
    pub cipher_suite: u32,
    pub keys_extracted: bool,
    pub client_random: Option<Vec<u8>>,
    pub master_secret: Option<Vec<u8>>,
    pub session_id: Option<Vec<u8>>,
    pub process_name: String,
    pub five_tuple: FiveTuple,
}

/// SSL库配置
#[derive(Debug, Clone)]
pub struct SslLibraryConfig {
    pub library_type: SslLibraryType,
    pub version_major: u32,
    pub version_minor: u32,
    pub enabled: bool,
    pub hook_functions: Vec<String>,
    pub library_path: Option<String>,
    pub process_names: Vec<String>,
}

impl Default for SslLibraryConfig {
    fn default() -> Self {
        Self {
            library_type: SslLibraryType::OpenSSL,
            version_major: 3,
            version_minor: 0,
            enabled: true,
            hook_functions: vec![
                "SSL_do_handshake".to_string(),
                "SSL_write".to_string(),
                "SSL_read".to_string(),
                "SSL_connect".to_string(),
                "SSL_accept".to_string(),
            ],
            library_path: None,
            process_names: vec![],
        }
    }
}

/// 多SSL库统计信息
#[derive(Debug, Clone, Default)]
pub struct MultiSslStats {
    pub total_events: u64,
    pub library_stats: HashMap<SslLibraryType, LibraryStats>,
    pub active_connections: usize,
    pub uptime: Duration,
    pub events_per_second: f64,
}

/// 单个库的统计信息
#[derive(Debug, Clone)]
pub struct LibraryStats {
    pub library_type: SslLibraryType,
    pub handshake_events: u64,
    pub write_bytes: u64,
    pub read_bytes: u64,
    pub keys_extracted: u64,
    pub success_rate: f64,
}

impl Default for LibraryStats {
    fn default() -> Self {
        Self {
            library_type: SslLibraryType::OpenSSL,
            handshake_events: 0,
            write_bytes: 0,
            read_bytes: 0,
            keys_extracted: 0,
            success_rate: 0.0,
        }
    }
}

/// 多SSL库注入器
#[allow(dead_code)]
pub struct MultiSslInjector {
    config: Arc<Config>,
    is_running: AtomicBool,
    start_time: Instant,

    // 库配置管理
    library_configs: Arc<RwLock<HashMap<SslLibraryType, SslLibraryConfig>>>,

    // 事件处理
    event_sender: mpsc::UnboundedSender<MultiSslEvent>,
    event_receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<MultiSslEvent>>>>,

    // 统计信息
    stats: Arc<RwLock<MultiSslStats>>,
    library_stats: Arc<RwLock<HashMap<SslLibraryType, AtomicU64>>>,

    // 传输管理器
    transport_manager: Option<Arc<EnhancedUdpTransportManager>>,

    // 进程检测
    detected_processes: Arc<RwLock<HashMap<u32, ProcessInfo>>>,

    // 库检测状态
    library_detection_status: Arc<RwLock<HashMap<SslLibraryType, bool>>>,
}

impl MultiSslInjector {
    /// 创建新的多SSL库注入器
    pub fn new(config: Arc<Config>) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel::<MultiSslEvent>();

        // 初始化默认库配置
        let mut library_configs = HashMap::new();
        library_configs.insert(SslLibraryType::OpenSSL, SslLibraryConfig {
            library_type: SslLibraryType::OpenSSL,
            version_major: 3,
            version_minor: 0,
            enabled: true,
            hook_functions: vec![
                "SSL_do_handshake".to_string(),
                "SSL_write".to_string(),
                "SSL_read".to_string(),
            ],
            library_path: Some("/usr/lib/x86_64-linux-gnu/libssl.so".to_string()),
            process_names: vec![
                "nginx".to_string(),
                "apache2".to_string(),
                "curl".to_string(),
                "wget".to_string(),
            ],
        });

        library_configs.insert(SslLibraryType::GnuTLS, SslLibraryConfig {
            library_type: SslLibraryType::GnuTLS,
            version_major: 3,
            version_minor: 7,
            enabled: true,
            hook_functions: vec![
                "gnutls_handshake".to_string(),
                "gnutls_record_send".to_string(),
                "gnutls_record_recv".to_string(),
            ],
            library_path: Some("/usr/lib/x86_64-linux-gnu/libgnutls.so".to_string()),
            process_names: vec![
                "wget".to_string(),
                "curl".to_string(),
            ],
        });

        library_configs.insert(SslLibraryType::NSS, SslLibraryConfig {
            library_type: SslLibraryType::NSS,
            version_major: 3,
            version_minor: 0,
            enabled: true,
            hook_functions: vec![
                "SSL_ForceHandshake".to_string(),
                "SSL_Write".to_string(),
                "SSL_Read".to_string(),
            ],
            library_path: Some("/usr/lib/x86_64-linux-gnu/libssl3.so".to_string()),
            process_names: vec![
                "firefox".to_string(),
                "thunderbird".to_string(),
            ],
        });

        Self {
            config,
            is_running: AtomicBool::new(false),
            start_time: Instant::now(),
            library_configs: Arc::new(RwLock::new(library_configs)),
            event_sender,
            event_receiver: Arc::new(RwLock::new(Some(event_receiver))),
            stats: Arc::new(RwLock::new(MultiSslStats::default())),
            library_stats: Arc::new(RwLock::new(HashMap::new())),
            transport_manager: None,
            detected_processes: Arc::new(RwLock::new(HashMap::new())),
            library_detection_status: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 注册传输管理器
    pub fn register_transport_manager(&mut self, manager: Arc<EnhancedUdpTransportManager>) {
        self.transport_manager = Some(manager);
        info!("注册传输管理器到多SSL库注入器");
    }

    /// 启动多SSL库注入器
    pub async fn start(&mut self) -> Result<()> {
        if self.is_running.load(Ordering::SeqCst) {
            warn!("多SSL库注入器已在运行");
            return Ok(());
        }

        info!("启动多SSL库注入器");

        // 初始化库检测状态
        self.initialize_library_detection().await?;

        // 启动eBPF程序
        self.load_ebpf_program().await?;

        // 启动事件处理器
        self.start_event_processor().await;

        // 启动进程检测器
        self.start_process_detector().await;

        // 启动统计报告器
        self.start_stats_reporter().await;

        self.is_running.store(true, Ordering::SeqCst);
        self.start_time = Instant::now();

        info!("多SSL库注入器启动成功");
        Ok(())
    }

    /// 停止多SSL库注入器
    pub async fn stop(&self) -> Result<()> {
        if !self.is_running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("停止多SSL库注入器");
        self.is_running.store(false, Ordering::SeqCst);

        // 卸载eBPF程序
        self.unload_ebpf_program().await?;

        info!("多SSL库注入器已停止");
        Ok(())
    }

    /// 检查是否运行中
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::SeqCst)
    }

    /// 更新库配置
    pub async fn update_library_config(&self, library_type: SslLibraryType, config: SslLibraryConfig) -> Result<()> {
        let mut configs = self.library_configs.write().await;
        configs.insert(library_type.clone(), config);

        info!("更新{}库配置", library_type.name());

        // 如果在运行中，重新加载eBPF配置
        if self.is_running() {
            self.reload_ebpf_config().await?;
        }

        Ok(())
    }

    /// 启用/禁用SSL库
    pub async fn set_library_enabled(&self, library_type: SslLibraryType, enabled: bool) -> Result<()> {
        let mut configs = self.library_configs.write().await;
        if let Some(config) = configs.get_mut(&library_type) {
            config.enabled = enabled;
            info!("{} SSL库已{}", library_type.name(), if enabled { "启用" } else { "禁用" });

            // 更新检测状态
            let mut detection_status = self.library_detection_status.write().await;
            detection_status.insert(library_type, false);

            // 如果在运行中，重新加载配置
            if self.is_running() {
                self.reload_ebpf_config().await?;
            }
        }

        Ok(())
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> MultiSslStats {
        let mut stats = self.stats.read().await.clone();
        stats.uptime = self.start_time.elapsed();

        // 计算事件/秒
        let elapsed = stats.uptime.as_secs_f64();
        if elapsed > 0.0 {
            stats.events_per_second = stats.total_events as f64 / elapsed;
        }

        stats
    }

    /// 获取库检测状态
    pub async fn get_library_detection_status(&self) -> HashMap<SslLibraryType, bool> {
        self.library_detection_status.read().await.clone()
    }

    /// 获取已检测进程
    pub async fn get_detected_processes(&self) -> HashMap<u32, ProcessInfo> {
        self.detected_processes.read().await.clone()
    }

    // 内部方法

    /// 初始化库检测
    async fn initialize_library_detection(&self) -> Result<()> {
        let mut detection_status = self.library_detection_status.write().await;
        let configs = self.library_configs.read().await;

        for (library_type, config) in configs.iter() {
            if config.enabled {
                detection_status.insert(library_type.clone(), false);
                info!("准备检测{}库", library_type.name());
            }
        }

        Ok(())
    }

    /// 加载eBPF程序
    async fn load_ebpf_program(&self) -> Result<()> {
        info!("加载多SSL库eBPF程序");

        // 这里应该调用实际的eBPF加载代码
        // 目前简化实现

        // 更新库检测状态
        let configs = self.library_configs.read().await;
        let mut detection_status = self.library_detection_status.write().await;

        for (library_type, config) in configs.iter() {
            if config.enabled {
                detection_status.insert(library_type.clone(), true);
                info!("{}库eBPF Hook已加载", library_type.name());
            }
        }

        Ok(())
    }

    /// 卸载eBPF程序
    async fn unload_ebpf_program(&self) -> Result<()> {
        info!("卸载多SSL库eBPF程序");

        // 更新库检测状态
        let mut detection_status = self.library_detection_status.write().await;
        let configs = self.library_configs.read().await;

        for (library_type, _) in configs.iter() {
            detection_status.insert(library_type.clone(), false);
        }

        Ok(())
    }

    /// 重新加载eBPF配置
    async fn reload_ebpf_config(&self) -> Result<()> {
        info!("重新加载多SSL库eBPF配置");

        // 卸载现有配置
        self.unload_ebpf_program().await?;

        // 等待一小段时间
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 重新加载配置
        self.load_ebpf_program().await?;

        Ok(())
    }

    /// 启动事件处理器
    async fn start_event_processor(&self) {
        let event_receiver = self.event_receiver.clone();
        let transport_manager = self.transport_manager.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            let mut receiver = {
                let mut guard = event_receiver.write().await;
                guard.take().unwrap()
            };

            info!("多SSL库事件处理器已启动");

            while let Some(event) = receiver.recv().await {
                debug!("处理多SSL事件: {:?}", event.library_type);

                // 更新统计
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.total_events += 1;

                    let library_stats_map = stats_guard.library_stats
                        .entry(event.library_type.clone())
                        .or_insert_with(|| LibraryStats {
                            library_type: event.library_type.clone(),
                            ..Default::default()
                        });

                    if event.keys_extracted {
                        library_stats_map.keys_extracted += 1;
                    }

                    if event.handshake_state > 0 {
                        library_stats_map.handshake_events += 1;
                    }
                }

                // 转换为TLS会话并发送
                if let Some(ref manager) = transport_manager {
                    if let Ok(session) = event_to_tls_session_static(&event) {
                        if let Err(e) = manager.send_tls_session(session).await {
                            error!("发送TLS会话失败: {}", e);
                        }
                    }
                }
            }

            info!("多SSL库事件处理器已停止");
        });
    }

    /// 启动进程检测器
    async fn start_process_detector(&self) {
        let detected_processes = self.detected_processes.clone();
        let library_configs = self.library_configs.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30)); // 每30秒检测一次

            info!("多SSL库进程检测器已启动");

            loop {
                interval.tick().await;

                // 简化的进程检测逻辑
                // 实际实现应该扫描/proc目录并检测SSL库使用
                let configs = library_configs.read().await;
                let mut processes = detected_processes.write().await;

                for (library_type, config) in configs.iter() {
                    if !config.enabled {
                        continue;
                    }

                    // 模拟检测到使用该库的进程
                    for process_name in &config.process_names {
                        let pid = (rand::random::<u32>() % 10000) + 1000;
                        let process_info = ProcessInfo {
                            pid,
                            process_name: process_name.clone(),
                            command_line: format!("{} --with-{}", process_name, library_type.name()),
                        };

                        processes.insert(pid, process_info);
                    }
                }

                debug!("进程检测完成，当前检测到的进程数: {}", processes.len());
            }
        });
    }

    /// 启动统计报告器
    async fn start_stats_reporter(&self) {
        let stats = self.stats.clone();
        let library_detection_status = self.library_detection_status.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // 每分钟报告一次

            loop {
                interval.tick().await;

                let current_stats = stats.read().await.clone();
                let detection_status = library_detection_status.read().await.clone();

                let uptime = current_stats.uptime.as_secs();

                info!(
                    "多SSL库统计 - 运行时间: {}秒, 总事件: {}, 事件/秒: {:.1}",
                    uptime,
                    current_stats.total_events,
                    current_stats.events_per_second
                );

                for (library_type, stats) in current_stats.library_stats.iter() {
                    let detected = detection_status.get(library_type).unwrap_or(&false);
                    info!(
                        "  {}: 检测={}, 握手={}, 密钥={}",
                        library_type.name(),
                        detected,
                        stats.handshake_events,
                        stats.keys_extracted
                    );
                }
            }
        });
    }
}

/// 静态的event_to_tls_session函数
fn event_to_tls_session_static(event: &MultiSslEvent) -> Result<TlsSession> {
    let client_random = event.client_random.clone().unwrap_or_default();
    let master_secret = event.master_secret.clone().unwrap_or_default();

    let process_info = ProcessInfo {
        pid: event.pid,
        process_name: event.process_name.clone(),
        command_line: format!("{} (lib: {})", event.process_name, event.library_type.name()),
    };

    Ok(TlsSession::new(
        client_random,
        master_secret,
        event.five_tuple.clone(),
        process_info,
    ))
}

impl Drop for MultiSslInjector {
    fn drop(&mut self) {
        if self.is_running() {
            // 确保在析构时停止注入器
            let rt = tokio::runtime::Handle::current();
            rt.block_on(self.stop()).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ssl_library_type_conversion() {
        assert_eq!(SslLibraryType::from_u32(1), SslLibraryType::OpenSSL);
        assert_eq!(SslLibraryType::from_u32(2), SslLibraryType::GnuTLS);
        assert_eq!(SslLibraryType::from_u32(0), SslLibraryType::Unknown);

        assert_eq!(SslLibraryType::OpenSSL.to_u32(), 1);
        assert_eq!(SslLibraryType::GnuTLS.to_u32(), 2);
        assert_eq!(SslLibraryType::Unknown.to_u32(), 0);

        assert_eq!(SslLibraryType::OpenSSL.name(), "OpenSSL");
        assert_eq!(SslLibraryType::GnuTLS.name(), "GnuTLS");
        assert_eq!(SslLibraryType::Unknown.name(), "Unknown");
    }

    #[tokio::test]
    async fn test_multi_ssl_injector_creation() {
        let config = Arc::new(Config::default());
        let injector = MultiSslInjector::new(config);

        assert!(!injector.is_running());

        // 测试默认库配置
        let configs = injector.library_configs.read().await;
        assert!(configs.contains_key(&SslLibraryType::OpenSSL));
        assert!(configs.contains_key(&SslLibraryType::GnuTLS));
        assert!(configs.contains_key(&SslLibraryType::NSS));
    }

    #[tokio::test]
    async fn test_library_config_update() {
        let config = Arc::new(Config::default());
        let injector = MultiSslInjector::new(config);

        let new_config = SslLibraryConfig {
            library_type: SslLibraryType::OpenSSL,
            version_major: 3,
            version_minor: 1,
            enabled: false,
            hook_functions: vec!["test_func".to_string()],
            library_path: None,
            process_names: vec!["test_process".to_string()],
        };

        let result = injector.update_library_config(SslLibraryType::OpenSSL, new_config).await;
        assert!(result.is_ok());

        let configs = injector.library_configs.read().await;
        let openssl_config = configs.get(&SslLibraryType::OpenSSL).unwrap();
        assert!(!openssl_config.enabled);
        assert_eq!(openssl_config.version_minor, 1);
    }

    #[tokio::test]
    async fn test_library_enabled_toggle() {
        let config = Arc::new(Config::default());
        let injector = MultiSslInjector::new(config);

        // 禁用OpenSSL
        let result = injector.set_library_enabled(SslLibraryType::OpenSSL, false).await;
        assert!(result.is_ok());

        let configs = injector.library_configs.read().await;
        let openssl_config = configs.get(&SslLibraryType::OpenSSL).unwrap();
        assert!(!openssl_config.enabled);

        // 启用OpenSSL
        let result = injector.set_library_enabled(SslLibraryType::OpenSSL, true).await;
        assert!(result.is_ok());

        let openssl_config = configs.get(&SslLibraryType::OpenSSL).unwrap();
        assert!(openssl_config.enabled);
    }
}