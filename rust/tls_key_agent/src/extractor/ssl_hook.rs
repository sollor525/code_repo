/**
 * @file ssl_hook.rs
 * @brief SSL Hook事件处理器 - 专门处理eBPF SSL Hook事件
 * @author sollor525@hotmail.com
 * @version 2.0.0 - eBPF内核级SSL Hook
 * @date 2023-12-01
 */

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{info, debug, warn};
use anyhow::Result;
use tokio::sync::RwLock;

use crate::common::session::{FiveTuple, ProcessInfo, Protocol};
use crate::config::{Config, FilterRule};
use crate::injector::ebpf::EbpfSslEvent;

/// SSL Hook事件类型
#[derive(Debug, Clone)]
pub enum SslHookEventType {
    HandshakeStart,
    HandshakeComplete,
    KeyExtracted,
    ConnectionClosed,
    Heartbeat,
}

/// 处理后的SSL事件
#[derive(Debug, Clone)]
pub struct ProcessedSslEvent {
    pub event_type: SslHookEventType,
    pub session_id: String,
    pub five_tuple: FiveTuple,
    pub process_info: ProcessInfo,
    pub client_random: Option<Vec<u8>>,
    pub master_secret: Option<Vec<u8>>,
    pub session_id_data: Option<Vec<u8>>,
    pub ssl_version: u8,
    pub cipher_suite: u16,
    pub timestamp: u64,
    pub processing_time_ms: u64,
}

/// SSL Hook处理器配置
#[derive(Debug, Clone)]
pub struct SslHookProcessorConfig {
    pub enable_filtering: bool,
    pub enable_deduplication: bool,
    pub enable_validation: bool,
    pub session_timeout_ms: u64,
    pub max_sessions: usize,
    pub key_validation_enabled: bool,
    pub stats_report_interval_ms: u64,
    pub default_allow_unknown: bool,
}

impl Default for SslHookProcessorConfig {
    fn default() -> Self {
        Self {
            enable_filtering: true,
            enable_deduplication: true,
            enable_validation: true,
            session_timeout_ms: 300_000, // 5分钟
            max_sessions: 10_000,
            key_validation_enabled: true,
            stats_report_interval_ms: 30_000, // 30秒
            default_allow_unknown: true, // 默认允许未匹配规则的事件
        }
    }
}

/// SSL Hook处理统计信息
#[derive(Debug, Clone, Default)]
pub struct SslHookProcessorStats {
    pub events_received: u64,
    pub events_processed: u64,
    pub events_filtered: u64,
    pub events_deduplicated: u64,
    pub events_invalid: u64,
    pub keys_extracted: u64,
    pub active_sessions: usize,
    pub processing_errors: u64,
    pub average_processing_time_ms: f64,
}

/// SSL会话状态跟踪
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SslSessionState {
    session_id: String,
    five_tuple: FiveTuple,
    process_info: ProcessInfo,
    handshake_start_time: Option<Instant>,
    last_key_extraction: Option<Instant>,
    keys_extracted: bool,
    event_count: u64,
    last_activity: Instant,
}

/// SSL Hook事件处理器
#[derive(Debug)]
#[allow(dead_code)]
pub struct SslHookProcessor {
    config: Arc<Config>,
    processor_config: SslHookProcessorConfig,

    // 内部状态
    is_running: AtomicBool,
    session_states: Arc<RwLock<HashMap<String, SslSessionState>>>,

    // 统计信息
    stats: Arc<RwLock<SslHookProcessorStats>>,

    // 过滤规则缓存
    filter_rules: Arc<RwLock<Vec<FilterRule>>>,

    // 重复事件检测
    recent_events: Arc<RwLock<HashMap<String, Instant>>>,
    deduplication_window: Duration,
}

impl SslHookProcessor {
    /// 创建新的SSL Hook事件处理器
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config: config.clone(),
            processor_config: SslHookProcessorConfig::default(),
            is_running: AtomicBool::new(false),
            session_states: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(SslHookProcessorStats::default())),
            filter_rules: Arc::new(RwLock::new(config.filters.clone())),
            recent_events: Arc::new(RwLock::new(HashMap::new())),
            deduplication_window: Duration::from_millis(1000), // 1秒去重窗口
        }
    }

    /// 设置处理器配置
    pub fn with_config(mut self, config: SslHookProcessorConfig) -> Self {
        self.processor_config = config;
        self
    }

    /// 启动SSL Hook事件处理器
    pub async fn start(&mut self) -> Result<()> {
        if self.is_running.load(Ordering::SeqCst) {
            warn!("SSL Hook事件处理器已经运行");
            return Ok(());
        }

        info!("启动SSL Hook事件处理器");

        // 启动统计报告任务
        self.start_stats_reporter().await;

        // 启动清理任务
        self.start_cleanup_task().await;

        self.is_running.store(true, Ordering::SeqCst);
        info!("SSL Hook事件处理器启动成功");
        Ok(())
    }

    /// 停止SSL Hook事件处理器
    pub async fn stop(&self) -> Result<()> {
        if !self.is_running.load(Ordering::SeqCst) {
            return Ok(());
        }

        info!("停止SSL Hook事件处理器");
        self.is_running.store(false, Ordering::SeqCst);

        // 清理会话状态
        {
            let mut session_states = self.session_states.write().await;
            session_states.clear();
        }

        // 清理重复事件缓存
        {
            let mut recent_events = self.recent_events.write().await;
            recent_events.clear();
        }

        info!("SSL Hook事件处理器已停止");
        Ok(())
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> SslHookProcessorStats {
        let mut stats = self.stats.read().await.clone();

        // 更新活跃会话数
        stats.active_sessions = self.session_states.read().await.len();

        stats
    }

    /// 更新过滤规则
    pub async fn update_filter_rules(&self, new_rules: Vec<FilterRule>) {
        let mut filter_rules = self.filter_rules.write().await;
        *filter_rules = new_rules;
        debug!("更新过滤规则，当前规则数: {}", filter_rules.len());
    }

    /// 处理单个eBPF SSL事件
    pub async fn process_ebpf_event(&self, ebpf_event: EbpfSslEvent) -> Result<Option<ProcessedSslEvent>> {
        let start_time = Instant::now();

        // 更新接收统计
        {
            let mut stats = self.stats.write().await;
            stats.events_received += 1;
        }

        // 第一层过滤：基础有效性检查
        if !self.is_valid_event(&ebpf_event).await {
            debug!("事件基础验证失败，跳过处理");
            return Ok(None);
        }

        // 第二层过滤：规则匹配
        if !self.matches_filter_rules(&ebpf_event).await {
            debug!("事件不匹配过滤规则，跳过处理");
            return Ok(None);
        }

        // 第三层过滤：会话状态检查
        let session_id = self.generate_session_id(&ebpf_event);

        // 检查重复事件
        if self.processor_config.enable_deduplication {
            if self.is_duplicate_event(&session_id).await {
                {
                    let mut stats = self.stats.write().await;
                    stats.events_deduplicated += 1;
                }
                return Ok(None);
            }
            self.record_event(&session_id).await;
        }

        // 应用过滤规则
        if self.processor_config.enable_filtering {
            if !self.should_process_event(&ebpf_event).await {
                {
                    let mut stats = self.stats.write().await;
                    stats.events_filtered += 1;
                }
                return Ok(None);
            }
        }

        // 验证密钥材料
        if self.processor_config.enable_validation && self.processor_config.key_validation_enabled {
            if !self.validate_key_material(&ebpf_event) {
                {
                    let mut stats = self.stats.write().await;
                    stats.events_invalid += 1;
                }
                return Ok(None);
            }
        }

        // 更新或创建会话状态
        let event_type = self.update_session_state(&ebpf_event).await;

        // 创建处理后的事件
        let processed_event = ProcessedSslEvent {
            event_type,
            session_id,
            five_tuple: self.ebpf_event_to_five_tuple(&ebpf_event),
            process_info: self.ebpf_event_to_process_info(&ebpf_event),
            client_random: ebpf_event.client_random.clone(),
            master_secret: ebpf_event.master_secret.clone(),
            session_id_data: ebpf_event.session_id.clone(),
            ssl_version: ebpf_event.ssl_version,
            cipher_suite: ebpf_event.cipher_suite,
            timestamp: ebpf_event.timestamp,
            processing_time_ms: start_time.elapsed().as_millis() as u64,
        };

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.events_processed += 1;
            if ebpf_event.keys_extracted {
                stats.keys_extracted += 1;
            }
        }

        Ok(Some(processed_event))
    }

    /// 生成会话ID
    fn generate_session_id(&self, event: &EbpfSslEvent) -> String {
        format!(
            "{}:{}-{}:{}-{}-{}",
            event.src_ip, event.src_port,
            event.dst_ip, event.dst_port,
            event.pid,
            event.connection_id
        )
    }

    /// 检查是否为重复事件
    async fn is_duplicate_event(&self, session_id: &str) -> bool {
        let recent = self.recent_events.read().await;
        if let Some(&timestamp) = recent.get(session_id) {
            timestamp.elapsed() < self.deduplication_window
        } else {
            false
        }
    }

    /// 记录事件
    async fn record_event(&self, session_id: &str) {
        let mut recent = self.recent_events.write().await;
        recent.insert(session_id.to_string(), Instant::now());

        // 清理过期记录（简单实现，可以优化）
        let now = Instant::now();
        recent.retain(|_, &mut timestamp| now.duration_since(timestamp) < Duration::from_secs(60));
    }

    /// 判断是否应该处理事件
    async fn should_process_event(&self, event: &EbpfSslEvent) -> bool {
        let rules = self.filter_rules.read().await;

        // 如果没有规则，默认允许所有事件
        if rules.is_empty() {
            return true;
        }

        // 检查是否有规则匹配此事件
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // 检查五元组过滤
            let five_filter = &rule.five_tuple;
            if let Some(dst_port) = five_filter.dst_port {
                if event.dst_port != dst_port {
                    continue;
                }
            }

            if let Some(protocol) = &five_filter.protocol {
                    let event_protocol = match event.protocol {
                        6 => Protocol::TCP,
                        17 => Protocol::UDP,
                        _ => Protocol::TCP,
                    };
                    if *protocol != event_protocol {
                        continue;
                    }
            }

            // 检查进程名过滤
            if let Some(ref process_filter) = rule.process_name {
                if !event.process_name.contains(process_filter) {
                    continue;
                }
            }

            // 检查PID过滤
            if let Some(pid_filter) = rule.pid {
                if event.pid != pid_filter {
                    continue;
                }
            }

            // 如果通过了所有检查，则允许处理
            return true;
        }

        // 没有规则匹配，默认不处理
        false
    }

    /// 验证密钥材料
    fn validate_key_material(&self, event: &EbpfSslEvent) -> bool {
        if let (Some(ref client_random), Some(ref master_secret)) = (&event.client_random, &event.master_secret) {
            // 检查长度
            if client_random.len() != 32 || master_secret.len() != 48 {
                return false;
            }

            // 简单的熵值检查
            let client_entropy = self.calculate_entropy(client_random);
            let master_entropy = self.calculate_entropy(master_secret);

            client_entropy > 3.0 && master_entropy > 3.0
        } else {
            true // 如果没有密钥材料，不需要验证
        }
    }

    /// 计算数据的熵值
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in counts.iter() {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    /// 更新会话状态
    async fn update_session_state(&self, event: &EbpfSslEvent) -> SslHookEventType {
        let session_id = self.generate_session_id(event);
        let now = Instant::now();

        let mut session_states = self.session_states.write().await;

        match session_states.get_mut(&session_id) {
            Some(state) => {
                // 更新现有会话
                state.last_activity = now;
                state.event_count += 1;

                if event.keys_extracted && !state.keys_extracted {
                    state.keys_extracted = true;
                    state.last_key_extraction = Some(now);
                    SslHookEventType::KeyExtracted
                } else if event.handshake_state == 2 { // 假设2表示握手完成
                    SslHookEventType::HandshakeComplete
                } else {
                    SslHookEventType::Heartbeat
                }
            }
            None => {
                // 创建新会话
                let new_state = SslSessionState {
                    session_id: session_id.clone(),
                    five_tuple: self.ebpf_event_to_five_tuple(event),
                    process_info: self.ebpf_event_to_process_info(event),
                    handshake_start_time: Some(now),
                    last_key_extraction: if event.keys_extracted { Some(now) } else { None },
                    keys_extracted: event.keys_extracted,
                    event_count: 1,
                    last_activity: now,
                };

                session_states.insert(session_id, new_state);
                SslHookEventType::HandshakeStart
            }
        }
    }

    /// 将eBPF事件转换为五元组
    fn ebpf_event_to_five_tuple(&self, event: &EbpfSslEvent) -> FiveTuple {
        FiveTuple {
            src_ip: std::net::Ipv4Addr::from(event.src_ip).into(),
            src_port: event.src_port,
            dst_ip: std::net::Ipv4Addr::from(event.dst_ip).into(),
            dst_port: event.dst_port,
            protocol: match event.protocol {
                6 => Protocol::TCP,
                17 => Protocol::UDP,
                _ => Protocol::TCP,
            },
        }
    }

    /// 将eBPF事件转换为进程信息
    fn ebpf_event_to_process_info(&self, event: &EbpfSslEvent) -> ProcessInfo {
        ProcessInfo {
            pid: event.pid,
            process_name: event.process_name.clone(),
            command_line: String::new(), // 可以从/proc读取
        }
    }

    /// 启动统计报告任务
    async fn start_stats_reporter(&self) {
        let stats = self.stats.clone();
        let session_states = self.session_states.clone();
        let report_interval = Duration::from_millis(self.processor_config.stats_report_interval_ms);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(report_interval);

            loop {
                interval.tick().await;

                let stats_guard = stats.read().await;
                let active_sessions = session_states.read().await.len();

                if stats_guard.events_received > 0 {
                    info!(
                        "SSL Hook处理器统计: 接收={}, 处理={}, 过滤={}, 去重={}, 提取={}, 活跃会话={}",
                        stats_guard.events_received,
                        stats_guard.events_processed,
                        stats_guard.events_filtered,
                        stats_guard.events_deduplicated,
                        stats_guard.keys_extracted,
                        active_sessions
                    );
                }
            }
        });
    }

    /// 启动清理任务
    async fn start_cleanup_task(&self) {
        let session_states = self.session_states.clone();
        let recent_events = self.recent_events.clone();
        let session_timeout = Duration::from_millis(self.processor_config.session_timeout_ms);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // 每分钟清理一次

            loop {
                interval.tick().await;

                let now = Instant::now();

                // 清理过期会话
                {
                    let mut states = session_states.write().await;
                    let initial_count = states.len();

                    states.retain(|_, state| {
                        now.duration_since(state.last_activity) < session_timeout
                    });

                    let cleaned_count = initial_count - states.len();
                    if cleaned_count > 0 {
                        debug!("清理了 {} 个过期SSL会话", cleaned_count);
                    }
                }

                // 清理过期的事件记录
                {
                    let mut events = recent_events.write().await;
                    let initial_count = events.len();

                    events.retain(|_, timestamp| {
                        now.duration_since(*timestamp) < Duration::from_secs(300) // 5分钟
                    });

                    let cleaned_count = initial_count - events.len();
                    if cleaned_count > 0 {
                        debug!("清理了 {} 个过期事件记录", cleaned_count);
                    }
                }
            }
        });
    }

    /// 基础事件验证
    async fn is_valid_event(&self, event: &EbpfSslEvent) -> bool {
        // 检查基本字段
        if event.pid == 0 || event.src_port == 0 || event.dst_port == 0 {
            return false;
        }

        // 检查IP地址有效性
        if event.src_ip == 0 || event.dst_ip == 0 {
            return false;
        }

        // 检查协议类型
        if event.protocol != 6 && event.protocol != 17 { // 只允许TCP和UDP
            return false;
        }

        // 检查进程名
        if event.process_name.is_empty() {
            return false;
        }

        true
    }

    /// 高级过滤规则匹配
    async fn matches_filter_rules(&self, event: &EbpfSslEvent) -> bool {
        let rules = self.filter_rules.read().await;

        // 如果没有规则，使用默认配置
        if rules.is_empty() {
            return self.processor_config.default_allow_unknown;
        }

        // 按优先级排序处理规则
        let mut sorted_rules: Vec<_> = rules.iter().collect();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in sorted_rules {
            if !rule.enabled {
                continue;
            }

            if self.matches_single_rule(event, rule).await {
                return true;
            }
        }

        // 没有规则匹配
        self.processor_config.default_allow_unknown
    }

    /// 单个规则匹配检查
    async fn matches_single_rule(&self, event: &EbpfSslEvent, rule: &FilterRule) -> bool {
        // 检查五元组过滤
        let five_filter = &rule.five_tuple;

        // 源IP过滤
        if let Some(ref src_ip) = five_filter.src_ip {
            if !self.ip_matches(event.src_ip, src_ip) {
                return false;
            }
        }

        // 源端口过滤
        if let Some(src_port) = five_filter.src_port {
            if event.src_port != src_port {
                return false;
            }
        }

        // 目标IP过滤
        if let Some(ref dst_ip) = five_filter.dst_ip {
            if !self.ip_matches(event.dst_ip, dst_ip) {
                return false;
            }
        }

        // 目标端口过滤
        if let Some(dst_port) = five_filter.dst_port {
            if event.dst_port != dst_port {
                return false;
            }
        }

        // 协议过滤
        if let Some(ref protocol) = five_filter.protocol {
            let event_protocol = match event.protocol {
                6 => Protocol::TCP,
                17 => Protocol::UDP,
                _ => Protocol::TCP,
            };
            if *protocol != event_protocol {
                return false;
            }
        }

        // 进程名过滤
        if let Some(ref process_name) = rule.process_name {
            if !event.process_name.contains(process_name) {
                return false;
            }
        }

        // PID过滤
        if let Some(pid) = rule.pid {
            if event.pid != pid {
                return false;
            }
        }

        // 源IP高级过滤
        if let Some(ref source_ip_filter) = rule.source_ip_filter {
            if !self.matches_ip_filter(event.src_ip, source_ip_filter) {
                return false;
            }
        }

        true
    }

    /// IP地址匹配检查（支持CIDR）
    fn ip_matches(&self, ip: u32, pattern: &str) -> bool {
        if pattern.contains('/') {
            // CIDR格式
            self.ip_in_range(ip, pattern)
        } else {
            // 单个IP地址
            if let Ok(addr) = pattern.parse::<std::net::Ipv4Addr>() {
                ip == u32::from(addr)
            } else {
                false
            }
        }
    }

    /// IP范围匹配检查
    fn ip_in_range(&self, ip: u32, cidr: &str) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let network_ip = if let Ok(addr) = parts[0].parse::<std::net::Ipv4Addr>() {
            u32::from(addr)
        } else {
            return false;
        };

        let prefix_len = if let Ok(len) = parts[1].parse::<u32>() {
            if len > 32 {
                return false;
            }
            len
        } else {
            return false;
        };

        if prefix_len == 0 {
            return true;
        }

        let mask = u32::MAX << (32 - prefix_len);
        (ip & mask) == (network_ip & mask)
    }

    /// 高级源IP过滤器匹配
    fn matches_ip_filter(&self, ip: u32, filter: &crate::config::SourceIpFilter) -> bool {
        let matches = filter.ip_ranges.iter().any(|range| self.ip_in_range(ip, range));

        match filter.mode.as_str() {
            "whitelist" => matches,
            "blacklist" => !matches,
            _ => true, // 未知模式默认允许
        }
    }
}

/// 旧版本兼容性结构体
#[derive(Debug, Clone)]
pub struct SslHookStats {
    pub is_active: bool,
    pub incomplete_sessions: usize,
    pub sessions_with_client_random: usize,
    pub sessions_with_master_secret: usize,
    pub sessions_with_connection: usize,
}

/// 旧版本兼容性结构体
#[derive(Debug)]
pub struct SslHook {
    processor: SslHookProcessor,
}

impl SslHook {
    pub fn new(config: Arc<Config>, _session_manager: Arc<crate::extractor::session_manager::SessionManager>) -> Result<Self> {
        info!("初始化eBPF SSL Hook事件处理器（兼容模式）");

        let processor = SslHookProcessor::new(config);

        Ok(Self { processor })
    }

    pub async fn start(&self) -> Result<()> {
        info!("启动eBPF SSL Hook（兼容模式）");
        // 新架构中，SSL Hook由eBPF注入器管理
        warn!("兼容模式：SSL Hook已集成到eBPF注入器中");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("停止eBPF SSL Hook（兼容模式）");
        Ok(())
    }

    pub async fn is_active(&self) -> bool {
        self.processor.is_running.load(Ordering::SeqCst)
    }

    // 兼容性方法
    pub async fn handle_client_random(&self, _ssl_ptr: usize, _client_random: Vec<u8>) -> Result<()> {
        warn!("兼容模式：Client Random处理已由eBPF注入器接管");
        Ok(())
    }

    pub async fn handle_master_secret(&self, _ssl_ptr: usize, _master_secret: Vec<u8>) -> Result<()> {
        warn!("兼容模式：Master Secret处理已由eBPF注入器接管");
        Ok(())
    }

    pub async fn handle_connection_info(&self, _ssl_ptr: usize, _five_tuple: FiveTuple) -> Result<()> {
        warn!("兼容模式：连接信息处理已由eBPF注入器接管");
        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) {
        warn!("兼容模式：会话清理已由eBPF注入器接管");
    }

    pub async fn get_stats(&self) -> SslHookStats {
        let processor_stats = self.processor.get_stats().await;
        SslHookStats {
            is_active: self.processor.is_running.load(Ordering::SeqCst),
            incomplete_sessions: processor_stats.active_sessions,
            sessions_with_client_random: 0,
            sessions_with_master_secret: 0,
            sessions_with_connection: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[tokio::test]
    async fn test_ssl_hook_processor_creation() {
        let config = Arc::new(Config::default());
        let processor = SslHookProcessor::new(config);

        assert!(!processor.is_running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_entropy_calculation() {
        let config = Arc::new(Config::default());
        let processor = SslHookProcessor::new(config);

        let high_entropy_data = vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let low_entropy_data = vec![42u8; 16];

        let high_entropy = processor.calculate_entropy(&high_entropy_data);
        let low_entropy = processor.calculate_entropy(&low_entropy_data);

        assert!(high_entropy > low_entropy);
        assert!(low_entropy < 1.0);
    }
}