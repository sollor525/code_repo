/**
 * @file enhanced_udp_manager.rs
 * @brief 增强型UDP批量传输管理器 - 优化性能和可靠性
 * @author sollor525@hotmail.com
 * @version 2.0.0 - eBPF内核级SSL Hook
 * @date 2023-12-01
 */

use std::sync::Arc;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use tracing::{info, error, debug, warn};
use anyhow::Result;

use crate::common::error::TlsKeyAgentError;
use crate::common::session::TlsSession;
use crate::transport::{TransportMessage, TransportType, DefaultTransportFactory, TransportEnum, TransportFactory};
use crate::config::{TransportConfig, TcpTransportConfig, RemoteConfigConfig};
use crate::injector::ebpf::EbpfSslEvent;

/// 批处理策略配置
#[derive(Debug, Clone)]
pub struct BatchStrategy {
    /// 批量大小限制
    pub max_batch_size: usize,
    /// 批次时间限制（毫秒）
    pub batch_timeout_ms: u64,
    /// 紧急批次大小限制（TLS密钥等关键数据）
    pub urgent_batch_size: usize,
    /// 紧急批次时间限制（毫秒）
    pub urgent_timeout_ms: u64,
    /// 动态批处理开关
    pub adaptive_batching: bool,
    /// 最小批次大小
    pub min_batch_size: usize,
}

impl Default for BatchStrategy {
    fn default() -> Self {
        Self {
            max_batch_size: 200,
            batch_timeout_ms: 50,
            urgent_batch_size: 10,
            urgent_timeout_ms: 5,
            adaptive_batching: true,
            min_batch_size: 5,
        }
    }
}

/// 压缩配置
#[derive(Debug, Clone)]
pub struct CompressionConfig {
    /// 是否启用压缩
    pub enabled: bool,
    /// 压缩算法
    pub algorithm: CompressionAlgorithm,
    /// 压缩阈值（字节）
    pub compression_threshold: usize,
    /// 最大压缩级别
    pub max_compression_level: u32,
}

#[derive(Debug, Clone)]
pub enum CompressionAlgorithm {
    None,
    Lz4,
    Zstd,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: CompressionAlgorithm::Lz4,
            compression_threshold: 512,
            max_compression_level: 6,
        }
    }
}

/// 重传配置
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// 是否启用重传
    pub enabled: bool,
    /// 最大重传次数
    pub max_retries: u32,
    /// 初始重传延迟（毫秒）
    pub initial_delay_ms: u64,
    /// 重传延迟倍数
    pub backoff_multiplier: f64,
    /// 最大重传延迟（毫秒）
    pub max_delay_ms: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_retries: 3,
            initial_delay_ms: 100,
            backoff_multiplier: 2.0,
            max_delay_ms: 5000,
        }
    }
}

/// 传输性能统计
#[derive(Debug, Clone, Default)]
pub struct EnhancedTransportStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub batches_sent: u64,
    pub average_batch_size: f64,
    pub compression_ratio: f64,
    pub retry_count: u64,
    pub failed_retries: u64,
    pub average_latency_ms: f64,
    pub queue_depth: usize,
    pub processing_time_ms: f64,
    pub memory_usage_mb: f64,
}

/// 待重传消息
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PendingRetry {
    message: TransportMessage,
    attempts: u32,
    next_retry_time: Instant,
    original_send_time: Instant,
}

/// 增强型UDP传输管理器
pub struct EnhancedUdpTransportManager {
    config: TransportConfig,
    batch_strategy: BatchStrategy,
    compression_config: CompressionConfig,
    retry_config: RetryConfig,

    // 内部状态
    is_running: AtomicBool,
    message_sender: Arc<RwLock<Option<mpsc::UnboundedSender<TransportMessage>>>>,
    factory: DefaultTransportFactory,
    udp_transport: Arc<RwLock<Option<TransportEnum>>>,

    // 性能优化组件
    message_queue: Arc<RwLock<VecDeque<TransportMessage>>>,
    pending_retries: Arc<RwLock<HashMap<String, PendingRetry>>>,

    // 统计信息
    stats: Arc<RwLock<EnhancedTransportStats>>,

    // 动态调整参数
    adaptive_batch_size: Arc<RwLock<usize>>,
    current_latency: Arc<RwLock<Duration>>,
    throughput_history: Arc<RwLock<VecDeque<f64>>>,
}

impl EnhancedUdpTransportManager {
    /// 创建新的增强型UDP传输管理器
    pub fn new(config: TransportConfig) -> Result<Self> {
        info!("初始化增强型UDP传输管理器");

        Ok(Self {
            config: config.clone(),
            batch_strategy: BatchStrategy::default(),
            compression_config: CompressionConfig::default(),
            retry_config: RetryConfig::default(),
            is_running: AtomicBool::new(false),
            message_sender: Arc::new(RwLock::new(None)),
            factory: DefaultTransportFactory,
            udp_transport: Arc::new(RwLock::new(None)),
            message_queue: Arc::new(RwLock::new(VecDeque::new())),
            pending_retries: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(EnhancedTransportStats::default())),
            adaptive_batch_size: Arc::new(RwLock::new(config.udp.batch_size)),
            current_latency: Arc::new(RwLock::new(Duration::from_millis(0))),
            throughput_history: Arc::new(RwLock::new(VecDeque::with_capacity(100))),
        })
    }

    /// 设置批处理策略
    pub fn with_batch_strategy(mut self, strategy: BatchStrategy) -> Self {
        self.batch_strategy = strategy;
        self
    }

    /// 设置压缩配置
    pub fn with_compression_config(mut self, config: CompressionConfig) -> Self {
        self.compression_config = config;
        self
    }

    /// 设置重传配置
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// 启动传输管理器
    pub async fn start(&self) -> Result<()> {
        info!("启动增强型UDP传输管理器");

        let mut is_running = self.is_running.load(Ordering::SeqCst);
        if is_running {
            return Err(TlsKeyAgentError::Config("增强型UDP传输管理器已在运行".to_string()).into());
        }

        // 初始化UDP传输器
        self.initialize_udp_transport().await?;

        // 启动增强的批量处理器
        self.start_enhanced_batch_processor().await;

        // 启动重传管理器
        if self.retry_config.enabled {
            self.start_retry_manager().await;
        }

        // 启动性能监控器
        self.start_performance_monitor().await;

        is_running = true;
        self.is_running.store(is_running, Ordering::SeqCst);
        info!("增强型UDP传输管理器启动成功");
        Ok(())
    }

    /// 停止传输管理器
    pub async fn stop(&self) -> Result<()> {
        info!("停止增强型UDP传输管理器");

        self.is_running.store(false, Ordering::SeqCst);

        // 停止消息发送器
        {
            let mut sender = self.message_sender.write().await;
            *sender = None;
        }

        // 停止UDP传输器
        {
            let mut udp_transport = self.udp_transport.write().await;
            if let Some(transport) = udp_transport.take() {
                if let Err(e) = transport.stop().await {
                    error!("停止UDP传输器失败: {}", e);
                }
            }
        }

        // 清理队列
        {
            let mut queue = self.message_queue.write().await;
            queue.clear();
        }

        {
            let mut retries = self.pending_retries.write().await;
            retries.clear();
        }

        info!("增强型UDP传输管理器已停止");
        Ok(())
    }

    /// 发送TLS会话
    pub async fn send_tls_session(&self, session: TlsSession) -> Result<()> {
        if !self.is_running.load(Ordering::SeqCst) {
            return Err(TlsKeyAgentError::Transport("增强型UDP传输管理器未运行".to_string()).into());
        }

        let message = TransportMessage::new_tls_key(session);
        self.send_message(message).await
    }

    /// 发送eBPF SSL事件
    pub async fn send_ebpf_ssl_event(&self, event: EbpfSslEvent) -> Result<()> {
        if !self.is_running.load(Ordering::SeqCst) {
            return Err(TlsKeyAgentError::Transport("增强型UDP传输管理器未运行".to_string()).into());
        }

        // 将eBPF事件转换为TLS会话格式
        let session = self.ebpf_event_to_tls_session(event)?;
        self.send_tls_session(session).await
    }

    /// 发送心跳消息
    pub async fn send_heartbeat(&self) -> Result<()> {
        let heartbeat = TransportMessage::new_heartbeat();
        self.send_message(heartbeat).await
    }

    /// 获取增强统计信息
    pub async fn get_enhanced_stats(&self) -> EnhancedTransportStats {
        let mut stats = self.stats.read().await.clone();

        // 更新队列深度
        stats.queue_depth = self.message_queue.read().await.len();

        // 计算内存使用量
        stats.memory_usage_mb = self.estimate_memory_usage() / 1024.0 / 1024.0;

        stats
    }

    /// 动态调整批处理大小
    pub async fn adjust_batch_size(&self) {
        if !self.batch_strategy.adaptive_batching {
            return;
        }

        let current_latency = *self.current_latency.read().await;
        let throughput_history = self.throughput_history.read().await;

        let new_size = if current_latency > Duration::from_millis(100) {
            // 延迟过高，减小批次大小
            let current_size = *self.adaptive_batch_size.read().await;
            (current_size * 3) / 4 // 减少25%
        } else if current_latency < Duration::from_millis(20) && throughput_history.len() > 10 {
            // 延迟较低且吞吐量稳定，可以增加批次大小
            let current_size = *self.adaptive_batch_size.read().await;
            (current_size * 5) / 4 // 增加25%
        } else {
            // 保持当前大小
            *self.adaptive_batch_size.read().await
        };

        let new_size = new_size.clamp(
            self.batch_strategy.min_batch_size,
            self.batch_strategy.max_batch_size
        );

        let mut adaptive_size = self.adaptive_batch_size.write().await;
        if *adaptive_size != new_size {
            info!("动态调整批处理大小: {} -> {}", *adaptive_size, new_size);
            *adaptive_size = new_size;
        }
    }

    // 内部方法

    /// 发送消息
    async fn send_message(&self, message: TransportMessage) -> Result<()> {
        let sender = self.message_sender.read().await;
        if let Some(ref tx) = *sender {
            tx.send(message)
                .map_err(|e| TlsKeyAgentError::Transport(format!("发送消息失败: {}", e)))?;
        } else {
            return Err(TlsKeyAgentError::Transport("消息批量处理器未初始化".to_string()).into());
        }

        Ok(())
    }

    /// 初始化UDP传输器
    async fn initialize_udp_transport(&self) -> Result<()> {
        debug!("初始化UDP传输器");

        // 只启用UDP传输
        let temp_config = TransportConfig {
            enabled_transports: vec![TransportType::Udp],
            udp: self.config.udp.clone(),
            tcp: TcpTransportConfig::default(),
            remote_config: RemoteConfigConfig::default(),
        };

        match self.factory.create_transport(&temp_config) {
            Ok(transport) => {
                // 启动UDP传输器
                transport.start().await
                    .map_err(|e| TlsKeyAgentError::Transport(
                        format!("启动UDP传输器失败: {}", e)
                    ))?;

                let mut udp_transport = self.udp_transport.write().await;
                *udp_transport = Some(transport);
                info!("UDP传输器初始化并启动成功");
            }
            Err(e) => {
                error!("创建UDP传输器失败: {}", e);
                return Err(e.into());
            }
        }

        Ok(())
    }

    /// 启动增强的批量处理器
    async fn start_enhanced_batch_processor(&self) {
        let message_queue = self.message_queue.clone();
        let udp_transport = self.udp_transport.clone();
        let batch_strategy = self.batch_strategy.clone();
        let compression_config = self.compression_config.clone();
        let pending_retries = self.pending_retries.clone();
        let stats = self.stats.clone();
        let adaptive_batch_size = self.adaptive_batch_size.clone();
        let current_latency = self.current_latency.clone();
        let throughput_history = self.throughput_history.clone();

        let (tx, mut rx) = mpsc::unbounded_channel::<TransportMessage>();
        {
            let mut sender = self.message_sender.write().await;
            *sender = Some(tx);
        }

        tokio::spawn(async move {
            info!("增强型UDP消息批量处理器已启动");

            let mut message_buffer: Vec<TransportMessage> = Vec::new();
            let mut last_batch_time = Instant::now();
            let mut last_throughput_calc = Instant::now();
            let mut messages_in_period = 0u64;

            while let Some(message) = rx.recv().await {
                let message_start_time = Instant::now();

                // 添加到消息队列
                {
                    let mut queue = message_queue.write().await;
                    queue.push_back(message.clone());
                    // 防止队列无限增长
                    if queue.len() > 10000 {
                        queue.pop_front();
                        warn!("消息队列过满，丢弃最旧的消息");
                    }
                }

                message_buffer.push(message);
                messages_in_period += 1;

                let now = Instant::now();
                let current_batch_size = *adaptive_batch_size.read().await;

                // 检查是否为紧急消息（TLS密钥）
                let is_urgent = message_buffer.iter().any(|msg|
                    matches!(msg.message_type, crate::transport::MessageType::TlsKey));

                // 确定批次参数
                let (batch_size_limit, batch_time_limit) = if is_urgent {
                    (batch_strategy.urgent_batch_size,
                     Duration::from_millis(batch_strategy.urgent_timeout_ms))
                } else {
                    (current_batch_size,
                     Duration::from_millis(batch_strategy.batch_timeout_ms))
                };

                // 检查是否需要发送批量
                let should_send = message_buffer.len() >= batch_size_limit ||
                                  now.duration_since(last_batch_time) >= batch_time_limit;

                if should_send && !message_buffer.is_empty() {
                    let batch_start_time = Instant::now();

                    if let Some(ref transport) = *udp_transport.read().await {
                        // 压缩批量消息
                        let compressed_data = if compression_config.enabled {
                            compress_messages_static(&message_buffer, &compression_config)
                        } else {
                            None
                        };

                        // 创建批量消息
                        let batch_message = create_batch_message_static(&message_buffer, compressed_data);

                        // 发送批量消息
                        match transport.send_message(&batch_message).await {
                            Ok(()) => {
                                // 记录发送统计
                                let mut stats_guard = stats.write().await;
                                stats_guard.messages_sent += message_buffer.len() as u64;
                                stats_guard.batches_sent += 1;
                                stats_guard.average_batch_size =
                                    (stats_guard.average_batch_size * (stats_guard.batches_sent - 1) as f64 +
                                     message_buffer.len() as f64) / stats_guard.batches_sent as f64;

                                // 添加到重传队列（如果启用）
                                if pending_retries.read().await.is_empty() {
                                    // 这里简化处理，实际应该基于消息ID和确认机制
                                }

                                info!("成功发送批量消息，包含 {} 条TLS会话", message_buffer.len());
                                message_buffer.clear();
                                last_batch_time = now;

                                // 更新延迟统计
                                let latency = batch_start_time.elapsed();
                                *current_latency.write().await = latency;
                                stats_guard.average_latency_ms =
                                    (stats_guard.average_latency_ms * (stats_guard.batches_sent - 1) as f64 +
                                     latency.as_millis() as f64) / stats_guard.batches_sent as f64;
                            }
                            Err(e) => {
                                error!("发送批量消息失败: {}", e);

                                // 添加到重传队列
                                if pending_retries.read().await.is_empty() {
                                    for msg in &message_buffer {
                                        let retry = PendingRetry {
                                            message: msg.clone(),
                                            attempts: 0,
                                            next_retry_time: now + Duration::from_millis(100),
                                            original_send_time: now,
                                        };
                                        pending_retries.write().await.insert(
                                            format!("{}:{}", msg.session.five_tuple.src_ip, msg.session.five_tuple.src_port),
                                            retry
                                        );
                                    }
                                }

                                let mut stats_guard = stats.write().await;
                                stats_guard.retry_count += message_buffer.len() as u64;
                            }
                        }
                    } else {
                        error!("UDP传输器不可用，消息将丢弃");
                        message_buffer.clear();
                        last_batch_time = now;
                    }
                }

                // 计算吞吐量（每秒）
                if now.duration_since(last_throughput_calc) >= Duration::from_secs(1) {
                    let throughput = messages_in_period as f64 /
                        now.duration_since(last_throughput_calc).as_secs_f64();

                    {
                        let mut history = throughput_history.write().await;
                        history.push_back(throughput);
                        if history.len() > 100 {
                            history.pop_front();
                        }
                    }

                    messages_in_period = 0;
                    last_throughput_calc = now;
                }

                // 更新处理时间统计
                let processing_time = message_start_time.elapsed();
                {
                    let mut stats_guard = stats.write().await;
                    stats_guard.processing_time_ms = processing_time.as_millis() as f64;
                }
            }

            info!("增强型UDP消息批量处理器已停止");
        });
    }

    /// 启动重传管理器
    async fn start_retry_manager(&self) {
        let pending_retries = self.pending_retries.clone();
        let udp_transport = self.udp_transport.clone();
        let retry_config = self.retry_config.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            info!("重传管理器已启动");

            let mut interval = tokio::time::interval(Duration::from_millis(50));

            loop {
                interval.tick().await;

                let now = Instant::now();
                let mut retries_to_remove = Vec::new();

                {
                    let mut retry_map = pending_retries.write().await;

                    for (key, retry) in retry_map.iter_mut() {
                        if now >= retry.next_retry_time {
                            if retry.attempts >= retry_config.max_retries {
                                retries_to_remove.push(key.clone());

                                // 更新失败统计
                                let mut stats_guard = stats.write().await;
                                stats_guard.failed_retries += 1;

                                warn!("消息重传失败，已达最大重试次数: {}", key);
                                continue;
                            }

                            // 执行重传
                            if let Some(ref transport) = *udp_transport.read().await {
                                match transport.send_message(&retry.message).await {
                                    Ok(()) => {
                                        retries_to_remove.push(key.clone());
                                        info!("重传成功: {}", key);
                                    }
                                    Err(e) => {
                                        error!("重传失败: {} - {}", key, e);
                                        retry.attempts += 1;

                                        // 计算下次重传时间
                                        let delay = Duration::from_millis(
                                            (retry_config.initial_delay_ms as f64 *
                                             retry_config.backoff_multiplier.powi(retry.attempts as i32)) as u64
                                        ).min(Duration::from_millis(retry_config.max_delay_ms));

                                        retry.next_retry_time = now + delay;

                                        // 更新重传统计
                                        let mut stats_guard = stats.write().await;
                                        stats_guard.retry_count += 1;
                                    }
                                }
                            }
                        }
                    }

                    // 移除已完成的重传
                    for key in retries_to_remove {
                        retry_map.remove(&key);
                    }
                }
            }
        });
    }

    /// 启动性能监控器
    async fn start_performance_monitor(&self) {
        let stats = self.stats.clone();
        let message_queue = self.message_queue.clone();
        let pending_retries = self.pending_retries.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                let current_stats = stats.read().await.clone();
                let queue_depth = message_queue.read().await.len();
                let pending_retry_count = pending_retries.read().await.len();

                info!(
                    "传输统计 - 发送: {}, 批次: {}, 平均批次: {:.1}, 延迟: {:.1}ms, 队列: {}, 重传: {}, 失败: {}",
                    current_stats.messages_sent,
                    current_stats.batches_sent,
                    current_stats.average_batch_size,
                    current_stats.average_latency_ms,
                    queue_depth,
                    pending_retry_count,
                    current_stats.failed_retries
                );
            }
        });
    }

  
    /// 估算内存使用量
    fn estimate_memory_usage(&self) -> f64 {
        // 简化估算
        let queue_size = self.message_queue.try_read().map(|q| q.len()).unwrap_or(0) * 1024;
        let retry_size = self.pending_retries.try_read().map(|r| r.len()).unwrap_or(0) * 512;
        let stats_size = std::mem::size_of::<EnhancedTransportStats>();

        (queue_size + retry_size + stats_size) as f64
    }

    /// 将eBPF SSL事件转换为TLS会话
    fn ebpf_event_to_tls_session(&self, event: EbpfSslEvent) -> Result<TlsSession> {
        use crate::common::session::{FiveTuple, ProcessInfo};

        let five_tuple = FiveTuple {
            src_ip: std::net::Ipv4Addr::from(event.src_ip).into(),
            src_port: event.src_port,
            dst_ip: std::net::Ipv4Addr::from(event.dst_ip).into(),
            dst_port: event.dst_port,
            protocol: match event.protocol {
                6 => crate::common::session::Protocol::TCP,
                17 => crate::common::session::Protocol::UDP,
                _ => crate::common::session::Protocol::TCP,
            },
        };

        let process_info = ProcessInfo {
            pid: event.pid,
            process_name: event.process_name.clone(),
            command_line: String::new(),
        };

        let client_random = event.client_random.unwrap_or_default();
        let master_secret = event.master_secret.unwrap_or_default();

        Ok(TlsSession::new(client_random, master_secret, five_tuple, process_info))
    }
}

// 静态辅助函数

/// 压缩消息（静态版本）
fn compress_messages_static(_messages: &[TransportMessage], config: &CompressionConfig) -> Option<Vec<u8>> {
    // 简化实现，实际应该使用压缩库
    if _messages.len() < 10 {
        return None;
    }

    // 模拟压缩（实际实现应该使用 lz4 或 zstd）
    let total_size = _messages.len() * 1024; // 估算大小
    if total_size < config.compression_threshold {
        return None;
    }

    // 这里返回None，表示不进行压缩
    // 实际实现中应该序列化消息并进行压缩
    None
}

/// 创建批量消息（静态版本）
fn create_batch_message_static(messages: &[TransportMessage], compressed_data: Option<Vec<u8>>) -> TransportMessage {
    if let Some(data) = compressed_data {
        // 创建压缩的批量消息
        if let Some(first_msg) = messages.first() {
            let mut batch_msg = first_msg.clone();
            batch_msg.message_type = crate::transport::MessageType::Batch;
            batch_msg.session.client_random = data; // 临时存储压缩数据
            batch_msg
        } else {
            TransportMessage::new_heartbeat()
        }
    } else {
        // 创建未压缩的批量消息
        if let Some(first_msg) = messages.first() {
            first_msg.clone()
        } else {
            TransportMessage::new_heartbeat()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_enhanced_udp_manager_creation() {
        let mut config = TransportConfig::default();
        config.udp.enabled = true;

        let manager = EnhancedUdpTransportManager::new(config);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_batch_strategy_adjustment() {
        let mut config = TransportConfig::default();
        config.udp.enabled = true;

        let manager = EnhancedUdpTransportManager::new(config).unwrap();

        // 测试初始批处理大小调整
        manager.adjust_batch_size().await;

        let current_size = *manager.adaptive_batch_size.read().await;
        assert!(current_size > 0);
    }

    #[test]
    fn test_compression_config_default() {
        let config = CompressionConfig::default();
        assert!(config.enabled);
        assert!(matches!(config.algorithm, CompressionAlgorithm::Lz4));
    }

    #[test]
    fn test_retry_config_default() {
        let config = RetryConfig::default();
        assert!(config.enabled);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay_ms, 100);
    }
}