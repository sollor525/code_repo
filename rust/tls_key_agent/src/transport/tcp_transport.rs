use std::sync::Arc;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, error, debug, warn};
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;

use crate::common::error::{TlsKeyAgentError, Result};
use crate::transport::{Transport, TransportMessage, TransportStats};
use crate::config::{TcpTransportConfig, TransportType};

#[derive(Debug)]
pub struct TcpTransport {
    config: TcpTransportConfig,
    is_connected: Arc<tokio::sync::RwLock<bool>>,
    stats: Arc<tokio::sync::RwLock<TcpTransportStats>>,
    message_sender: Arc<tokio::sync::RwLock<Option<tokio::sync::mpsc::UnboundedSender<TransportMessage>>>>,
    tcp_stream: Arc<tokio::sync::RwLock<Option<TcpStream>>>,
}

#[derive(Debug, Clone)]
struct TcpTransportStats {
    messages_sent: u64,
    messages_failed: u64,
    bytes_sent: u64,
    reconnections: u64,
    last_activity: Option<std::time::SystemTime>,
}

impl TcpTransport {
    pub fn new(config: &TcpTransportConfig) -> Result<Self> {
        info!("初始化TCP传输器: {}:{}", config.server_host, config.server_port);

        Ok(Self {
            config: config.clone(),
            is_connected: Arc::new(tokio::sync::RwLock::new(false)),
            stats: Arc::new(tokio::sync::RwLock::new(TcpTransportStats {
                messages_sent: 0,
                messages_failed: 0,
                bytes_sent: 0,
                reconnections: 0,
                last_activity: None,
            })),
            message_sender: Arc::new(tokio::sync::RwLock::new(None)),
            tcp_stream: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    async fn connect(&self) -> Result<()> {
        info!("连接到TCP服务器: {}:{}", self.config.server_host, self.config.server_port);

        let server_addr = format!("{}:{}", self.config.server_host, self.config.server_port);
        let socket_addr: SocketAddr = server_addr.parse()
            .map_err(|e| TlsKeyAgentError::Network(format!("无效的服务器地址: {}", e)))?;

        // 设置连接超时
        let connect_timeout = Duration::from_secs(self.config.timeout);
        let tcp_stream = timeout(connect_timeout, TcpStream::connect(&socket_addr))
            .await
            .map_err(|_| TlsKeyAgentError::Network("连接超时".to_string()))?
            .map_err(|e| TlsKeyAgentError::Network(format!("TCP连接失败: {}", e)))?;

        info!("TCP连接已建立: {}", socket_addr);

        // 保存连接
        {
            let mut stream = self.tcp_stream.write().await;
            *stream = Some(tcp_stream);
        }

        // 更新连接状态
        {
            let mut is_connected = self.is_connected.write().await;
            *is_connected = true;
        }

        Ok(())
    }

    async fn disconnect(&self) {
        info!("断开TCP连接");

        // 关闭TCP连接
        {
            let mut stream = self.tcp_stream.write().await;
            if let Some(mut tcp_stream) = stream.take() {
                if let Err(e) = tcp_stream.shutdown().await {
                    warn!("关闭TCP连接时出错: {}", e);
                }
            }
        }

        // 更新连接状态
        {
            let mut is_connected = self.is_connected.write().await;
            *is_connected = false;
        }
    }

    async fn reconnect(&self) -> Result<()> {
        debug!("尝试重新连接TCP服务器");

        // 更新重连统计
        {
            let mut stats = self.stats.write().await;
            stats.reconnections += 1;
        }

        self.disconnect().await;

        // 实现重试机制
        let mut retry_count = 0;
        let max_retries = self.config.max_retries;
        let retry_interval = Duration::from_secs(self.config.reconnect_interval);

        while retry_count < max_retries {
            debug!("重连尝试 {}/{}", retry_count + 1, max_retries);

            match self.connect().await {
                Ok(()) => {
                    info!("重连成功");
                    return Ok(());
                }
                Err(e) => {
                    warn!("重连失败: {}", e);
                    retry_count += 1;

                    if retry_count < max_retries {
                        debug!("等待 {} 秒后重试", retry_interval.as_secs());
                        tokio::time::sleep(retry_interval).await;
                    }
                }
            }
        }

        error!("重连失败，已达到最大重试次数: {}", max_retries);
        Err(TlsKeyAgentError::Network("重连失败，已达到最大重试次数".to_string()))
    }

    async fn send_data(&self, data: &[u8]) -> Result<()> {
        debug!("TCP数据发送，大小: {} 字节", data.len());

        // 获取TCP连接
        let mut stream = self.tcp_stream.write().await;
        let tcp_stream = stream.as_mut()
            .ok_or_else(|| TlsKeyAgentError::Network("TCP连接未建立".to_string()))?;

        // 添加消息长度前缀（4字节网络字节序）
        let length_prefix = (data.len() as u32).to_be_bytes();
        let mut full_message = Vec::with_capacity(4 + data.len());
        full_message.extend_from_slice(&length_prefix);
        full_message.extend_from_slice(data);

        // 发送数据
        if let Err(e) = tcp_stream.write_all(&full_message).await {
            error!("TCP发送数据失败: {}", e);

            // 更新失败统计
            {
                let mut stats = self.stats.write().await;
                stats.messages_failed += 1;
            }

            // 连接可能已断开，标记为未连接
            {
                let mut is_connected = self.is_connected.write().await;
                *is_connected = false;
            }

            return Err(TlsKeyAgentError::Network(format!("TCP发送失败: {}", e)));
        }

        // 刷新缓冲区
        if let Err(e) = tcp_stream.flush().await {
            warn!("TCP刷新缓冲区失败: {}", e);
        }

        // 更新成功统计信息
        {
            let mut stats = self.stats.write().await;
            stats.messages_sent += 1;
            stats.bytes_sent += full_message.len() as u64;
            stats.last_activity = Some(std::time::SystemTime::now());
        }

        debug!("TCP数据发送成功，大小: {} 字节", full_message.len());
        Ok(())
    }

    async fn start_heartbeat(&self) {
        let is_connected = self.is_connected.clone();
        let message_sender = self.message_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30)); // 30秒心跳

            loop {
                interval.tick().await;

                if *is_connected.read().await {
                    let heartbeat = TransportMessage::new_heartbeat();

                    if let Some(ref sender) = *message_sender.read().await {
                        if let Err(e) = sender.send(heartbeat) {
                            error!("发送心跳消息失败: {}", e);
                        }
                    }
                }
            }
        });
    }

    async fn start_message_sender(&self) {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<TransportMessage>();
        {
            let mut sender = self.message_sender.write().await;
            *sender = Some(tx);
        }

        let tcp_stream = self.tcp_stream.clone();
        let stats = self.stats.clone();
        let is_connected = self.is_connected.clone();

        tokio::spawn(async move {
            info!("TCP消息发送器已启动");

            while let Some(message) = rx.recv().await {
                debug!("处理TCP消息: {:?}", message.message_type);

                // 检查连接状态
                if !*is_connected.read().await {
                    warn!("TCP连接未建立，跳过消息发送");
                    continue;
                }

                // 序列化消息
                match message.serialize() {
                    Ok(data) => {
                        debug!("消息序列化成功，大小: {} 字节", data.len());

                        // 发送数据
                        let send_result = {
                            let mut stream = tcp_stream.write().await;
                            if let Some(tcp_stream) = stream.as_mut() {
                                // 添加消息长度前缀
                                let length_prefix = (data.len() as u32).to_be_bytes();
                                let mut full_message = Vec::with_capacity(4 + data.len());
                                full_message.extend_from_slice(&length_prefix);
                                full_message.extend_from_slice(&data);

                                // 发送完整消息
                                match tcp_stream.write_all(&full_message).await {
                                    Ok(()) => {
                                        // 刷新缓冲区
                                        if let Err(e) = tcp_stream.flush().await {
                                            warn!("TCP刷新缓冲区失败: {}", e);
                                        }
                                        Ok(())
                                    }
                                    Err(e) => {
                                        error!("TCP发送消息失败: {}", e);
                                        Err(e)
                                    }
                                }
                            } else {
                                Err(std::io::Error::new(std::io::ErrorKind::NotConnected, "TCP连接未建立"))
                            }
                        };

                        // 更新统计信息
                        match send_result {
                            Ok(()) => {
                                let mut stats_guard = stats.write().await;
                                stats_guard.messages_sent += 1;
                                stats_guard.bytes_sent += (4 + data.len()) as u64; // 包含长度前缀
                                stats_guard.last_activity = Some(std::time::SystemTime::now());
                                debug!("TCP消息发送成功");
                            }
                            Err(e) => {
                                let mut stats_guard = stats.write().await;
                                stats_guard.messages_failed += 1;

                                // 连接可能已断开，更新状态
                                {
                                    let mut connected = is_connected.write().await;
                                    *connected = false;
                                }

                                error!("TCP消息发送失败: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("消息序列化失败: {}", e);
                        let mut stats_guard = stats.write().await;
                        stats_guard.messages_failed += 1;
                    }
                }
            }

            info!("TCP消息发送器已停止");
        });
    }

    #[allow(dead_code)]
    async fn flush_file(&self) -> Result<()> {
        // TCP不需要flush
        Ok(())
    }
}

#[async_trait::async_trait]
impl Transport for TcpTransport {
    async fn start(&self) -> Result<()> {
        info!("启动TCP传输器");

        // 建立初始连接
        self.connect().await?;

        // 启动消息发送器
        self.start_message_sender().await;

        // 启动心跳
        self.start_heartbeat().await;

        info!("TCP传输器启动成功");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("停止TCP传输器");

        // 停止消息发送器
        {
            let mut sender = self.message_sender.write().await;
            *sender = None;
        }

        // 断开连接
        self.disconnect().await;

        info!("TCP传输器已停止");
        Ok(())
    }

    async fn send_message(&self, message: &TransportMessage) -> Result<()> {
        if !self.is_connected().await {
            // 尝试重连
            if let Err(e) = self.reconnect().await {
                return Err(e);
            }
        }

        let data = message.serialize()?;
        self.send_data(&data).await
    }

    async fn is_connected(&self) -> bool {
        *self.is_connected.read().await
    }

    fn get_transport_type(&self) -> TransportType {
        TransportType::Tcp
    }

    async fn get_stats(&self) -> TransportStats {
        let stats = self.stats.read().await;
        TransportStats {
            transport_type: TransportType::Tcp,
            is_connected: self.is_connected().await,
            messages_sent: stats.messages_sent,
            messages_failed: stats.messages_failed,
            bytes_sent: stats.bytes_sent,
            last_activity: stats.last_activity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_transport_creation() {
        let config = TcpTransportConfig::default();
        let transport = TcpTransport::new(&config);
        assert!(transport.is_ok());
    }

    #[tokio::test]
    async fn test_tcp_transport_lifecycle() {
        let config = TcpTransportConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            server_port: 9999, // 假设没有服务器监听
            connection_timeout: 5,
            keep_alive: true,
            max_retries: 1,
            retry_delay: 1,
            reconnect_interval: 1,
            timeout: 1,
        };

        let transport = TcpTransport::new(&config).unwrap();

        // 测试连接状态
        assert!(!transport.is_connected().await);

        // 注意：实际的连接测试需要真实的服务器
    }
}