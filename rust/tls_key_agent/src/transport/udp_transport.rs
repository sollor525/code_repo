/**
 * @file udp_transport.rs
 * @brief UDP传输器 - 基本的UDP数据传输实现
 * @author sollor525@hotmail.com
 * @version 0.1.0
 * @date 2025-12-01
 */
use std::sync::Arc;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{info, debug};

use crate::common::error::{TlsKeyAgentError, Result};
use crate::config::{UdpTransportConfig, TransportType};
use crate::transport::{TransportMessage, TransportStats};

/// UDP传输器
#[derive(Debug)]
pub struct UdpTransport {
    #[allow(dead_code)]
    config: UdpTransportConfig,
    socket: Arc<RwLock<Option<UdpSocket>>>,
    stats: Arc<RwLock<TransportStats>>,
    server_addr: SocketAddr,
}

impl UdpTransport {
    /// 创建新的UDP传输器
    pub fn new(config: &UdpTransportConfig) -> Result<Self> {
        let server_addr: SocketAddr = format!("{}:{}", config.server_host, config.server_port)
            .parse()
            .map_err(|e| TlsKeyAgentError::Transport(format!("无效的服务器地址: {}", e)))?;

        info!("创建UDP传输器: {}:{}", config.server_host, config.server_port);

        Ok(Self {
            config: config.clone(),
            socket: Arc::new(RwLock::new(None)),
            stats: Arc::new(RwLock::new(TransportStats {
                transport_type: TransportType::Udp,
                is_connected: false,
                messages_sent: 0,
                messages_failed: 0,
                bytes_sent: 0,
                last_activity: None,
            })),
            server_addr,
        })
    }

    /// 启动UDP传输器
    pub async fn start(&self) -> Result<()> {
        info!("启动UDP传输器");

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| TlsKeyAgentError::Transport(format!("绑定UDP套接字失败: {}", e)))?;

        // 连接到服务器
        socket.connect(self.server_addr)
            .await
            .map_err(|e| TlsKeyAgentError::Transport(format!("连接到服务器失败: {}", e)))?;

        let mut socket_guard = self.socket.write().await;
        *socket_guard = Some(socket);

        // 更新连接状态
        {
            let mut stats = self.stats.write().await;
            stats.is_connected = true;
            stats.last_activity = Some(std::time::SystemTime::now());
        }

        info!("UDP传输器启动成功，连接到: {}", self.server_addr);
        Ok(())
    }

    /// 停止UDP传输器
    pub async fn stop(&self) -> Result<()> {
        info!("停止UDP传输器");

        let mut socket_guard = self.socket.write().await;
        *socket_guard = None;

        // 更新连接状态
        {
            let mut stats = self.stats.write().await;
            stats.is_connected = false;
        }

        info!("UDP传输器已停止");
        Ok(())
    }

    /// 发送消息
    pub async fn send_message(&self, message: &TransportMessage) -> Result<()> {
        let socket_guard = self.socket.read().await;

        match socket_guard.as_ref() {
            Some(socket) => {
                // 序列化消息
                let serialized = serde_json::to_vec(message)
                    .map_err(|e| TlsKeyAgentError::Transport(format!("序列化消息失败: {}", e)))?;

                // 发送数据
                socket.send(&serialized)
                    .await
                    .map_err(|e| TlsKeyAgentError::Transport(format!("发送UDP数据失败: {}", e)))?;

                // 更新统计信息
                let mut stats = self.stats.write().await;
                stats.messages_sent += 1;
                stats.bytes_sent += serialized.len() as u64;
                stats.last_activity = Some(std::time::SystemTime::now());

                debug!("UDP消息发送成功，大小: {} 字节", serialized.len());
                Ok(())
            }
            None => {
                Err(TlsKeyAgentError::Transport("UDP套接字未初始化".to_string()))
            }
        }
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> TransportStats {
        self.stats.read().await.clone()
    }

    /// 重置统计信息
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        stats.messages_sent = 0;
        stats.messages_failed = 0;
        stats.bytes_sent = 0;
        stats.last_activity = None;
        // 保持连接状态不变
    }

    /// 检查连接状态
    pub async fn is_connected(&self) -> bool {
        let socket_guard = self.socket.read().await;
        socket_guard.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_transport_creation() {
        let config = UdpTransportConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            server_port: 9999,
            batch_size: 100,
            batch_timeout_ms: 1000,
            compression: false,
            reconnect_interval: 5,
            max_retries: 3,
            timeout: 30,
        };

        let transport = UdpTransport::new(&config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_invalid_server_address() {
        let config = UdpTransportConfig {
            enabled: true,
            server_host: "invalid_address".to_string(),
            server_port: 9999,
            batch_size: 100,
            batch_timeout_ms: 1000,
            compression: false,
            reconnect_interval: 5,
            max_retries: 3,
            timeout: 30,
        };

        let transport = UdpTransport::new(&config);
        assert!(transport.is_err());
    }
}