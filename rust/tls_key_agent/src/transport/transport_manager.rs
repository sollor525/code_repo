use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
#[allow(unused_imports)]
use tracing::{info, error, debug, warn};

use crate::common::error::{TlsKeyAgentError, Result};
use crate::common::session::TlsSession;
use crate::transport::{TransportMessage, TransportType, DefaultTransportFactory, TransportEnum, TransportFactory};
use crate::config::{TransportConfig, TcpTransportConfig, RemoteConfigConfig};
use crate::injector::ebpf::EbpfSslEvent;

/// 专用UDP批量传输管理器
#[derive(Debug)]
pub struct UdpTransportManager {
    config: TransportConfig,
    is_running: Arc<RwLock<bool>>,
    message_sender: Arc<RwLock<Option<mpsc::UnboundedSender<TransportMessage>>>>,
    factory: DefaultTransportFactory,
    udp_transport: Arc<RwLock<Option<TransportEnum>>>,
}

impl UdpTransportManager {
    /// 创建新的UDP传输管理器
    pub fn new(config: TransportConfig) -> Result<Self> {
        info!("初始化UDP批量传输管理器");

        Ok(Self {
            config,
            is_running: Arc::new(RwLock::new(false)),
            message_sender: Arc::new(RwLock::new(None)),
            factory: DefaultTransportFactory,
            udp_transport: Arc::new(RwLock::new(None)),
        })
    }

    /// 启动传输管理器
    pub async fn start(&self) -> Result<()> {
        info!("启动UDP批量传输管理器");

        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(TlsKeyAgentError::Config("UDP传输管理器已在运行".to_string()));
        }

        // 初始化UDP传输器
        self.initialize_udp_transport().await?;

        *is_running = true;
        info!("UDP批量传输管理器启动成功");
        Ok(())
    }

    /// 停止传输管理器
    pub async fn stop(&self) -> Result<()> {
        info!("停止UDP批量传输管理器");

        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }

        // 停止消息批量处理器
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

        *is_running = false;
        info!("UDP批量传输管理器已停止");
        Ok(())
    }

    /// 检查是否正在运行
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    /// 初始化UDP传输器
    async fn initialize_udp_transport(&self) -> Result<()> {
        debug!("初始化UDP传输器");

        // 只启用UDP传输
        let temp_config = TransportConfig {
            enabled_transports: vec![TransportType::Udp],
            udp: self.config.udp.clone(),
            tcp: TcpTransportConfig::default(), // 使用默认TCP配置（将被忽略）
            remote_config: RemoteConfigConfig::default(), // 使用默认远程配置
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
                return Err(e);
            }
        }

        Ok(())
    }

  
    /// 发送TLS会话
    pub async fn send_tls_session(&self, session: TlsSession) -> Result<()> {
        if !self.is_running().await {
            return Err(TlsKeyAgentError::Transport("UDP传输管理器未运行".to_string()));
        }

        let message = TransportMessage::new_tls_key(session);
        self.send_message(message).await
    }

    /// 发送eBPF SSL事件
    pub async fn send_ebpf_ssl_event(&self, event: EbpfSslEvent) -> Result<()> {
        if !self.is_running().await {
            return Err(TlsKeyAgentError::Transport("UDP传输管理器未运行".to_string()));
        }

        // 将eBPF事件转换为TLS会话格式
        let session = self.ebpf_event_to_tls_session(event)?;
        self.send_tls_session(session).await
    }

    /// 发送消息
    async fn send_message(&self, message: TransportMessage) -> Result<()> {
        let sender = self.message_sender.read().await;
        if let Some(ref tx) = *sender {
            tx.send(message)
                .map_err(|e| TlsKeyAgentError::Transport(format!("发送消息失败: {}", e)))?;
        } else {
            return Err(TlsKeyAgentError::Transport("消息批量处理器未初始化".to_string()));
        }

        Ok(())
    }

    /// 发送心跳消息
    pub async fn send_heartbeat(&self) -> Result<()> {
        let heartbeat = TransportMessage::new_heartbeat();
        self.send_message(heartbeat).await
    }

    /// 获取传输统计信息
    pub async fn get_stats(&self) -> TransportManagerStats {
        let connected = if let Some(ref transport) = *self.udp_transport.read().await {
            transport.is_connected().await
        } else {
            false
        };

        TransportManagerStats {
            is_running: self.is_running().await,
            connected,
        }
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

/// UDP传输管理器统计信息
#[derive(Debug, Clone)]
pub struct TransportManagerStats {
    pub is_running: bool,
    pub connected: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_transport_manager_creation() {
        let mut config = TransportConfig::default();
        config.udp.enabled = true;
        config.tcp.enabled = false;

        let manager = UdpTransportManager::new(config);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_udp_transport_manager_lifecycle() {
        let mut config = TransportConfig::default();
        config.udp.enabled = true;
        config.udp.server_host = "127.0.0.1".to_string();
        config.udp.server_port = 9999;
        config.tcp.enabled = false;

        let manager = UdpTransportManager::new(config).unwrap();

        assert!(!manager.is_running().await);

        // 启动管理器（可能因为没有实际的UDP服务器而失败）
        let result = manager.start().await;
        if result.is_ok() {
            assert!(manager.is_running().await);

            // 发送心跳
            let heartbeat_result = manager.send_heartbeat().await;
            if heartbeat_result.is_err() {
                warn!("心跳发送失败: {:?}", heartbeat_result);
            }

            // 停止管理器
            manager.stop().await.unwrap();
            assert!(!manager.is_running().await);
        }
    }

    #[tokio::test]
    async fn test_send_message_when_not_running() {
        let mut config = TransportConfig::default();
        config.udp.enabled = true;
        config.tcp.enabled = false;

        let manager = UdpTransportManager::new(config).unwrap();

        let session = TlsSession::new(
            vec![0u8; 32],
            vec![0u8; 48],
            crate::common::session::FiveTuple::wildcard(),
            crate::common::session::ProcessInfo {
                pid: 1234,
                process_name: "test".to_string(),
                command_line: "test".to_string(),
            },
        );

        let result = manager.send_tls_session(session).await;
        assert!(result.is_err());
    }
}