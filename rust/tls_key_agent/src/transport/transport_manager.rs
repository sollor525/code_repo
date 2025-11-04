use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, error, debug, warn};

use crate::common::error::{TlsKeyAgentError, Result};
use crate::common::session::TlsSession;
use crate::transport::{TransportMessage, TransportStats, TransportType, DefaultTransportFactory, TransportEnum, TransportFactory};
use crate::config::TransportConfig;

#[derive(Debug)]
pub struct TransportManager {
    config: TransportConfig,
    transports: Arc<RwLock<HashMap<TransportType, TransportEnum>>>,
    is_running: Arc<RwLock<bool>>,
    message_sender: Arc<RwLock<Option<mpsc::UnboundedSender<TransportMessage>>>>,
    factory: DefaultTransportFactory,
}

impl TransportManager {
    pub fn new(config: TransportConfig) -> Result<Self> {
        info!("初始化传输管理器");

        Ok(Self {
            config,
            transports: Arc::new(RwLock::new(HashMap::new())),
            is_running: Arc::new(RwLock::new(false)),
            message_sender: Arc::new(RwLock::new(None)),
            factory: DefaultTransportFactory,
        })
    }

    pub async fn start(&self) -> Result<()> {
        info!("启动传输管理器");

        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(TlsKeyAgentError::Config("传输管理器已在运行".to_string()));
        }

        // 初始化启用的传输器
        self.initialize_transports().await?;

        // 启动消息分发器
        self.start_message_distributor().await;

        *is_running = true;
        info!("传输管理器启动成功");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("停止传输管理器");

        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }

        // 停止消息分发器
        {
            let mut sender = self.message_sender.write().await;
            *sender = None;
        }

        // 停止所有传输器
        let transports = self.transports.read().await;
        for (transport_type, transport) in transports.iter() {
            debug!("停止传输器: {:?}", transport_type);
            if let Err(e) = transport.stop().await {
                error!("停止传输器 {:?} 失败: {}", transport_type, e);
            }
        }

        *is_running = false;
        info!("传输管理器已停止");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    async fn initialize_transports(&self) -> Result<()> {
        debug!("初始化传输器");

        let mut transports = self.transports.write().await;

        for transport_type in &self.config.enabled_transports {
            debug!("初始化传输器: {:?}", transport_type);

            // 创建临时配置，只包含当前传输类型的配置
            let temp_config = TransportConfig {
                enabled_transports: vec![transport_type.clone()],
                tcp: self.config.tcp.clone(),
                file: self.config.file.clone(),
            };

            match self.factory.create_transport(&temp_config) {
                Ok(transport) => {
                    // 启动传输器
                    transport.start().await
                        .map_err(|e| TlsKeyAgentError::Transport(
                            format!("启动传输器 {:?} 失败: {}", transport_type, e)
                        ))?;

                    transports.insert(transport_type.clone(), transport);
                    info!("传输器 {:?} 初始化并启动成功", transport_type);
                }
                Err(e) => {
                    error!("创建传输器 {:?} 失败: {}", transport_type, e);
                    return Err(e);
                }
            }
        }

        if transports.is_empty() {
            return Err(TlsKeyAgentError::Transport("没有可用的传输器".to_string()));
        }

        Ok(())
    }

    async fn start_message_distributor(&self) {
        debug!("启动消息分发器");

        let (tx, mut rx) = mpsc::unbounded_channel::<TransportMessage>();
        {
            let mut sender = self.message_sender.write().await;
            *sender = Some(tx);
        }

        let transports = self.transports.clone();

        tokio::spawn(async move {
            info!("消息分发器已启动");

            while let Some(message) = rx.recv().await {
                debug!("分发消息: {:?}", message.message_type);

                let transports_guard = transports.read().await;

                // 将消息发送到所有活跃的传输器
                let mut success_count = 0;
                let mut total_count = 0;

                for (transport_type, transport) in transports_guard.iter() {
                    total_count += 1;

                    match transport.send_message(&message).await {
                        Ok(()) => {
                            success_count += 1;
                            debug!("消息成功发送到传输器: {:?}", transport_type);
                        }
                        Err(e) => {
                            error!("消息发送到传输器 {:?} 失败: {}", transport_type, e);
                        }
                    }
                }

                if success_count == 0 && total_count > 0 {
                    error!("消息发送失败，所有传输器都不可用");
                } else if success_count < total_count {
                    warn!("消息只发送到 {}/{} 个传输器", success_count, total_count);
                } else {
                    debug!("消息成功发送到所有 {} 个传输器", total_count);
                }
            }

            info!("消息分发器已停止");
        });
    }

    pub async fn send_tls_session(&self, session: TlsSession) -> Result<()> {
        if !self.is_running().await {
            return Err(TlsKeyAgentError::Transport("传输管理器未运行".to_string()));
        }

        let message = TransportMessage::new_tls_key(session);
        self.send_message(message).await
    }

    pub async fn send_message(&self, message: TransportMessage) -> Result<()> {
        let sender = self.message_sender.read().await;
        if let Some(ref tx) = *sender {
            tx.send(message)
                .map_err(|e| TlsKeyAgentError::Transport(format!("发送消息失败: {}", e)))?;
        } else {
            return Err(TlsKeyAgentError::Transport("消息分发器未初始化".to_string()));
        }

        Ok(())
    }

    pub async fn send_heartbeat(&self) -> Result<()> {
        let heartbeat = TransportMessage::new_heartbeat();
        self.send_message(heartbeat).await
    }

    pub async fn get_transport_stats(&self) -> HashMap<TransportType, TransportStats> {
        let transports = self.transports.read().await;
        let mut stats = HashMap::new();

        for (transport_type, transport) in transports.iter() {
            let transport_stats = transport.get_stats().await;
            stats.insert(transport_type.clone(), transport_stats);
        }

        stats
    }

    pub async fn get_transport(&self, transport_type: &TransportType) -> Option<TransportEnum> {
        let transports = self.transports.read().await;
        transports.get(transport_type).cloned()
    }

    pub async fn get_connected_transports(&self) -> Vec<TransportType> {
        let transports = self.transports.read().await;
        let mut connected = Vec::new();

        for (transport_type, transport) in transports.iter() {
            if transport.is_connected().await {
                connected.push(transport_type.clone());
            }
        }

        connected
    }

    pub async fn get_manager_stats(&self) -> TransportManagerStats {
        let transports = self.transports.read().await;
        let transport_stats = self.get_transport_stats().await;

        let mut total_messages_sent = 0;
        let mut total_messages_failed = 0;
        let mut total_bytes_sent = 0;
        let mut connected_transports = 0;

        for stats in transport_stats.values() {
            total_messages_sent += stats.messages_sent;
            total_messages_failed += stats.messages_failed;
            total_bytes_sent += stats.bytes_sent;
            if stats.is_connected {
                connected_transports += 1;
            }
        }

        TransportManagerStats {
            is_running: self.is_running().await,
            total_transports: transports.len(),
            connected_transports,
            total_messages_sent,
            total_messages_failed,
            total_bytes_sent,
            transport_stats,
        }
    }

    // 重启指定的传输器
    pub async fn restart_transport(&self, transport_type: &TransportType) -> Result<()> {
        info!("重启传输器: {:?}", transport_type);

        // 停止现有传输器
        {
            let mut transports = self.transports.write().await;
            if let Some(transport) = transports.remove(transport_type) {
                if let Err(e) = transport.stop().await {
                    error!("停止传输器 {:?} 失败: {}", transport_type, e);
                }
            }
        }

        // 重新创建并启动传输器
        let temp_config = TransportConfig {
            enabled_transports: vec![transport_type.clone()],
            tcp: self.config.tcp.clone(),
            file: self.config.file.clone(),
        };

        let new_transport = self.factory.create_transport(&temp_config)?;
        new_transport.start().await?;

        {
            let mut transports = self.transports.write().await;
            transports.insert(transport_type.clone(), new_transport);
        }

        info!("传输器 {:?} 重启成功", transport_type);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TransportManagerStats {
    pub is_running: bool,
    pub total_transports: usize,
    pub connected_transports: usize,
    pub total_messages_sent: u64,
    pub total_messages_failed: u64,
    pub total_bytes_sent: u64,
    pub transport_stats: HashMap<TransportType, TransportStats>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_manager_creation() {
        let config = TransportConfig::default();
        let manager = TransportManager::new(config);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_transport_manager_lifecycle() {
        let mut config = TransportConfig::default();
        config.tcp.enabled = false; // 禁用TCP以避免连接问题
        config.file.enabled = true; // 启用文件传输

        let manager = TransportManager::new(config).unwrap();

        assert!(!manager.is_running().await);

        // 启动管理器
        manager.start().await.unwrap();
        assert!(manager.is_running().await);

        // 发送心跳
        let result = manager.send_heartbeat().await;
        assert!(result.is_ok());

        // 停止管理器
        manager.stop().await.unwrap();
        assert!(!manager.is_running().await);
    }

    #[tokio::test]
    async fn test_send_message_when_not_running() {
        let config = TransportConfig::default();
        let manager = TransportManager::new(config).unwrap();

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