use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::common::error::{TlsKeyAgentError, Result};
use crate::common::session::TlsSession;
use crate::config::{TransportConfig, TransportType};

pub mod tcp_transport;
pub mod file_transport;
pub mod transport_manager;
pub mod key_output;

pub use tcp_transport::*;
pub use file_transport::*;
pub use transport_manager::*;
pub use key_output::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportMessage {
    pub message_type: MessageType,
    pub session: TlsSession,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    TlsKey,
    Heartbeat,
    ConfigUpdate,
}

impl TransportMessage {
    pub fn new_tls_key(session: TlsSession) -> Self {
        Self {
            message_type: MessageType::TlsKey,
            session,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn new_heartbeat() -> Self {
        Self {
            message_type: MessageType::Heartbeat,
            session: TlsSession::new(
                vec![],
                vec![],
                crate::common::session::FiveTuple::wildcard(),
                crate::common::session::ProcessInfo {
                    pid: 0,
                    process_name: "heartbeat".to_string(),
                    command_line: "".to_string(),
                },
            ),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| TlsKeyAgentError::Serialization(format!("序列化失败: {}", e)))
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| TlsKeyAgentError::Serialization(format!("反序列化失败: {}", e)))
    }
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn send_message(&self, message: &TransportMessage) -> Result<()>;
    async fn is_connected(&self) -> bool;
    fn get_transport_type(&self) -> TransportType;
    async fn get_stats(&self) -> TransportStats;
}

#[derive(Debug, Clone)]
pub struct TransportStats {
    pub transport_type: TransportType,
    pub is_connected: bool,
    pub messages_sent: u64,
    pub messages_failed: u64,
    pub bytes_sent: u64,
    pub last_activity: Option<std::time::SystemTime>,
}

#[derive(Debug, Clone)]
pub enum TransportEnum {
    Tcp(Arc<TcpTransport>),
    File(Arc<FileTransport>),
}

impl TransportEnum {
    pub async fn start(&self) -> Result<()> {
        match self {
            TransportEnum::Tcp(transport) => transport.start().await,
            TransportEnum::File(transport) => transport.start().await,
        }
    }

    pub async fn stop(&self) -> Result<()> {
        match self {
            TransportEnum::Tcp(transport) => transport.stop().await,
            TransportEnum::File(transport) => transport.stop().await,
        }
    }

    pub async fn send_message(&self, message: &TransportMessage) -> Result<()> {
        match self {
            TransportEnum::Tcp(transport) => transport.send_message(message).await,
            TransportEnum::File(transport) => transport.send_message(message).await,
        }
    }

    pub async fn is_connected(&self) -> bool {
        match self {
            TransportEnum::Tcp(transport) => transport.is_connected().await,
            TransportEnum::File(transport) => transport.is_connected().await,
        }
    }

    pub fn get_transport_type(&self) -> TransportType {
        match self {
            TransportEnum::Tcp(_) => TransportType::Tcp,
            TransportEnum::File(_) => TransportType::File,
        }
    }

    pub async fn get_stats(&self) -> TransportStats {
        match self {
            TransportEnum::Tcp(transport) => transport.get_stats().await,
            TransportEnum::File(transport) => transport.get_stats().await,
        }
    }
}

pub trait TransportFactory: Send + Sync {
    fn create_transport(&self, config: &TransportConfig) -> Result<TransportEnum>;
}

#[derive(Debug)]
pub struct DefaultTransportFactory;

impl TransportFactory for DefaultTransportFactory {
    fn create_transport(&self, config: &TransportConfig) -> Result<TransportEnum> {
        // 根据配置创建相应的传输器
        if config.enabled_transports.contains(&TransportType::Tcp) && config.tcp.enabled {
            Ok(TransportEnum::Tcp(Arc::new(TcpTransport::new(&config.tcp)?)))
        } else if config.enabled_transports.contains(&TransportType::File) && config.file.enabled {
            Ok(TransportEnum::File(Arc::new(FileTransport::new(&config.file)?)))
        } else {
            Err(TlsKeyAgentError::Transport("没有启用的传输方式".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_message_creation() {
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

        let message = TransportMessage::new_tls_key(session);
        assert!(matches!(message.message_type, MessageType::TlsKey));
        assert!(message.timestamp > 0);
    }

    #[test]
    fn test_heartbeat_message() {
        let message = TransportMessage::new_heartbeat();
        assert!(matches!(message.message_type, MessageType::Heartbeat));
        assert!(message.timestamp > 0);
    }

    #[test]
    fn test_message_serialization() {
        let message = TransportMessage::new_heartbeat();
        let serialized = message.serialize().unwrap();
        let deserialized = TransportMessage::deserialize(&serialized).unwrap();

        assert!(matches!(deserialized.message_type, MessageType::Heartbeat));
        assert_eq!(message.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_default_transport_factory() {
        let factory = DefaultTransportFactory;

        // 测试没有启用传输的情况
        let empty_config = TransportConfig::default();
        let result = factory.create_transport(&empty_config);
        assert!(result.is_ok()); // TCP默认启用
    }
}