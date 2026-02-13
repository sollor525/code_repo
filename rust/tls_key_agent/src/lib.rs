#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod config;
pub mod extractor;
pub mod transport;
pub mod common;
pub mod ffi;
pub mod monitor;
pub mod injector;
pub mod resilience;

use anyhow::Result;
use tracing::info;
use std::sync::Arc;

pub use config::{Config, FilterRule, TransportConfig, TransportType};
pub use extractor::KeyExtractor;
pub use transport::{UdpTransportManager as TransportManager};
pub use common::{error::TlsKeyAgentError, session::TlsSession, buffer::BufferPool};

#[derive(Debug, Clone)]
pub struct TlsKeyAgent {
    #[allow(dead_code)]
    config: Arc<Config>,
    extractor: Arc<KeyExtractor>,
    transport: Arc<TransportManager>,
}

impl TlsKeyAgent {
    pub async fn new(config: Config) -> Result<Self> {
        info!("初始化TLS密钥Agent");

        let config = Arc::new(config);
        let extractor = Arc::new(KeyExtractor::new(config.clone())?);
        let transport = Arc::new(TransportManager::new(config.transport.clone())?);

        Ok(Self {
            config,
            extractor,
            transport,
        })
    }

    pub async fn start(&self) -> Result<()> {
        info!("启动TLS密钥Agent");

        // 启动传输管理器
        self.transport.start().await?;

        // 启动密钥提取器
        self.extractor.start().await?;

        info!("TLS密钥Agent启动成功");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("停止TLS密钥Agent");

        self.extractor.stop().await?;
        self.transport.stop().await?;

        info!("TLS密钥Agent已停止");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        self.extractor.is_running().await && self.transport.is_running().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_creation() {
        let config = Config::default();
        let agent = TlsKeyAgent::new(config).await;
        assert!(agent.is_ok());
    }

    #[tokio::test]
    async fn test_agent_lifecycle() {
        let config = Config::default();
        let agent = TlsKeyAgent::new(config).await.unwrap();

        assert!(!agent.is_running().await);

        // 注意：实际启动测试需要模拟环境
        // agent.start().await.unwrap();
        // assert!(agent.is_running().await);
        // agent.stop().await.unwrap();
        // assert!(!agent.is_running().await);
    }
}