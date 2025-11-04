/**
 * @file mod.rs
 * @brief 集成层 - 连接各个模块
 * @author sollor525@hotmail.com
 * @version 0.1.0
 * @date 2023-11-04
 */
use std::sync::Arc;
use tracing::{info, error, debug, warn, trace};
use tokio::sync::RwLock;

use crate::common::error::{TlsKeyAgentError, Result};
use crate::common::session::TlsSession;
use crate::extractor::KeyProcessor;
use crate::transport::{TransportMessage, TransportEnum, TransportFactory};

/// 集成管理器 - 负责连接密钥处理器和传输层
pub struct IntegrationManager {
    /// 密钥处理器
    key_processor: Arc<KeyProcessor>,
    /// 传输层实例
    transports: Arc<RwLock<Vec<TransportEnum>>>,
    /// 传输工厂
    transport_factory: Arc<dyn TransportFactory + Send + Sync>,
    /// 是否已初始化
    initialized: Arc<RwLock<bool>>,
    /// 统计信息
    stats: Arc<RwLock<IntegrationStats>>,
}

/// 集成统计信息
#[derive(Debug, Clone, Default)]
pub struct IntegrationStats {
    pub total_sessions_processed: usize,
    pub sessions_transmitted: usize,
    pub sessions_failed: usize,
    pub last_session_time: Option<std::time::SystemTime>,
    pub active_transports: usize,
}

impl IntegrationManager {
    /// 创建新的集成管理器
    pub fn new(
        key_processor: Arc<KeyProcessor>,
        transport_factory: Arc<dyn TransportFactory + Send + Sync>,
    ) -> Self {
        Self {
            key_processor,
            transports: Arc::new(RwLock::new(Vec::new())),
            transport_factory,
            initialized: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(IntegrationStats::default())),
        }
    }

    /// 初始化集成管理器
    pub async fn initialize(&self, transport_configs: Vec<crate::config::TransportConfig>) -> Result<()> {
        debug!("初始化集成管理器");

        {
            let mut initialized = self.initialized.write().await;
            if *initialized {
                warn!("集成管理器已经初始化");
                return Ok(());
            }

            // 创建传输层实例
            let mut transports = self.transports.write().await;
            for config in transport_configs {
                match self.transport_factory.create_transport(&config) {
                    Ok(transport) => {
                        info!("创建传输层成功: {:?}", transport.get_transport_type());
                        transports.push(transport);
                    }
                    Err(e) => {
                        error!("创建传输层失败: {}", e);
                        return Err(e);
                    }
                }
            }

            // 设置会话处理回调
            self.setup_session_callback().await?;

            *initialized = true;
        }

        info!("集成管理器初始化完成，创建了{}个传输层",
              self.transports.read().await.len());

        Ok(())
    }

    /// 设置会话处理回调
    async fn setup_session_callback(&self) -> Result<()> {
        let transports = self.transports.clone();
        let stats = self.stats.clone();

        self.key_processor.set_session_callback(move |session: TlsSession| {
            let transports = transports.clone();
            let stats = stats.clone();
            let message = TransportMessage::new_tls_key(session);

            // 在异步任务中处理会话
            tokio::spawn(async move {
                debug!("收到会话回调，开始处理: {:?}", message.session.five_tuple);

                // 异步发送到所有传输层
                let transports_guard = transports.read().await;
                let mut stats_guard = stats.write().await;

                stats_guard.total_sessions_processed += 1;
                stats_guard.last_session_time = Some(std::time::SystemTime::now());
                stats_guard.active_transports = transports_guard.len();

                let mut success_count = 0;
                let mut failure_count = 0;

                for transport in transports_guard.iter() {
                    match transport.send_message(&message).await {
                        Ok(()) => {
                            debug!("传输成功: {:?}", transport.get_transport_type());
                            success_count += 1;
                        }
                        Err(e) => {
                            error!("传输失败: {:?}, 错误: {}", transport.get_transport_type(), e);
                            failure_count += 1;
                        }
                    }
                }

                // 更新统计信息
                if success_count > 0 {
                    stats_guard.sessions_transmitted += 1;
                }
                if failure_count > 0 {
                    stats_guard.sessions_failed += 1;
                }

                debug!("会话处理完成 - 成功传输: {}, 失败: {}", success_count, failure_count);

                if success_count == 0 {
                    warn!("所有传输都失败了");
                }
            });

            Ok(())
        }).await;

        Ok(())
    }

    /// 启动集成管理器
    pub async fn start(&self) -> Result<()> {
        debug!("启动集成管理器");

        {
            let initialized = self.initialized.read().await;
            if !*initialized {
                return Err(TlsKeyAgentError::Config("集成管理器未初始化".to_string()));
            }
        }

        // 启动所有传输层
        let transports = self.transports.read().await;
        for transport in transports.iter() {
            transport.start().await
                .map_err(|e| TlsKeyAgentError::Transport(format!("启动传输层失败: {}", e)))?;
        }

        info!("集成管理器启动成功，活跃传输层数: {}", transports.len());
        Ok(())
    }

    /// 停止集成管理器
    pub async fn stop(&self) -> Result<()> {
        debug!("停止集成管理器");

        // 停止所有传输层
        let transports = self.transports.read().await;
        for transport in transports.iter() {
            if let Err(e) = transport.stop().await {
                warn!("停止传输层失败: {:?}, 错误: {}", transport.get_transport_type(), e);
            }
        }

        info!("集成管理器已停止");
        Ok(())
    }

    /// 启动会话清理任务
    pub async fn start_cleanup_task(&self) {
        info!("启动集成管理器清理任务");

        let key_processor = self.key_processor.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            // 启动密钥处理器的清理任务
            key_processor.start_cleanup_task().await;

            // 定期更新统计信息
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(30) // 每30秒更新一次
            );

            loop {
                interval.tick().await;

                // 获取密钥处理器统计
                let _key_processor_stats = key_processor.get_stats().await;

                // 更新集成统计信息
                {
                    let _stats_guard = stats.write().await;
                    // 这里可以根据需要合并统计信息
                }

                trace!("集成管理器统计更新完成");
            }
        });
    }

    /// 获取集成统计信息
    pub async fn get_stats(&self) -> IntegrationStats {
        let mut stats = self.stats.read().await.clone();
        stats.active_transports = self.transports.read().await.len();
        stats
    }

    /// 获取密钥处理器统计信息
    pub async fn get_key_processor_stats(&self) -> crate::extractor::ProcessorStats {
        self.key_processor.get_stats().await
    }

    /// 手动触发会话清理
    pub async fn cleanup_sessions(&self) -> usize {
        self.key_processor.cleanup_expired_sessions().await
    }

    /// 获取活跃会话数量
    pub async fn get_active_sessions_count(&self) -> usize {
        self.key_processor.get_active_sessions_count().await
    }

    /// 获取会话年龄分布
    pub async fn get_session_age_distribution(&self) -> Vec<(String, usize)> {
        self.key_processor.get_session_age_distribution().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{DefaultTransportFactory};
    use crate::config::{Config, TransportConfig};

    #[tokio::test]
    async fn test_integration_manager_creation() {
        let config = Config::default();
        let key_processor = Arc::new(KeyProcessor::new(config.filters));
        let factory = Arc::new(DefaultTransportFactory);

        let manager = IntegrationManager::new(key_processor, factory);
        assert!(!*manager.initialized.read().await);
    }

    #[tokio::test]
    async fn test_integration_initialization() {
        let config = Config::default();
        let key_processor = Arc::new(KeyProcessor::new(config.filters));
        let factory = Arc::new(DefaultTransportFactory);

        let manager = IntegrationManager::new(key_processor, factory);

        // 创建一个空的传输配置
        let empty_config = TransportConfig::default();
        let result = manager.initialize(vec![empty_config]).await;
        assert!(result.is_ok());
        assert!(*manager.initialized.read().await);
    }
}