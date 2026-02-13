use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, debug, warn};

use crate::common::error::{TlsKeyAgentError, Result};
use crate::common::session::TlsSession;
use crate::common::buffer::BufferPool;
use crate::config::Config;
use crate::transport::{TransportMessage, TransportEnum, TransportFactory};
use crate::ffi::set_global_key_processor;

// 注意：ld_preload模块在eBPF架构中不再需要
pub mod ssl_hook;
pub mod session_manager;
pub mod key_processor;

pub use ssl_hook::*;
pub use session_manager::*;
pub use key_processor::*;

#[derive(Debug)]
pub struct KeyExtractor {
    #[allow(dead_code)]
    config: Arc<Config>,
    is_running: Arc<RwLock<bool>>,
    session_manager: Arc<SessionManager>,
    buffer_pool: Arc<BufferPool>,
    ssl_hook: Arc<SslHook>,
    key_processor: Arc<KeyProcessor>,
    transport: Arc<TransportEnum>,
}

impl KeyExtractor {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        info!("初始化密钥提取器");

        let buffer_pool = Arc::new(BufferPool::new(
            config.agent.buffer_size,
            config.agent.buffer_pool_size,
        ));

        let session_manager = Arc::new(SessionManager::new(
            config.filters.clone(),
            buffer_pool.clone(),
        )?);

        let ssl_hook = Arc::new(SslHook::new(
            config.clone(),
            session_manager.clone(),
        )?);

        let key_processor = Arc::new(KeyProcessor::new(config.filters.clone()));

        // 设置全局密钥处理器
        set_global_key_processor(key_processor.clone());

        // 创建传输层
        let transport_factory = crate::transport::DefaultTransportFactory;
        let transport = Arc::new(transport_factory.create_transport(&config.transport)?);

        Ok(Self {
            config,
            is_running: Arc::new(RwLock::new(false)),
            session_manager,
            buffer_pool,
            ssl_hook,
            key_processor,
            transport,
        })
    }

    pub async fn start(&self) -> Result<()> {
        info!("启动密钥提取器");

        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(TlsKeyAgentError::Config("密钥提取器已在运行".to_string()));
        }

        // 启动传输层
        self.transport.start().await?;

        // 设置会话处理回调
        let transport = self.transport.clone();
        self.key_processor.set_session_callback(move |session| {
            debug!("处理TLS会话回调: {:?}", session.five_tuple);

            // 创建传输消息
            let message = TransportMessage::new_tls_key(session);

            // 发送消息
            tokio::spawn({
                let transport = transport.clone();
                async move {
                    if let Err(e) = transport.send_message(&message).await {
                        error!("发送TLS密钥消息失败: {}", e);
                    } else {
                        debug!("TLS密钥消息发送成功");
                    }
                }
            });

            Ok(())
        }).await;

        // 启动SSL Hook
        self.ssl_hook.start().await?;

        // 启动会话管理器
        self.session_manager.start().await?;

        *is_running = true;
        info!("密钥提取器启动成功");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("停止密钥提取器");

        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }

        // 清理会话回调
        self.key_processor.clear_session_callback().await;

        // 停止SSL Hook
        self.ssl_hook.stop().await?;

        // 停止会话管理器
        self.session_manager.stop().await?;

        // 停止传输层
        self.transport.stop().await?;

        *is_running = false;
        info!("密钥提取器已停止");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    pub fn get_session_manager(&self) -> Arc<SessionManager> {
        self.session_manager.clone()
    }

    pub fn get_buffer_pool(&self) -> Arc<BufferPool> {
        self.buffer_pool.clone()
    }

    pub async fn get_stats(&self) -> ExtractorStats {
        ExtractorStats {
            is_running: self.is_running().await,
            active_sessions: self.session_manager.get_active_sessions_count().await,
            total_sessions: self.session_manager.get_total_sessions_count().await as usize,
            buffer_pool_stats: self.buffer_pool.stats(),
        }
    }

    /// 处理 TLS 会话并发送（增强版本）
    pub async fn process_and_send_session(&self, session: TlsSession) -> Result<()> {
        debug!("处理并发送 TLS 会话: {:?}", session.five_tuple);

        // 验证和处理Client Random
        let validated_session = self.validate_client_random(&session)?;

        // 验证和处理Master Secret
        let processed_session = self.process_master_secret(validated_session)?;

        // 创建传输消息
        let message = TransportMessage::new_tls_key(processed_session);

        // 发送到传输层
        match self.transport.send_message(&message).await {
            Ok(()) => {
                info!("✓ TLS 会话消息发送成功: {}", message.session.session_id);
                debug!("Client Random: {} bytes", message.session.client_random.len());
                debug!("Master Secret: {} bytes", message.session.master_secret.len());

                // 记录密钥指纹（用于调试）
                if !message.session.client_random.is_empty() {
                    let cr_fingerprint = hex::encode(&message.session.client_random[..8]);
                    debug!("Client Random指纹: {}", cr_fingerprint);
                }

                if !message.session.master_secret.is_empty() {
                    let ms_fingerprint = hex::encode(&message.session.master_secret[..8]);
                    debug!("Master Secret指纹: {}", ms_fingerprint);
                }
            }
            Err(e) => {
                error!("✗ TLS 会话消息发送失败: {}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// 验证Client Random
    fn validate_client_random(&self, session: &TlsSession) -> Result<TlsSession> {
        if session.client_random.len() != 32 {
            warn!("⚠ Client Random长度异常: {} (期望32)", session.client_random.len());

            if session.client_random.is_empty() {
                return Err(TlsKeyAgentError::TlsParse(
                    "Client Random为空，无法进行TLS密钥提取".to_string()
                ));
            }

            // 如果长度不对但不为空，记录警告并继续处理
            warn!("继续处理长度异常的Client Random");
        }

        // 检查Client Random的熵值
        let entropy = self.calculate_entropy(&session.client_random);
        if entropy < 4.0 {
            warn!("⚠ Client Random熵值过低: {:.2} (可能存在问题)", entropy);
        }

        debug!("✓ Client Random验证通过 (熵值: {:.2})", entropy);
        Ok(session.clone())
    }

    /// 处理Master Secret
    fn process_master_secret(&self, session: TlsSession) -> Result<TlsSession> {
        if session.master_secret.len() != 48 {
            if session.master_secret.is_empty() {
                debug!("Master Secret为空，这在现代OpenSSL中是正常的");
                // 返回原会话，不报错
                return Ok(session);
            } else {
                warn!("⚠ Master Secret长度异常: {} (期望48)", session.master_secret.len());

                // 如果是部分数据，尝试补零或截断
                let mut processed_session = session.clone();
                if processed_session.master_secret.len() > 48 {
                    // 截断到48字节
                    processed_session.master_secret.truncate(48);
                    warn!("Master Secret已截断到48字节");
                } else if processed_session.master_secret.len() < 48 {
                    // 补零到48字节
                    let mut master_secret = processed_session.master_secret.clone();
                    master_secret.resize(48, 0);
                    processed_session.master_secret = master_secret;
                    warn!("Master Secret已补零到48字节");
                }

                return Ok(processed_session);
            }
        }

        // 检查Master Secret的熵值
        let entropy = self.calculate_entropy(&session.master_secret);
        if entropy < 4.0 {
            warn!("⚠ Master Secret熵值过低: {:.2} (可能存在问题)", entropy);
        }

        debug!("✓ Master Secret处理通过 (熵值: {:.2})", entropy);
        Ok(session)
    }

    /// 计算数据熵值
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        use std::collections::HashMap;

        if data.is_empty() {
            return 0.0;
        }

        let mut frequency = HashMap::new();
        let len = data.len() as f64;

        // 计算每个字节的出现频率
        for &byte in data {
            *frequency.entry(byte).or_insert(0) += 1;
        }

        // 计算香农熵
        let mut entropy = 0.0;
        for &count in frequency.values() {
            let probability = count as f64 / len;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }

        entropy
    }

    /// 批量处理多个会话
    pub async fn process_sessions_batch(&self, sessions: Vec<TlsSession>) -> Result<usize> {
        if sessions.is_empty() {
            return Ok(0);
        }

        let total_count = sessions.len();
        info!("开始批量处理 {} 个TLS会话", total_count);
        let mut success_count = 0;

        for session in sessions {
            match self.process_and_send_session(session).await {
                Ok(()) => success_count += 1,
                Err(e) => error!("批量处理中失败的会话: {}", e),
            }
        }

        info!("批量处理完成: {}/{} 成功", success_count, total_count);
        Ok(success_count)
    }

    /// 验证会话完整性
    pub fn validate_session_integrity(&self, session: &TlsSession) -> Result<()> {
        // 验证基本字段
        if session.session_id.is_empty() {
            return Err(TlsKeyAgentError::TlsParse("会话ID为空".to_string()));
        }

        // 验证五元组
        if session.five_tuple.src_ip.is_unspecified() && session.five_tuple.dst_ip.is_unspecified() {
            return Err(TlsKeyAgentError::TlsParse("源和目标IP都未指定".to_string()));
        }

        // 验证端口
        if session.five_tuple.src_port == 0 || session.five_tuple.dst_port == 0 {
            warn!("端口号为零，可能是通配符配置");
        }

        // 验证进程信息
        if session.process_info.pid == 0 {
            warn!("进程ID为零，可能无法获取进程信息");
        }

        debug!("✓ 会话完整性验证通过: {}", session.session_id);
        Ok(())
    }

    /// 获取密钥处理器
    pub fn get_key_processor(&self) -> Arc<KeyProcessor> {
        self.key_processor.clone()
    }
}

#[derive(Debug, Clone)]
pub struct ExtractorStats {
    pub is_running: bool,
    pub active_sessions: usize,
    pub total_sessions: usize,
    pub buffer_pool_stats: crate::common::buffer::PoolStats,
}

// C FFI 接口函数
#[no_mangle]
pub unsafe extern "C" fn on_ssl_client_random(
    ssl_ptr: *mut std::ffi::c_void,
    client_random: *const u8,
    len: usize,
) -> i32 {
    debug!("收到SSL Client Random回调");

    if ssl_ptr.is_null() || client_random.is_null() {
        error!("SSL Client Random回调参数为空");
        return -1;
    }

    if len != 32 {
        error!("Client Random长度不正确: {} (期望: 32)", len);
        return -1;
    }

    // 复制Client Random数据
    let client_random_data = unsafe {
        std::slice::from_raw_parts(client_random, len).to_vec()
    };

    debug!("Client Random: {}", hex::encode(&client_random_data));

    // 获取全局密钥处理器
    let processor = crate::ffi::get_global_key_processor();
    if let Some(processor) = processor {
        // 注意：这里需要在异步上下文中调用，暂时使用同步方式
        if let Err(e) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                processor.process_client_random(ssl_ptr, &client_random_data)
            )
        }) {
            error!("处理Client Random失败: {}", e);
            return -1;
        }
    } else {
        error!("全局密钥处理器未设置");
        return -1;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn on_ssl_master_secret(
    ssl_ptr: *mut std::ffi::c_void,
    master_secret: *const u8,
    len: usize,
) -> i32 {
    debug!("收到SSL Master Secret回调");

    if ssl_ptr.is_null() || master_secret.is_null() {
        error!("SSL Master Secret回调参数为空");
        return -1;
    }

    if len != 48 {
        error!("Master Secret长度不正确: {} (期望: 48)", len);
        return -1;
    }

    // 复制Master Secret数据
    let master_secret_data = unsafe {
        std::slice::from_raw_parts(master_secret, len).to_vec()
    };

    debug!("Master Secret: {}", hex::encode(&master_secret_data));

    // 获取全局密钥处理器
    let processor = crate::ffi::get_global_key_processor();
    if let Some(processor) = processor {
        // 注意：这里需要在异步上下文中调用，暂时使用同步方式
        if let Err(e) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(
                processor.process_master_secret(ssl_ptr, &master_secret_data)
            )
        }) {
            error!("处理Master Secret失败: {}", e);
            return -1;
        }
    } else {
        error!("全局密钥处理器未设置");
        return -1;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn on_ssl_session_ticket(
    ssl_ptr: *mut std::ffi::c_void,
    session_ticket: *const u8,
    len: usize,
) -> i32 {
    debug!("收到SSL Session Ticket回调");

    if ssl_ptr.is_null() || session_ticket.is_null() {
        error!("SSL Session Ticket回调参数为空");
        return -1;
    }

    if len == 0 {
        debug!("Session Ticket为空，跳过处理");
        return 0;
    }

    // 复制Session Ticket数据
    let session_ticket_data = unsafe {
        std::slice::from_raw_parts(session_ticket, len).to_vec()
    };

    debug!("Session Ticket (长度: {}): {}", len, hex::encode(&session_ticket_data));

    // 获取全局密钥处理器
    let processor = crate::ffi::get_global_key_processor();
    if let Some(_processor) = processor {
        // 注意：Session Ticket处理暂时简化，直接记录日志
        info!("收到Session Ticket，长度: {}", session_ticket_data.len());
        debug!("Session Ticket内容: {}", hex::encode(&session_ticket_data));
    } else {
        error!("全局密钥处理器未设置");
        return -1;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_extractor_creation() {
        let config = Arc::new(Config::default());
        let extractor = KeyExtractor::new(config);
        assert!(extractor.is_ok());
    }

    #[tokio::test]
    async fn test_key_extractor_lifecycle() {
        let config = Arc::new(Config::default());
        let extractor = KeyExtractor::new(config).unwrap();

        assert!(!extractor.is_running().await);

        // 注意：实际的启动测试可能需要模拟环境
        // extractor.start().await.unwrap();
        // assert!(extractor.is_running().await);
        // extractor.stop().await.unwrap();
        // assert!(!extractor.is_running().await);
    }
}