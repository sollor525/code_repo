use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, error, debug, trace, warn};
use parking_lot::Mutex;

use crate::common::error::{TlsKeyAgentError, Result};
use crate::common::session::TlsSession;
use crate::common::buffer::BufferPool;
use crate::config::{FilterRule, FilterEngine};

#[derive(Debug)]
pub struct SessionManager {
    filter_engine: Arc<FilterEngine>,
    #[allow(dead_code)]
    buffer_pool: Arc<BufferPool>,
    is_running: Arc<RwLock<bool>>,
    session_sender: Arc<Mutex<Option<mpsc::UnboundedSender<TlsSession>>>>,
    total_sessions: Arc<RwLock<u64>>,
    active_sessions: Arc<RwLock<HashMap<String, TlsSession>>>,
}

impl SessionManager {
    pub fn new(filter_rules: Vec<FilterRule>, buffer_pool: Arc<BufferPool>) -> Result<Self> {
        info!("初始化会话管理器");

        let filter_engine = Arc::new(FilterEngine::from_config(filter_rules)?);

        Ok(Self {
            filter_engine,
            buffer_pool,
            is_running: Arc::new(RwLock::new(false)),
            session_sender: Arc::new(Mutex::new(None)),
            total_sessions: Arc::new(RwLock::new(0)),
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn start(&self) -> Result<()> {
        info!("启动会话管理器");

        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(TlsKeyAgentError::Config("会话管理器已在运行".to_string()));
        }

        // 创建会话处理通道
        let (tx, mut rx) = mpsc::unbounded_channel();
        *self.session_sender.lock() = Some(tx);

        // 启动会话处理任务
        let active_sessions = self.active_sessions.clone();
        let filter_engine = self.filter_engine.clone();
        let total_sessions = self.total_sessions.clone();

        tokio::spawn(async move {
            info!("会话处理任务已启动");

            while let Some(session) = rx.recv().await {
                debug!("处理TLS会话: {}", session.session_id);

                // 检查是否应该捕获此会话
                if filter_engine.should_capture_session(&session) {
                    // 更新统计信息
                    {
                        let mut total = total_sessions.write().await;
                        *total += 1;
                    }

                    // 存储活跃会话
                    {
                        let mut active = active_sessions.write().await;
                        active.insert(session.session_id.clone(), session.clone());
                    }

                    debug!("会话 {} 已通过过滤规则，正在处理", session.session_id);

                    // 执行完整的会话处理逻辑
                    Self::process_session_complete(&session).await;

                } else {
                    trace!("会话 {} 未通过过滤规则，跳过", session.session_id);
                }
            }

            info!("会话处理任务已停止");
        });

        *is_running = true;
        info!("会话管理器启动成功");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("停止会话管理器");

        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Ok(());
        }

        // 关闭会话通道
        {
            let mut sender = self.session_sender.lock();
            *sender = None;
        }

        // 清理活跃会话
        {
            let mut active = self.active_sessions.write().await;
            active.clear();
        }

        *is_running = false;
        info!("会话管理器已停止");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    pub async fn handle_session(&self, session: TlsSession) -> Result<()> {
        if !self.is_running().await {
            return Err(TlsKeyAgentError::Config("会话管理器未运行".to_string()));
        }

        let sender = self.session_sender.lock();
        if let Some(ref tx) = *sender {
            tx.send(session)
                .map_err(|e| TlsKeyAgentError::Transport(format!("发送会话失败: {}", e)))?;
        } else {
            return Err(TlsKeyAgentError::Transport("会话通道未初始化".to_string()));
        }

        Ok(())
    }

    pub async fn get_active_sessions_count(&self) -> usize {
        self.active_sessions.read().await.len()
    }

    pub async fn get_total_sessions_count(&self) -> u64 {
        *self.total_sessions.read().await
    }

    pub async fn get_active_sessions(&self) -> Vec<TlsSession> {
        self.active_sessions.read().await.values().cloned().collect()
    }

    pub async fn remove_session(&self, session_id: &str) -> bool {
        let mut active = self.active_sessions.write().await;
        active.remove(session_id).is_some()
    }

    pub async fn cleanup_expired_sessions(&self, max_age_seconds: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut active = self.active_sessions.write().await;
        let initial_count = active.len();

        active.retain(|_, session| {
            let age = now - session.timestamp;
            age < max_age_seconds
        });

        let final_count = active.len();
        if initial_count != final_count {
            debug!("清理了{}个过期会话", initial_count - final_count);
        }
    }

    pub async fn get_session_by_id(&self, session_id: &str) -> Option<TlsSession> {
        self.active_sessions.read().await.get(session_id).cloned()
    }

    pub async fn find_sessions_by_process(&self, process_name: &str) -> Vec<TlsSession> {
        let active = self.active_sessions.read().await;
        active.values()
            .filter(|session| session.process_info.process_name.contains(process_name))
            .cloned()
            .collect()
    }

    pub async fn find_sessions_by_port(&self, port: u16) -> Vec<TlsSession> {
        let active = self.active_sessions.read().await;
        active.values()
            .filter(|session| {
                session.five_tuple.src_port == port || session.five_tuple.dst_port == port
            })
            .cloned()
            .collect()
    }

    pub async fn get_session_stats(&self) -> SessionStats {
        let active_sessions = self.active_sessions.read().await;
        let total_sessions = *self.total_sessions.read().await;

        let mut process_stats = HashMap::new();
        let mut port_stats = HashMap::new();

        for session in active_sessions.values() {
            // 统计进程信息
            let process_name = &session.process_info.process_name;
            *process_stats.entry(process_name.clone()).or_insert(0) += 1;

            // 统计端口信息
            let src_port = session.five_tuple.src_port;
            let dst_port = session.five_tuple.dst_port;
            *port_stats.entry(src_port).or_insert(0) += 1;
            *port_stats.entry(dst_port).or_insert(0) += 1;
        }

        SessionStats {
            total_sessions,
            active_sessions: active_sessions.len(),
            process_stats,
            port_stats,
            filter_stats: self.filter_engine.stats(),
        }
    }

    pub fn get_filter_engine(&self) -> Arc<FilterEngine> {
        self.filter_engine.clone()
    }

    /// 完整的会话处理逻辑
    async fn process_session_complete(session: &TlsSession) {
        debug!("开始完整处理TLS会话: {}", session.session_id);

        // 1. 验证会话数据完整性
        if let Err(e) = Self::validate_session_data(session) {
            error!("会话数据验证失败 {}: {}", session.session_id, e);
            return;
        }

        // 2. 提取和记录关键信息
        Self::extract_session_info(session).await;

        // 3. 检查密钥有效性
        if let Err(e) = Self::validate_keys(session) {
            warn!("会话密钥验证失败 {}: {}", session.session_id, e);
            // 注意：即使密钥验证失败，也继续处理，可能是部分密钥可用
        }

        // 4. 生成会话报告
        let report = Self::generate_session_report(session);
        info!("会话报告: {}", report);

        // 5. 清理和优化会话数据
        Self::optimize_session_data(session).await;

        debug!("会话 {} 处理完成", session.session_id);
    }

    /// 验证会话数据完整性
    fn validate_session_data(session: &TlsSession) -> Result<()> {
        // 验证Client Random
        if session.client_random.len() != 32 {
            return Err(TlsKeyAgentError::TlsParse(
                format!("Client Random长度错误: {}", session.client_random.len())
            ));
        }

        // 验证Master Secret
        if session.master_secret.len() != 48 {
            return Err(TlsKeyAgentError::TlsParse(
                format!("Master Secret长度错误: {}", session.master_secret.len())
            ));
        }

        // 验证五元组信息
        if session.five_tuple.src_ip.is_unspecified() || session.five_tuple.dst_ip.is_unspecified() {
            return Err(TlsKeyAgentError::TlsParse("IP地址无效".to_string()));
        }

        // 验证端口范围
        if session.five_tuple.src_port == 0 || session.five_tuple.dst_port == 0 {
            return Err(TlsKeyAgentError::TlsParse("端口无效".to_string()));
        }

        Ok(())
    }

    /// 提取和记录会话信息
    async fn extract_session_info(session: &TlsSession) {
        let timestamp = session.timestamp;
        let formatted_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);

        info!("会话时间: {:?}", formatted_time);
        info!("进程信息: {} (PID: {})", session.process_info.process_name, session.process_info.pid);
        info!("连接信息: {}:{} -> {}:{}",
              session.five_tuple.src_ip, session.five_tuple.src_port,
              session.five_tuple.dst_ip, session.five_tuple.dst_port);

        // 记录密钥指纹
        let client_random_hex = hex::encode(&session.client_random);
        let client_random_fingerprint = &client_random_hex[..16]; // 取前16位作为指纹
        info!("Client Random指纹: {}", client_random_fingerprint);

        // 检查是否为有效的密钥（非全零）
        if !session.client_random.iter().all(|&b| b == 0) {
            debug!("✓ Client Random有效");
        } else {
            warn!("⚠ Client Random为全零，可能无效");
        }

        if !session.master_secret.iter().all(|&b| b == 0) {
            debug!("✓ Master Secret有效");
            let master_secret_hex = hex::encode(&session.master_secret);
            let master_secret_fingerprint = &master_secret_hex[..16];
            info!("Master Secret指纹: {}", master_secret_fingerprint);
        } else {
            debug!("Master Secret为全零（这在现代OpenSSL中是正常的）");
        }
    }

    /// 验证密钥有效性
    fn validate_keys(session: &TlsSession) -> Result<()> {
        // 验证Client Random熵值
        let client_random_entropy = Self::calculate_entropy(&session.client_random);
        if client_random_entropy < 4.0 {
            return Err(TlsKeyAgentError::TlsParse(
                format!("Client Random熵值过低: {:.2}", client_random_entropy)
            ));
        }

        // 验证Master Secret熵值（如果不为空）
        if !session.master_secret.iter().all(|&b| b == 0) {
            let master_secret_entropy = Self::calculate_entropy(&session.master_secret);
            if master_secret_entropy < 4.0 {
                return Err(TlsKeyAgentError::TlsParse(
                    format!("Master Secret熵值过低: {:.2}", master_secret_entropy)
                ));
            }
        }

        Ok(())
    }

    /// 计算数据熵值
    fn calculate_entropy(data: &[u8]) -> f64 {
        use std::collections::HashMap;

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

    /// 生成会话报告
    fn generate_session_report(session: &TlsSession) -> String {
        format!(
            "会话ID: {} | 进程: {} | 连接: {}:{}->{}:{} | 客户端随机: {} | 主密钥状态: {}",
            session.session_id,
            session.process_info.process_name,
            session.five_tuple.src_ip,
            session.five_tuple.src_port,
            session.five_tuple.dst_ip,
            session.five_tuple.dst_port,
            hex::encode(&session.client_random[..8]), // 只显示前8字节
            if session.master_secret.iter().all(|&b| b == 0) { "空" } else { "可用" }
        )
    }

    /// 优化会话数据
    async fn optimize_session_data(session: &TlsSession) {
        // 这里可以添加数据优化逻辑，比如：
        // 1. 压缩存储
        // 2. 去重处理
        // 3. 缓存热点数据
        // 4. 清理不必要的字段

        debug!("优化会话 {} 数据", session.session_id);

        // 检查会话大小
        let session_size = std::mem::size_of_val(session);
        if session_size > 1024 { // 如果会话数据大于1KB
            debug!("会话数据较大: {} bytes", session_size);
        }

        // 检查是否需要缓存
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let session_age = now - session.timestamp;
        if session_age > 300 { // 超过5分钟的会话
            debug!("旧会话检测: {} 秒", session_age);
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionStats {
    pub total_sessions: u64,
    pub active_sessions: usize,
    pub process_stats: HashMap<String, usize>,
    pub port_stats: HashMap<u16, usize>,
    pub filter_stats: crate::config::filter::FilterStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::common::session::{Protocol, ProcessInfo};

    fn create_test_session() -> TlsSession {
        TlsSession::new(
            vec![0u8; 32], // client_random
            vec![0u8; 48], // master_secret
            crate::common::session::FiveTuple {
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_port: 443,
                protocol: Protocol::TCP,
            },
            ProcessInfo {
                pid: 1234,
                process_name: "nginx".to_string(),
                command_line: "nginx -c /etc/nginx/nginx.conf".to_string(),
            },
        )
    }

    #[tokio::test]
    async fn test_session_manager_creation() {
        let buffer_pool = Arc::new(BufferPool::new(8192, 1000));
        let manager = SessionManager::new(vec![], buffer_pool);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_session_lifecycle() {
        let buffer_pool = Arc::new(BufferPool::new(8192, 1000));
        let manager = SessionManager::new(vec![], buffer_pool).unwrap();

        assert!(!manager.is_running().await);

        // 启动管理器
        manager.start().await.unwrap();
        assert!(manager.is_running().await);

        // 处理会话
        let session = create_test_session();
        manager.handle_session(session).await.unwrap();

        // 检查统计信息
        assert_eq!(manager.get_total_sessions_count().await, 1);
        assert_eq!(manager.get_active_sessions_count().await, 1);

        // 停止管理器
        manager.stop().await.unwrap();
        assert!(!manager.is_running().await);
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let buffer_pool = Arc::new(BufferPool::new(8192, 1000));
        let manager = SessionManager::new(vec![], buffer_pool).unwrap();

        manager.start().await.unwrap();

        let session = create_test_session();
        manager.handle_session(session).await.unwrap();

        // 清理过期会话（0秒超时，应该清理所有会话）
        manager.cleanup_expired_sessions(0).await;
        assert_eq!(manager.get_active_sessions_count().await, 0);

        manager.stop().await.unwrap();
    }
}