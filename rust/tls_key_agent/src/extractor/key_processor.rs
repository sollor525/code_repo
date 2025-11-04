/**
 * @file key_processor.rs
 * @brief TLS密钥处理器 - 处理从OpenSSL Hook提取的密钥信息
 * @author sollor525@hotmail.com
 * @version 0.1.0
 * @date 2023-11-04
 */
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::RwLock;
use tracing::{info, error, debug, warn, trace};
use std::net::IpAddr;
use std::str::FromStr;

use crate::common::error::{TlsKeyAgentError, Result};
use crate::common::session::{FiveTuple, Protocol, TlsSession, ProcessInfo};
use crate::config::FilterRule;

/// 会话处理回调类型
pub type SessionCallback = Box<dyn Fn(TlsSession) -> Result<()> + Send + Sync>;

/// 密钥信息处理器
pub struct KeyProcessor {
    /// 过滤规则
    filter_rules: Arc<RwLock<Vec<FilterRule>>>,
    /// 活跃的会话信息
    active_sessions: Arc<RwLock<HashMap<usize, PendingSession>>>,
    /// 统计信息
    stats: Arc<RwLock<ProcessorStats>>,
    /// 会话处理回调
    session_callback: Arc<RwLock<Option<SessionCallback>>>,
    /// 会话ID计数器
    session_counter: AtomicUsize,
}

impl std::fmt::Debug for KeyProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyProcessor")
            .field("filter_rules", &"<Vec<FilterRule>>")
            .field("active_sessions", &"<HashMap<usize, PendingSession>>")
            .field("stats", &"<ProcessorStats>")
            .field("session_callback", &"<SessionCallback>")
            .field("session_counter", &self.session_counter)
            .finish()
    }
}

/// 待完成的会话信息
#[derive(Debug, Clone)]
pub struct PendingSession {
    /// SSL 指针（作为唯一标识）
    pub ssl_ptr: usize,
    /// Client Random
    pub client_random: Option<Vec<u8>>,
    /// Master Secret
    pub master_secret: Option<Vec<u8>>,
    /// 连接信息
    pub five_tuple: Option<FiveTuple>,
    /// 进程信息
    pub process_info: Option<ProcessInfo>,
    /// 创建时间
    pub created_at: std::time::SystemTime,
}

/// 处理器统计信息
#[derive(Debug, Clone, Default)]
pub struct ProcessorStats {
    pub total_client_randoms: usize,
    pub total_master_secrets: usize,
    pub total_sessions: usize,
    pub filtered_sessions: usize,
    pub processed_sessions: usize,
    pub error_count: usize,
    pub expired_sessions: usize,
    pub active_sessions: usize,
    pub last_cleanup: Option<std::time::SystemTime>,
}

impl KeyProcessor {
    pub fn new(filter_rules: Vec<FilterRule>) -> Self {
        Self {
            filter_rules: Arc::new(RwLock::new(filter_rules)),
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ProcessorStats::default())),
            session_callback: Arc::new(RwLock::new(None)),
            session_counter: AtomicUsize::new(0),
        }
    }

    /// 设置会话处理回调
    pub async fn set_session_callback<F>(&self, callback: F)
    where
        F: Fn(TlsSession) -> Result<()> + Send + Sync + 'static,
    {
        let mut cb = self.session_callback.write().await;
        *cb = Some(Box::new(callback));
        info!("会话处理回调已设置");
    }

    /// 移除会话处理回调
    pub async fn clear_session_callback(&self) {
        let mut cb = self.session_callback.write().await;
        *cb = None;
        info!("会话处理回调已移除");
    }

    /// 处理 Client Random
    pub async fn process_client_random(
        &self,
        ssl_ptr: *mut std::ffi::c_void,
        client_random: &[u8],
    ) -> Result<()> {
        // 验证输入参数
        if ssl_ptr.is_null() {
            return Err(TlsKeyAgentError::TlsParse("SSL指针为空".to_string()));
        }

        if client_random.len() != 32 {
            return Err(TlsKeyAgentError::TlsParse(
                format!("Client Random 长度无效: {}, 期望长度: 32", client_random.len())
            ));
        }

        // 验证Client Random不为全零（常见错误情况）
        if client_random.iter().all(|&b| b == 0) {
            warn!("检测到全零的Client Random，SSL ID: {:?}", ssl_ptr);
        }

        let ssl_id = ssl_ptr as usize;
        debug!("处理 Client Random，SSL ID: {:x}, 长度: {}", ssl_id, client_random.len());

        // 记录Client Random的十六进制表示（调试用）
        let hex_str = client_random.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        trace!("Client Random 内容: {}", hex_str);

        // 创建或更新待处理会话
        {
            let mut sessions = self.active_sessions.write().await;

            // 检查是否已存在该会话
            if let Some(existing_session) = sessions.get_mut(&ssl_id) {
                if existing_session.client_random.is_some() {
                    warn!("收到重复的Client Random，SSL ID: {:x}", ssl_id);
                    // 更新时间戳，但保留原有数据
                    existing_session.created_at = std::time::SystemTime::now();
                } else {
                    debug!("为现有会话添加Client Random，SSL ID: {:x}", ssl_id);
                    existing_session.client_random = Some(client_random.to_vec());
                    existing_session.created_at = std::time::SystemTime::now();
                }
            } else {
                // 创建新的待处理会话
                let session = PendingSession {
                    ssl_ptr: ssl_id,
                    client_random: Some(client_random.to_vec()),
                    master_secret: None,
                    five_tuple: None,
                    process_info: None,
                    created_at: std::time::SystemTime::now(),
                };
                sessions.insert(ssl_id, session);
                debug!("创建新的待处理会话，SSL ID: {:x}", ssl_id);
            }
        }

        // 更新统计信息
        {
            let mut stats = self.stats.write().await;
            stats.total_client_randoms += 1;
        }

        // 尝试完成会话处理
        if let Err(e) = self.try_complete_session(ssl_ptr).await {
            debug!("会话尚未完成，SSL ID: {:x}, 错误: {}", ssl_id, e);
        }

        debug!("Client Random 处理完成，SSL ID: {:x}", ssl_id);
        Ok(())
    }

    /// 处理 Master Secret
    pub async fn process_master_secret(
        &self,
        ssl_ptr: *mut std::ffi::c_void,
        master_secret: &[u8],
    ) -> Result<()> {
        // 验证输入参数
        if ssl_ptr.is_null() {
            return Err(TlsKeyAgentError::TlsParse("SSL指针为空".to_string()));
        }

        if master_secret.len() != 48 {
            return Err(TlsKeyAgentError::TlsParse(
                format!("Master Secret 长度无效: {}, 期望长度: 48", master_secret.len())
            ));
        }

        // 验证Master Secret不为全零（常见错误情况）
        if master_secret.iter().all(|&b| b == 0) {
            warn!("检测到全零的Master Secret，SSL ID: {:?}", ssl_ptr);
        }

        let ssl_id = ssl_ptr as usize;
        debug!("处理 Master Secret，SSL ID: {:x}, 长度: {}", ssl_id, master_secret.len());

        // 记录Master Secret的十六进制表示（调试用，只显示前16字节）
        let hex_str = master_secret.iter()
            .take(16)
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        trace!("Master Secret 前16字节: {}...", hex_str);

        // 创建或更新待处理会话
        {
            let mut sessions = self.active_sessions.write().await;

            // 检查是否已存在该会话
            if let Some(existing_session) = sessions.get_mut(&ssl_id) {
                if existing_session.master_secret.is_some() {
                    warn!("收到重复的Master Secret，SSL ID: {:x}", ssl_id);
                    // 更新时间戳，但保留原有数据
                    existing_session.created_at = std::time::SystemTime::now();
                } else {
                    debug!("为现有会话添加Master Secret，SSL ID: {:x}", ssl_id);
                    existing_session.master_secret = Some(master_secret.to_vec());
                    existing_session.created_at = std::time::SystemTime::now();
                }
            } else {
                // 创建新的待处理会话
                let session = PendingSession {
                    ssl_ptr: ssl_id,
                    client_random: None,
                    master_secret: Some(master_secret.to_vec()),
                    five_tuple: None,
                    process_info: None,
                    created_at: std::time::SystemTime::now(),
                };
                sessions.insert(ssl_id, session);
                debug!("创建新的待处理会话（仅Master Secret），SSL ID: {:x}", ssl_id);
            }
        }

        // 更新统计信息
        {
            let mut stats = self.stats.write().await;
            stats.total_master_secrets += 1;
        }

        // 尝试完成会话处理
        if let Err(e) = self.try_complete_session(ssl_ptr).await {
            debug!("会话尚未完成，SSL ID: {:x}, 错误: {}", ssl_id, e);
        }

        debug!("Master Secret 处理完成，SSL ID: {:x}", ssl_id);
        Ok(())
    }

    /// 处理连接信息
    pub async fn process_connection_info(
        &self,
        ssl_ptr: *mut std::ffi::c_void,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        protocol: &str,
    ) -> Result<()> {
        let ssl_id = ssl_ptr as usize;
        debug!("处理连接信息，SSL ID: {}: {}:{} -> {}:{} ({})",
               ssl_id, src_ip, src_port, dst_ip, dst_port, protocol);

        // 解析 IP 地址
        let src_addr = IpAddr::from_str(src_ip)
            .map_err(|e| TlsKeyAgentError::Network(format!("源IP地址解析失败: {}", e)))?;
        let dst_addr = IpAddr::from_str(dst_ip)
            .map_err(|e| TlsKeyAgentError::Network(format!("目标IP地址解析失败: {}", e)))?;

        // 解析协议
        let protocol_enum = match protocol.to_uppercase().as_str() {
            "TCP" => Protocol::TCP,
            "UDP" => Protocol::UDP,
            _ => return Err(TlsKeyAgentError::Network(format!("不支持的协议: {}", protocol))),
        };

        let five_tuple = FiveTuple {
            src_ip: src_addr,
            src_port,
            dst_ip: dst_addr,
            dst_port,
            protocol: protocol_enum,
        };

        // 获取进程信息
        let process_info = self.get_current_process_info()?;

        // 创建或更新待处理会话
        {
            let mut sessions = self.active_sessions.write().await;
            let session = sessions.entry(ssl_id).or_insert_with(|| PendingSession {
                ssl_ptr: ssl_id,
                client_random: None,
                master_secret: None,
                five_tuple: None,
                process_info: None,
                created_at: std::time::SystemTime::now(),
            });

            session.five_tuple = Some(five_tuple.clone());
            session.process_info = Some(process_info.clone());
        }

        debug!("连接信息处理完成: {:?}", five_tuple);
        Ok(())
    }

    /// 尝试完成会话处理
    pub async fn try_complete_session(&self, ssl_ptr: *mut std::ffi::c_void) -> Result<Option<TlsSession>> {
        let ssl_id = ssl_ptr as usize;

        // 获取会话信息并处理
        {
            let mut sessions = self.active_sessions.write().await;

            if let Some(session) = sessions.get_mut(&ssl_id) {
                // 检查是否有足够的信息来创建完整的会话
                let has_client_random = session.client_random.is_some();
                let has_five_tuple = session.five_tuple.is_some();

                if has_client_random && has_five_tuple {
                    // 创建完整的会话
                    let client_random = session.client_random.clone().unwrap();
                    let master_secret = session.master_secret.clone(); // 可能为空
                    let five_tuple = session.five_tuple.clone().unwrap();
                    let process_info = session.process_info.clone().unwrap();

                    // 创建会话对象
                    let tls_session = TlsSession::new(
                        client_random,
                        master_secret.unwrap_or_default(),
                        five_tuple,
                        process_info,
                    );

                    // 检查过滤规则
                    if self.should_capture_session(&tls_session).await {
                        info!("会话通过过滤，SSL ID: {}", ssl_id);

                        // 更新统计信息
                        let mut stats = self.stats.write().await;
                        stats.processed_sessions += 1;

                        // 调用会话处理回调
                        let callback_result = {
                            let callback = self.session_callback.read().await;
                            if let Some(ref cb) = *callback {
                                Some(cb(tls_session.clone()))
                            } else {
                                None
                            }
                        };

                        match callback_result {
                            Some(Ok(())) => {
                                info!("会话处理回调执行成功");
                            }
                            Some(Err(e)) => {
                                error!("会话处理回调执行失败: {}", e);
                                let mut stats = self.stats.write().await;
                                stats.error_count += 1;
                            }
                            None => {
                                debug!("没有设置会话处理回调，跳过回调执行");
                            }
                        }

                        // 移除已处理的会话
                        sessions.remove(&ssl_id);

                        return Ok(Some(tls_session));
                    } else {
                        debug!("会话被过滤规则拒绝，SSL ID: {}", ssl_id);

                        // 更新统计信息
                        let mut stats = self.stats.write().await;
                        stats.filtered_sessions += 1;

                        // 移除已处理的会话
                        sessions.remove(&ssl_id);

                        return Ok(None);
                    }
                }

                // 检查会话是否超时（超过30秒）
                if session.created_at.elapsed().unwrap_or_default().as_secs() > 30 {
                    warn!("会话超时，移除 SSL ID: {}", ssl_id);
                    sessions.remove(&ssl_id);
                    return Ok(None);
                }
            }
        }

        Ok(None)
    }

    /// 检查是否应该捕获此会话
    async fn should_capture_session(&self, session: &TlsSession) -> bool {
        let rules = self.filter_rules.read().await;

        // 如果没有规则，默认捕获所有会话
        if rules.is_empty() {
            debug!("没有配置过滤规则，捕获所有TLS会话");
            return true;
        }

        // 检查是否有任何启用的规则匹配
        for rule in rules.iter().filter(|r| r.enabled) {
            if self.rule_matches_session(rule, session) {
                debug!("会话匹配规则 '{}'", rule.name);
                return true;
            }
        }

        trace!("会话不匹配任何过滤规则，跳过捕获");
        false
    }

    /// 检查规则是否匹配会话
    fn rule_matches_session(&self, rule: &FilterRule, session: &TlsSession) -> bool {
        // 检查五元组过滤
        if !self.five_tuple_matches(&rule.five_tuple, &session.five_tuple) {
            return false;
        }

        // 检查进程名过滤
        if let Some(ref process_name) = rule.process_name {
            if !session.process_info.process_name.contains(process_name) {
                return false;
            }
        }

        // 检查PID过滤
        if let Some(pid) = rule.pid {
            if session.process_info.pid != pid {
                return false;
            }
        }

        true
    }

    /// 检查五元组是否匹配
    fn five_tuple_matches(&self, filter: &crate::config::FiveTupleFilter, tuple: &FiveTuple) -> bool {
        // 检查源IP
        if let Some(ref src_ip_str) = filter.src_ip {
            match src_ip_str.parse::<IpAddr>() {
                Ok(src_ip) => {
                    if !src_ip.is_unspecified() && src_ip != tuple.src_ip {
                        return false;
                    }
                }
                Err(_) => {
                    debug!("无效的源IP地址格式: {}", src_ip_str);
                    return false;
                }
            }
        }

        // 检查源端口
        if let Some(src_port) = filter.src_port {
            if src_port != 0 && src_port != tuple.src_port {
                return false;
            }
        }

        // 检查目标IP
        if let Some(ref dst_ip_str) = filter.dst_ip {
            match dst_ip_str.parse::<IpAddr>() {
                Ok(dst_ip) => {
                    if !dst_ip.is_unspecified() && dst_ip != tuple.dst_ip {
                        return false;
                    }
                }
                Err(_) => {
                    debug!("无效的目标IP地址格式: {}", dst_ip_str);
                    return false;
                }
            }
        }

        // 检查目标端口
        if let Some(dst_port) = filter.dst_port {
            if dst_port != 0 && dst_port != tuple.dst_port {
                return false;
            }
        }

        // 检查协议
        if let Some(ref protocol) = filter.protocol {
            if std::mem::discriminant(protocol) != std::mem::discriminant(&tuple.protocol) {
                return false;
            }
        }

        true
    }

    /// 获取当前进程信息
    fn get_current_process_info(&self) -> Result<ProcessInfo> {
        let pid = std::process::id();
        let exe_path = std::env::current_exe()
            .unwrap_or_else(|_| "unknown".into())
            .to_string_lossy()
            .to_string();
        let process_name = exe_path
            .split('/')
            .last()
            .unwrap_or("unknown")
            .to_string();

        let command_line = std::env::args().collect::<Vec<_>>().join(" ");

        Ok(ProcessInfo {
            pid,
            process_name,
            command_line,
        })
    }

    /// 清理超时的会话
    pub async fn cleanup_expired_sessions(&self) -> usize {
        let mut sessions = self.active_sessions.write().await;
        let now = std::time::SystemTime::now();

        // 配置的超时时间（秒）
        const SESSION_TIMEOUT: u64 = 300; // 5分钟

        let _initial_count = sessions.len();

        // 查找超时的会话
        let expired_keys: Vec<usize> = sessions
            .iter()
            .filter(|(_, session)| {
                let age = now.duration_since(session.created_at).unwrap_or_default();
                let age_seconds = age.as_secs();

                if age_seconds > SESSION_TIMEOUT {
                    warn!("会话超时，SSL ID: {:x}, 年龄: {}秒", session.ssl_ptr, age_seconds);
                    true
                } else {
                    false
                }
            })
            .map(|(key, _)| *key)
            .collect();

        // 移除超时的会话
        let cleaned_count = expired_keys.len();
        for key in expired_keys {
            if let Some(session) = sessions.remove(&key) {
                debug!("清理超时会话，SSL ID: {:x}, 创建时间: {:?}",
                       session.ssl_ptr, session.created_at);

                // 记录会话状态
                let has_client_random = session.client_random.is_some();
                let has_master_secret = session.master_secret.is_some();
                let has_connection = session.five_tuple.is_some();

                trace!("超时会话状态 - Client Random: {}, Master Secret: {}, 连接信息: {}",
                      has_client_random, has_master_secret, has_connection);
            }
        }

        // 更新统计信息
        {
            let mut stats = self.stats.write().await;
            stats.expired_sessions += cleaned_count;
            stats.last_cleanup = Some(now);
        }

        if cleaned_count > 0 {
            info!("清理了{}个超时会话，剩余活跃会话: {}", cleaned_count, sessions.len());
        }

        cleaned_count
    }

    /// 启动定期清理任务
    pub async fn start_cleanup_task(&self) {
        info!("启动会话定期清理任务");

        let active_sessions = self.active_sessions.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(60) // 每分钟清理一次
            );

            loop {
                interval.tick().await;

                // 获取当前活跃会话数量
                let session_count = {
                    let sessions = active_sessions.read().await;
                    sessions.len()
                };

                // 如果没有活跃会话，跳过清理
                if session_count == 0 {
                    continue;
                }

                trace!("执行定期会话清理，当前活跃会话: {}", session_count);

                // 查找超时的会话
                let now = std::time::SystemTime::now();
                const SESSION_TIMEOUT: u64 = 300; // 5分钟

                let expired_count = {
                    let mut sessions = active_sessions.write().await;

                    let expired_keys: Vec<usize> = sessions
                        .iter()
                        .filter(|(_, session)| {
                            now.duration_since(session.created_at)
                                .unwrap_or_default()
                                .as_secs() > SESSION_TIMEOUT
                        })
                        .map(|(key, _)| *key)
                        .collect();

                    let expired_count = expired_keys.len();

                    for key in expired_keys {
                        sessions.remove(&key);
                    }

                    // 更新统计信息
                    {
                        let mut stats_guard = stats.write().await;
                        stats_guard.expired_sessions += expired_count;
                        stats_guard.last_cleanup = Some(now);
                    }

                    expired_count
                };

                if expired_count > 0 {
                    info!("定期清理完成，移除了{}个超时会话", expired_count);
                }
            }
        });
    }

    /// 获取会话年龄分布统计
    pub async fn get_session_age_distribution(&self) -> Vec<(String, usize)> {
        let sessions = self.active_sessions.read().await;
        let now = std::time::SystemTime::now();

        let mut distribution = vec![
            ("< 10s".to_string(), 0),
            ("10-60s".to_string(), 0),
            ("1-5m".to_string(), 0),
            ("5-10m".to_string(), 0),
            ("> 10m".to_string(), 0),
        ];

        for (_, session) in sessions.iter() {
            let age = now.duration_since(session.created_at).unwrap_or_default();
            let age_seconds = age.as_secs();

            let index = if age_seconds < 10 {
                0
            } else if age_seconds < 60 {
                1
            } else if age_seconds < 300 {
                2
            } else if age_seconds < 600 {
                3
            } else {
                4
            };

            distribution[index].1 += 1;
        }

        distribution
    }

    /// 获取统计信息
    pub async fn get_stats(&self) -> ProcessorStats {
        let mut stats = self.stats.read().await.clone();
        stats.active_sessions = self.active_sessions.read().await.len();
        stats
    }

    /// 获取活跃会话数量
    pub async fn get_active_sessions_count(&self) -> usize {
        self.active_sessions.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_processor_creation() {
        let processor = KeyProcessor::new(vec![]);
        assert_eq!(processor.get_active_sessions_count().await, 0);
    }

    #[tokio::test]
    async fn test_client_random_processing() {
        let processor = KeyProcessor::new(vec![]);
        let client_random = vec![0u8; 32];
        let ssl_ptr = 0x12345678 as *mut std::ffi::c_void;

        let result = processor.process_client_random(ssl_ptr, &client_random).await;
        assert!(result.is_ok());
        assert_eq!(processor.get_active_sessions_count().await, 1);

        let stats = processor.get_stats().await;
        assert_eq!(stats.total_client_randoms, 1);
    }

    #[tokio::test]
    async fn test_session_completion() {
        let processor = KeyProcessor::new(vec![]);
        let client_random = vec![0u8; 32];
        let master_secret = vec![0u8; 48];
        let ssl_ptr = 0x12345678 as *mut std::ffi::c_void;

        // 处理 Client Random
        processor.process_client_random(ssl_ptr, &client_random).await.unwrap();

        // 处理 Master Secret
        processor.process_master_secret(ssl_ptr, &master_secret).await.unwrap();

        // 处理连接信息
        processor.process_connection_info(
            ssl_ptr,
            "192.168.1.100",
            12345,
            "192.168.1.1",
            443,
            "TCP"
        ).await.unwrap();

        // 尝试完成会话
        let session = processor.try_complete_session(ssl_ptr).await.unwrap();
        assert!(session.is_some());

        let stats = processor.get_stats().await;
        assert_eq!(stats.processed_sessions, 1);
    }
}