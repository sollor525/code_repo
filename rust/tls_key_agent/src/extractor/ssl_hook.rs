use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{info, error, debug, trace, warn};
use crate::common::error::{TlsKeyAgentError, Result};
use crate::common::session::{TlsSession, FiveTuple, ProcessInfo};
use crate::config::Config;
use crate::extractor::session_manager::SessionManager;

#[derive(Debug)]
pub struct SslHook {
    #[allow(dead_code)]
    config: Arc<Config>,
    session_manager: Arc<SessionManager>,
    is_active: Arc<RwLock<bool>>,
    ssl_sessions: Arc<RwLock<HashMap<usize, SslSessionInfo>>>,
}

#[derive(Debug, Clone)]
struct SslSessionInfo {
    #[allow(dead_code)]
    ssl_ptr: usize,
    client_random: Option<Vec<u8>>,
    master_secret: Option<Vec<u8>>,
    five_tuple: Option<FiveTuple>,
    created_at: std::time::Instant,
}

impl SslHook {
    pub fn new(config: Arc<Config>, session_manager: Arc<SessionManager>) -> Result<Self> {
        info!("初始化SSL Hook");

        Ok(Self {
            config,
            session_manager,
            is_active: Arc::new(RwLock::new(false)),
            ssl_sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn start(&self) -> Result<()> {
        info!("启动SSL Hook");

        let mut is_active = self.is_active.write().await;
        if *is_active {
            return Err(TlsKeyAgentError::Config("SSL Hook已在运行".to_string()));
        }

        // 安装OpenSSL Hook
        self.install_openssl_hooks().await?;

        *is_active = true;
        info!("SSL Hook启动成功");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("停止SSL Hook");

        let mut is_active = self.is_active.write().await;
        if !*is_active {
            return Ok(());
        }

        // 卸载OpenSSL Hook
        self.uninstall_openssl_hooks().await?;

        // 清理会话缓存
        let mut sessions = self.ssl_sessions.write().await;
        sessions.clear();

        *is_active = false;
        info!("SSL Hook已停止");
        Ok(())
    }

    pub async fn is_active(&self) -> bool {
        *self.is_active.read().await
    }

    async fn install_openssl_hooks(&self) -> Result<()> {
        debug!("安装OpenSSL Hook");

        // 使用默认配置路径，实际应用中可以从Config获取
        let config_path = std::ffi::CString::new("config.toml")
            .map_err(|e| TlsKeyAgentError::Config(format!("配置路径转换失败: {}", e)))?;

        let result = unsafe {
            crate::ffi::init_tls_key_agent_hook(config_path.as_ptr())
        };

        // C函数返回int，需要转换为FfiResult
        match result {
            0 => {
                info!("OpenSSL Hook安装成功");
                Ok(())
            }
            1 => {
                info!("OpenSSL Hook已安装");
                Ok(())
            }
            _ => {
                error!("OpenSSL Hook安装失败，错误码: {}", result);
                Err(TlsKeyAgentError::Extraction("Hook安装失败".to_string()))
            }
        }
    }

    async fn uninstall_openssl_hooks(&self) -> Result<()> {
        debug!("卸载OpenSSL Hook");

        // 调用C函数来清理Hook
        let result = unsafe {
            crate::ffi::cleanup_tls_key_agent_hook()
        };

        match result {
            0 => {
                info!("OpenSSL Hook卸载成功");
                Ok(())
            }
            _ => {
                warn!("OpenSSL Hook卸载失败，错误码: {}", result);
                // 卸载失败不应该阻止整个停止过程，只记录警告
                Ok(())
            }
        }
    }

    // 处理Client Random
    pub async fn handle_client_random(
        &self,
        ssl_ptr: usize,
        client_random: Vec<u8>,
    ) -> Result<()> {
        if !self.is_active().await {
            trace!("SSL Hook未激活，忽略Client Random");
            return Ok(());
        }

        debug!("收到Client Random，长度: {}", client_random.len());

        if client_random.len() != 32 {
            return Err(TlsKeyAgentError::TlsParse(
                format!("Client Random长度无效: {}", client_random.len())
            ));
        }

        let mut sessions = self.ssl_sessions.write().await;
        let session = sessions.entry(ssl_ptr).or_insert_with(|| SslSessionInfo {
            ssl_ptr,
            client_random: None,
            master_secret: None,
            five_tuple: None,
            created_at: std::time::Instant::now(),
        });

        session.client_random = Some(client_random);

        // 尝试构建完整的会话信息
        if let Some(complete_session) = self.try_build_complete_session(session).await {
            self.session_manager.handle_session(complete_session).await?;
        }

        Ok(())
    }

    // 处理Master Secret
    pub async fn handle_master_secret(
        &self,
        ssl_ptr: usize,
        master_secret: Vec<u8>,
    ) -> Result<()> {
        if !self.is_active().await {
            trace!("SSL Hook未激活，忽略Master Secret");
            return Ok(());
        }

        debug!("收到Master Secret，长度: {}", master_secret.len());

        if master_secret.len() != 48 {
            return Err(TlsKeyAgentError::TlsParse(
                format!("Master Secret长度无效: {}", master_secret.len())
            ));
        }

        let mut sessions = self.ssl_sessions.write().await;
        let session = sessions.entry(ssl_ptr).or_insert_with(|| SslSessionInfo {
            ssl_ptr,
            client_random: None,
            master_secret: None,
            five_tuple: None,
            created_at: std::time::Instant::now(),
        });

        session.master_secret = Some(master_secret);

        // 尝试构建完整的会话信息
        if let Some(complete_session) = self.try_build_complete_session(session).await {
            self.session_manager.handle_session(complete_session).await?;
        }

        Ok(())
    }

    // 处理连接信息（五元组）
    pub async fn handle_connection_info(
        &self,
        ssl_ptr: usize,
        five_tuple: FiveTuple,
    ) -> Result<()> {
        if !self.is_active().await {
            trace!("SSL Hook未激活，忽略连接信息");
            return Ok(());
        }

        debug!("收到连接信息: {:?}", five_tuple);

        let mut sessions = self.ssl_sessions.write().await;
        let session = sessions.entry(ssl_ptr).or_insert_with(|| SslSessionInfo {
            ssl_ptr,
            client_random: None,
            master_secret: None,
            five_tuple: None,
            created_at: std::time::Instant::now(),
        });

        session.five_tuple = Some(five_tuple);

        // 尝试构建完整的会话信息
        if let Some(complete_session) = self.try_build_complete_session(session).await {
            self.session_manager.handle_session(complete_session).await?;
        }

        Ok(())
    }

    // 尝试构建完整的会话信息
    async fn try_build_complete_session(&self, session: &SslSessionInfo) -> Option<TlsSession> {
        // 检查是否所有必需的信息都已收集
        let client_random = session.client_random.as_ref()?;
        let master_secret = session.master_secret.as_ref()?;
        let five_tuple = session.five_tuple.as_ref()?;

        // 获取进程信息
        let (pid, process_name, command_line) = crate::common::utils::get_process_info();
        let process_info = ProcessInfo {
            pid,
            process_name,
            command_line,
        };

        // 创建完整的会话
        Some(TlsSession::new(
            client_random.clone(),
            master_secret.clone(),
            five_tuple.clone(),
            process_info,
        ))
    }

    // 清理过期的会话
    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.ssl_sessions.write().await;
        let now = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(300); // 5分钟超时

        let initial_count = sessions.len();
        sessions.retain(|_, session| now.duration_since(session.created_at) < timeout);
        let final_count = sessions.len();

        if initial_count != final_count {
            debug!("清理了{}个过期会话", initial_count - final_count);
        }
    }

    pub async fn get_stats(&self) -> SslHookStats {
        let sessions = self.ssl_sessions.read().await;
        let incomplete_sessions = sessions.len();
        let sessions_with_client_random = sessions.values()
            .filter(|s| s.client_random.is_some())
            .count();
        let sessions_with_master_secret = sessions.values()
            .filter(|s| s.master_secret.is_some())
            .count();
        let sessions_with_connection = sessions.values()
            .filter(|s| s.five_tuple.is_some())
            .count();

        SslHookStats {
            is_active: self.is_active().await,
            incomplete_sessions,
            sessions_with_client_random,
            sessions_with_master_secret,
            sessions_with_connection,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SslHookStats {
    pub is_active: bool,
    pub incomplete_sessions: usize,
    pub sessions_with_client_random: usize,
    pub sessions_with_master_secret: usize,
    pub sessions_with_connection: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::common::session::Protocol;

    fn create_test_five_tuple() -> FiveTuple {
        FiveTuple {
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            src_port: 12345,
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_port: 443,
            protocol: Protocol::TCP,
        }
    }

    #[tokio::test]
    async fn test_ssl_hook_creation() {
        let config = Arc::new(Config::default());
        let session_manager = Arc::new(SessionManager::new(vec![], Arc::new(
            crate::common::buffer::BufferPool::new(8192, 1000)
        )).unwrap());

        let ssl_hook = SslHook::new(config, session_manager);
        assert!(ssl_hook.is_ok());
    }

    #[tokio::test]
    async fn test_client_random_handling() {
        let config = Arc::new(Config::default());
        let session_manager = Arc::new(SessionManager::new(vec![], Arc::new(
            crate::common::buffer::BufferPool::new(8192, 1000)
        )).unwrap());

        let ssl_hook = SslHook::new(config, session_manager).unwrap();

        let client_random = vec![0u8; 32];
        let ssl_ptr = 0x12345678usize;

        // 测试Client Random处理
        let result = ssl_hook.handle_client_random(ssl_ptr, client_random).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_invalid_client_random() {
        let config = Arc::new(Config::default());
        let session_manager = Arc::new(SessionManager::new(vec![], Arc::new(
            crate::common::buffer::BufferPool::new(8192, 1000)
        )).unwrap());

        let ssl_hook = SslHook::new(config, session_manager).unwrap();

        let invalid_client_random = vec![0u8; 16]; // 错误的长度
        let ssl_ptr = 0x12345678usize;

        let result = ssl_hook.handle_client_random(ssl_ptr, invalid_client_random).await;
        assert!(result.is_err());
    }
}