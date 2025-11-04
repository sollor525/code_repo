use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use tokio::sync::RwLock;
use tokio::fs;
use tokio::time::{interval, Duration};
use tracing::{info, error, debug, warn};
use parking_lot::Mutex;

use crate::common::error::{TlsKeyAgentError, Result};
use crate::transport::{Transport, TransportMessage, TransportStats, TransportType};
use crate::config::FileTransportConfig;

#[derive(Debug)]
pub struct FileTransport {
    config: FileTransportConfig,
    current_file: Arc<RwLock<Option<BufWriter<File>>>>,
    current_file_path: Arc<RwLock<Option<PathBuf>>>,
    current_file_size: Arc<RwLock<u64>>,
    stats: Arc<RwLock<FileTransportStats>>,
    rotation_counter: Arc<Mutex<usize>>,
}

#[derive(Debug, Clone)]
struct FileTransportStats {
    messages_written: u64,
    messages_failed: u64,
    bytes_written: u64,
    files_rotated: u64,
    last_write: Option<std::time::SystemTime>,
}

impl FileTransport {
    pub fn new(config: &FileTransportConfig) -> Result<Self> {
        info!("初始化文件传输器: {}", config.output_path);

        Ok(Self {
            config: config.clone(),
            current_file: Arc::new(RwLock::new(None)),
            current_file_path: Arc::new(RwLock::new(None)),
            current_file_size: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(FileTransportStats {
                messages_written: 0,
                messages_failed: 0,
                bytes_written: 0,
                files_rotated: 0,
                last_write: None,
            })),
            rotation_counter: Arc::new(Mutex::new(0)),
        })
    }

    async fn ensure_file_open(&self) -> Result<()> {
        // 检查是否需要轮转文件
        if self.should_rotate_file().await {
            self.rotate_file().await?;
        }

        // 如果当前没有打开的文件，创建新文件
        if self.current_file.read().await.is_none() {
            self.create_new_file().await?;
        }

        Ok(())
    }

    async fn should_rotate_file(&self) -> bool {
        if !self.config.rotation {
            return false;
        }

        let current_size = *self.current_file_size.read().await;
        current_size >= self.config.max_file_size
    }

    async fn create_new_file(&self) -> Result<()> {
        let file_path = self.generate_file_path().await?;

        info!("创建新文件: {}", file_path.display());

        // 确保目录存在
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await
                .map_err(|e| TlsKeyAgentError::Transport(
                    format!("创建目录失败: {}", e)
                ))?;
        }

        // 创建文件
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .map_err(|e| TlsKeyAgentError::Transport(
                format!("创建文件失败: {}", e)
            ))?;

        let writer = BufWriter::new(file);

        // 更新状态
        {
            let mut current_file = self.current_file.write().await;
            *current_file = Some(writer);
        }

        {
            let mut current_path = self.current_file_path.write().await;
            *current_path = Some(file_path.clone());
        }

        {
            let mut current_size = self.current_file_size.write().await;
            *current_size = 0;
        }

        // 写入文件头
        self.write_file_header(&file_path).await?;

        debug!("新文件创建成功: {}", file_path.display());
        Ok(())
    }

    async fn generate_file_path(&self) -> Result<PathBuf> {
        let base_path = Path::new(&self.config.output_path);

        if !self.config.rotation {
            return Ok(base_path.to_path_buf());
        }

        // 生成带时间戳的文件名
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut counter = self.rotation_counter.lock();
        let file_name = format!(
            "{}_{}.log",
            base_path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("tls_keys"),
            now
        );

        let mut new_path = base_path.with_file_name(file_name);

        // 如果文件已存在，添加序号
        while new_path.exists() {
            *counter += 1;
            let file_name = format!(
                "{}_{}_{}.log",
                base_path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("tls_keys"),
                now,
                *counter
            );
            new_path = base_path.with_file_name(file_name);
        }

        Ok(new_path)
    }

    async fn write_file_header(&self, _file_path: &Path) -> Result<()> {
        let header = format!(
            "# TLS Key Agent Log File\n# Created: {}\n# PID: {}\n\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            std::process::id()
        );

        // 直接写入文件，避免递归调用
        let mut current_file = self.current_file.write().await;
        if let Some(ref mut writer) = *current_file {
            writer.write_all(header.as_bytes())
                .map_err(|e| TlsKeyAgentError::Transport(
                    format!("写入文件头失败: {}", e)
                ))?;

            // 更新文件大小和统计
            {
                let mut current_size = self.current_file_size.write().await;
                *current_size += header.len() as u64;
            }

            {
                let mut stats = self.stats.write().await;
                stats.bytes_written += header.len() as u64;
            }

            debug!("文件头写入成功，大小: {} 字节", header.len());
            Ok(())
        } else {
            Err(TlsKeyAgentError::Transport("文件未打开，无法写入文件头".to_string()))
        }
    }

    async fn rotate_file(&self) -> Result<()> {
        info!("开始文件轮转");

        // 关闭当前文件
        {
            let mut current_file = self.current_file.write().await;
            if let Some(mut writer) = current_file.take() {
                if let Err(e) = writer.flush() {
                    warn!("刷新文件缓冲失败: {}", e);
                }
            }
        }

        // 更新统计
        {
            let mut stats = self.stats.write().await;
            stats.files_rotated += 1;
        }

        // 清理旧文件
        self.cleanup_old_files().await?;

        info!("文件轮转完成");
        Ok(())
    }

    async fn cleanup_old_files(&self) -> Result<()> {
        if !self.config.rotation || self.config.max_files == 0 {
            return Ok(());
        }

        let base_path = Path::new(&self.config.output_path);
        let parent_dir = base_path.parent().unwrap_or(Path::new("."));

        debug!("清理旧文件，目录: {}", parent_dir.display());

        let mut entries = fs::read_dir(parent_dir).await
            .map_err(|e| TlsKeyAgentError::Transport(
                format!("读取目录失败: {}", e)
            ))?;

        let mut files = Vec::new();
        let base_prefix = base_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("tls_keys");

        while let Some(entry) = entries.next_entry().await
            .map_err(|e| TlsKeyAgentError::Transport(
                format!("读取目录条目失败: {}", e)
            ))? {

            let path = entry.path();
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.starts_with(base_prefix) && file_name.ends_with(".log") {
                    if let Ok(metadata) = entry.metadata().await {
                        if let Ok(modified) = metadata.modified() {
                            files.push((path, modified));
                        }
                    }
                }
            }
        }

        // 按修改时间排序（最旧的在前）
        files.sort_by_key(|(_, modified)| *modified);

        // 删除多余的文件
        let files_to_remove = files.len().saturating_sub(self.config.max_files);
        for (path, _) in files.into_iter().take(files_to_remove) {
            debug!("删除旧文件: {}", path.display());
            if let Err(e) = fs::remove_file(&path).await {
                warn!("删除文件失败 {}: {}", path.display(), e);
            }
        }

        Ok(())
    }

    async fn write_to_file(&self, data: &[u8]) -> Result<()> {
        // 检查是否需要轮转文件（在写入前检查）
        if self.should_rotate_file().await {
            debug!("检测到需要文件轮转");
            self.rotate_file().await?;

            // 轮转后创建新文件
            self.create_new_file().await?;
        }

        let mut current_file = self.current_file.write().await;
        if let Some(ref mut writer) = *current_file {
            writer.write_all(data)
                .map_err(|e| TlsKeyAgentError::Transport(
                    format!("写入文件失败: {}", e)
                ))?;

            // 更新统计和文件大小
            {
                let mut current_size = self.current_file_size.write().await;
                *current_size += data.len() as u64;
            }

            {
                let mut stats = self.stats.write().await;
                stats.messages_written += 1;
                stats.bytes_written += data.len() as u64;
                stats.last_write = Some(std::time::SystemTime::now());
            }

            debug!("写入文件成功，大小: {} 字节", data.len());
            Ok(())
        } else {
            Err(TlsKeyAgentError::Transport("文件未打开".to_string()))
        }
    }

    async fn flush_file(&self) -> Result<()> {
        let mut current_file = self.current_file.write().await;
        if let Some(ref mut writer) = *current_file {
            writer.flush()
                .map_err(|e| TlsKeyAgentError::Transport(
                    format!("刷新文件缓冲失败: {}", e)
                ))?;
            debug!("文件缓冲刷新成功");
        }
        Ok(())
    }

    /// 重新创建文件（在写入失败时使用）
    async fn recreate_file(&self) -> Result<()> {
        info!("重新创建文件");

        // 关闭当前文件
        {
            let mut current_file = self.current_file.write().await;
            if let Some(mut writer) = current_file.take() {
                if let Err(e) = writer.flush() {
                    warn!("关闭旧文件时刷新失败: {}", e);
                }
            }
        }

        // 重置文件大小
        {
            let mut current_size = self.current_file_size.write().await;
            *current_size = 0;
        }

        // 清空文件路径
        {
            let mut current_path = self.current_file_path.write().await;
            *current_path = None;
        }

        // 创建新文件
        self.create_new_file().await
    }
}

#[async_trait::async_trait]
impl Transport for FileTransport {
    async fn start(&self) -> Result<()> {
        info!("启动文件传输器");

        // 确保初始文件已创建
        self.ensure_file_open().await?;

        // 启动定期刷新任务
        let current_file = self.current_file.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5)); // 5秒刷新一次

            loop {
                interval.tick().await;

                let mut file = current_file.write().await;
                if let Some(ref mut writer) = *file {
                    if let Err(e) = writer.flush() {
                        error!("定期刷新文件失败: {}", e);
                    }
                }
            }
        });

        info!("文件传输器启动成功");
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        info!("停止文件传输器");

        // 刷新并关闭当前文件
        {
            let mut current_file = self.current_file.write().await;
            if let Some(mut writer) = current_file.take() {
                if let Err(e) = writer.flush() {
                    warn!("停止时刷新文件失败: {}", e);
                }
            }
        }

        info!("文件传输器已停止");
        Ok(())
    }

    async fn send_message(&self, message: &TransportMessage) -> Result<()> {
        // 确保文件已打开
        if let Err(e) = self.ensure_file_open().await {
            error!("确保文件打开失败: {}", e);

            // 更新失败统计
            {
                let mut stats = self.stats.write().await;
                stats.messages_failed += 1;
            }

            return Err(e);
        }

        // 格式化消息
        let formatted_message = self.format_message(message).await;

        // 写入文件，带有重试机制
        let mut retry_count = 0;
        let max_retries = 3;

        loop {
            match self.write_to_file(formatted_message.as_bytes()).await {
                Ok(()) => {
                    // 写入成功，立即刷新重要消息
                    if matches!(message.message_type, crate::transport::MessageType::TlsKey) {
                        if let Err(e) = self.flush_file().await {
                            warn!("刷新TLS密钥消息失败: {}", e);
                            // 刷新失败不影响整体成功，但记录警告
                        }
                    }
                    break Ok(());
                }
                Err(e) => {
                    retry_count += 1;
                    warn!("写入文件失败 (尝试 {}/{}): {}", retry_count, max_retries, e);

                    if retry_count >= max_retries {
                        error!("写入文件失败，已达到最大重试次数");

                        // 更新失败统计
                        {
                            let mut stats = self.stats.write().await;
                            stats.messages_failed += 1;
                        }

                        // 尝试重新创建文件
                        info!("尝试重新创建文件");
                        self.recreate_file().await?;

                        return Err(e);
                    }

                    // 等待一段时间后重试
                    tokio::time::sleep(Duration::from_millis(100 * retry_count as u64)).await;
                }
            }
        }
    }

    async fn is_connected(&self) -> bool {
        self.current_file.read().await.is_some()
    }

    fn get_transport_type(&self) -> TransportType {
        TransportType::File
    }

    async fn get_stats(&self) -> TransportStats {
        let stats = self.stats.read().await;
        TransportStats {
            transport_type: TransportType::File,
            is_connected: self.is_connected().await,
            messages_sent: stats.messages_written,
            messages_failed: stats.messages_failed,
            bytes_sent: stats.bytes_written,
            last_activity: stats.last_write,
        }
    }
}

impl FileTransport {
    async fn format_message(&self, message: &TransportMessage) -> String {
        match message.message_type {
            crate::transport::MessageType::TlsKey => {
                format!(
                    "[{}] TLS_KEY | {} | {}:{} -> {}:{} | Process: {} (PID: {}) | ClientRandom: {} | MasterSecret: {}\n",
                    chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::from(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(message.timestamp)
                    )).format("%Y-%m-%d %H:%M:%S UTC"),
                    message.session.session_id,
                    message.session.five_tuple.src_ip,
                    message.session.five_tuple.src_port,
                    message.session.five_tuple.dst_ip,
                    message.session.five_tuple.dst_port,
                    message.session.process_info.process_name,
                    message.session.process_info.pid,
                    hex::encode(&message.session.client_random),
                    hex::encode(&message.session.master_secret)
                )
            }
            crate::transport::MessageType::Heartbeat => {
                format!(
                    "[{}] HEARTBEAT | Agent is running\n",
                    chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::from(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(message.timestamp)
                    )).format("%Y-%m-%d %H:%M:%S UTC")
                )
            }
            crate::transport::MessageType::ConfigUpdate => {
                format!(
                    "[{}] CONFIG_UPDATE | Configuration updated\n",
                    chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::from(
                        std::time::UNIX_EPOCH + std::time::Duration::from_secs(message.timestamp)
                    )).format("%Y-%m-%d %H:%M:%S UTC")
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_transport_creation() {
        let config = FileTransportConfig::default();
        let transport = FileTransport::new(&config);
        assert!(transport.is_ok());
    }

    #[tokio::test]
    async fn test_file_path_generation() {
        let config = FileTransportConfig {
            enabled: true,
            output_path: "/tmp/test_tls_keys.log".to_string(),
            rotation: true,
            max_file_size: 1024,
            max_files: 5,
        };

        let transport = FileTransport::new(&config).unwrap();
        let path1 = transport.generate_file_path().await.unwrap();
        let path2 = transport.generate_file_path().await.unwrap();

        // 路径应该不同（因为时间戳不同）
        assert_ne!(path1, path2);
    }
}