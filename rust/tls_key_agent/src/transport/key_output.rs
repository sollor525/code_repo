/**
 * @file key_output.rs
 * @brief 统一的密钥输出格式管理
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-11-05
 */

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use anyhow::Result;
use tracing::{info};

use crate::common::error::TlsKeyAgentError;

/// 密钥类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    ClientRandom,
    MasterSecret,
    SessionTicket,
    PreMasterSecret,
}

/// 密钥信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsKeyInfo {
    /// 时间戳
    pub timestamp: DateTime<Utc>,
    /// 进程信息
    pub process_info: ProcessInfo,
    /// 密钥类型
    pub key_type: KeyType,
    /// Client Random (32字节)
    pub client_random: String,
    /// 密钥数据
    pub secret: String,
    /// TLS版本
    pub tls_version: Option<String>,
    /// 连接信息
    pub connection_info: Option<ConnectionInfo>,
    /// 额外信息
    pub metadata: HashMap<String, String>,
}

/// 进程信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub parent_pid: Option<u32>,
}

/// 连接信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
}

/// 密钥输出格式
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyOutputFormat {
    /// Wireshark兼容格式
    Wireshark,
    /// JSON格式
    Json,
    /// 纯文本格式
    Text,
    /// CSV格式
    Csv,
    /// TLSKeyLog格式
    TLSKeyLog,
}

/// 统一的密钥输出器
#[allow(dead_code)]
pub struct KeyOutputManager {
    format: KeyOutputFormat,
    output_path: Option<String>,
    enable_rotation: bool,
    max_file_size: u64,
    output_format: String,
}

impl KeyOutputManager {
    /// 创建新的密钥输出管理器
    pub fn new(
        format: KeyOutputFormat,
        output_path: Option<String>,
        enable_rotation: bool,
        max_file_size: u64,
    ) -> Self {
        Self {
            format: format.clone(),
            output_path,
            enable_rotation,
            max_file_size,
            output_format: Self::get_format_string(&format),
        }
    }

    /// 输出密钥信息
    pub fn output_key(&self, key_info: &TlsKeyInfo) -> Result<()> {
        let formatted_output = match self.format {
            KeyOutputFormat::Wireshark => self.format_wireshark(key_info),
            KeyOutputFormat::Json => self.format_json(key_info),
            KeyOutputFormat::Text => self.format_text(key_info),
            KeyOutputFormat::Csv => self.format_csv(key_info),
            KeyOutputFormat::TLSKeyLog => self.format_tls_keylog(key_info),
        };

        // 输出到文件或标准输出
        if let Some(path) = &self.output_path {
            self.output_to_file(path, &formatted_output)?;
        } else {
            println!("{}", formatted_output);
        }

        Ok(())
    }

    /// 批量输出密钥信息
    pub fn output_keys(&self, keys: &[TlsKeyInfo]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }

        match self.format {
            KeyOutputFormat::Csv => {
                // CSV格式需要输出表头
                let header = "timestamp,pid,name,cmdline,key_type,client_random,secret,tls_version,local_ip,local_port,remote_ip,remote_port,protocol";
                if let Some(path) = &self.output_path {
                    self.output_to_file(path, header)?;
                } else {
                    println!("{}", header);
                }
            }
            _ => {}
        }

        for key in keys {
            self.output_key(key)?;
        }

        info!("输出了 {} 个密钥记录", keys.len());
        Ok(())
    }

    /// 格式化为Wireshark兼容格式
    fn format_wireshark(&self, key_info: &TlsKeyInfo) -> String {
        match key_info.key_type {
            KeyType::ClientRandom => {
                format!("CLIENT_RANDOM {} {}", key_info.client_random, key_info.secret)
            }
            KeyType::MasterSecret => {
                format!("RSA Session-ID:{} Master-Key:{}", key_info.client_random, key_info.secret)
            }
            KeyType::SessionTicket => {
                format!("CLIENT_RANDOM {} {}", key_info.client_random, key_info.secret)
            }
            _ => {
                format!("CLIENT_RANDOM {} {}", key_info.client_random, key_info.secret)
            }
        }
    }

    /// 格式化为JSON
    fn format_json(&self, key_info: &TlsKeyInfo) -> String {
        serde_json::to_string_pretty(key_info)
            .unwrap_or_else(|_| "{\"error\":\"序列化失败\"}".to_string())
    }

    /// 格式化为纯文本
    fn format_text(&self, key_info: &TlsKeyInfo) -> String {
        format!(
            "[{}] TLS密钥记录\n\
            进程: {} (PID: {}) - {}\n\
            类型: {:?}\n\
            Client Random: {}\n\
            Secret: {}\n\
            TLS版本: {}\n\
            连接: {}",
            key_info.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            key_info.process_info.name,
            key_info.process_info.pid,
            key_info.process_info.cmdline,
            key_info.key_type,
            key_info.client_random,
            key_info.secret,
            key_info.tls_version.as_deref().unwrap_or("未知"),
            key_info.connection_info.as_ref()
                .map(|conn| format!("{}:{} -> {}:{}", conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port))
                .unwrap_or_else(|| "未知".to_string())
        )
    }

    /// 格式化为CSV
    fn format_csv(&self, key_info: &TlsKeyInfo) -> String {
        let conn_info = key_info.connection_info.as_ref();
        let (local_ip, local_port, remote_ip, remote_port, protocol) = if let Some(conn) = conn_info {
            (
                conn.local_ip.clone(),
                conn.local_port.to_string(),
                conn.remote_ip.clone(),
                conn.remote_port.to_string(),
                conn.protocol.clone(),
            )
        } else {
            (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            )
        };

        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{}",
            key_info.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
            key_info.process_info.pid,
            key_info.process_info.name,
            key_info.process_info.cmdline.replace(',', ";"),
            format!("{:?}", key_info.key_type),
            key_info.client_random,
            key_info.secret,
            key_info.tls_version.as_deref().unwrap_or(""),
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            protocol
        )
    }

    /// 格式化为TLS KeyLog格式
    fn format_tls_keylog(&self, key_info: &TlsKeyInfo) -> String {
        match key_info.key_type {
            KeyType::ClientRandom => {
                format!("CLIENT_RANDOM {} {}", key_info.client_random, key_info.secret)
            }
            KeyType::MasterSecret => {
                format!("RSA Session-ID:{} Master-Key:{}", key_info.client_random, key_info.secret)
            }
            KeyType::SessionTicket => {
                format!("CLIENT_RANDOM {} {}", key_info.client_random, key_info.secret)
            }
            _ => {
                format!("CLIENT_RANDOM {} {}", key_info.client_random, key_info.secret)
            }
        }
    }

    /// 输出到文件
    fn output_to_file(&self, path: &str, content: &str) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| TlsKeyAgentError::Transport(format!("打开输出文件失败: {}", e)))?;

        writeln!(file, "{}", content)
            .map_err(|e| TlsKeyAgentError::Transport(format!("写入文件失败: {}", e)))?;

        Ok(())
    }

    /// 获取格式字符串
    fn get_format_string(format: &KeyOutputFormat) -> String {
        match format {
            KeyOutputFormat::Wireshark => "wireshark".to_string(),
            KeyOutputFormat::Json => "json".to_string(),
            KeyOutputFormat::Text => "text".to_string(),
            KeyOutputFormat::Csv => "csv".to_string(),
            KeyOutputFormat::TLSKeyLog => "tls_keylog".to_string(),
        }
    }

    /// 从字符串解析格式
    pub fn format_from_string(format_str: &str) -> Option<KeyOutputFormat> {
        match format_str.to_lowercase().as_str() {
            "wireshark" => Some(KeyOutputFormat::Wireshark),
            "json" => Some(KeyOutputFormat::Json),
            "text" => Some(KeyOutputFormat::Text),
            "csv" => Some(KeyOutputFormat::Csv),
            "tls_keylog" | "tls-keylog" => Some(KeyOutputFormat::TLSKeyLog),
            _ => None,
        }
    }

    /// 获取支持的所有格式
    pub fn supported_formats() -> Vec<&'static str> {
        vec!["wireshark", "json", "text", "csv", "tls_keylog"]
    }

    /// 获取当前格式
    pub fn current_format(&self) -> &KeyOutputFormat {
        &self.format
    }

    /// 获取文件扩展名
    pub fn get_file_extension(&self) -> &'static str {
        match self.format {
            KeyOutputFormat::Wireshark => "log",
            KeyOutputFormat::Json => "json",
            KeyOutputFormat::Text => "txt",
            KeyOutputFormat::Csv => "csv",
            KeyOutputFormat::TLSKeyLog => "log",
        }
    }
}

impl Default for KeyOutputManager {
    fn default() -> Self {
        Self::new(
            KeyOutputFormat::TLSKeyLog,
            Some("./tls_keys.log".to_string()),
            true,
            100 * 1024 * 1024, // 100MB
        )
    }
}

/// 密钥信息构建器
pub struct TlsKeyInfoBuilder {
    key_info: TlsKeyInfo,
}

impl TlsKeyInfoBuilder {
    /// 创建新的构建器
    pub fn new(pid: u32, name: String, cmdline: String) -> Self {
        Self {
            key_info: TlsKeyInfo {
                timestamp: Utc::now(),
                process_info: ProcessInfo {
                    pid,
                    name,
                    cmdline,
                    parent_pid: None,
                },
                key_type: KeyType::ClientRandom,
                client_random: String::new(),
                secret: String::new(),
                tls_version: None,
                connection_info: None,
                metadata: HashMap::new(),
            },
        }
    }

    /// 设置密钥类型
    pub fn key_type(mut self, key_type: KeyType) -> Self {
        self.key_info.key_type = key_type;
        self
    }

    /// 设置Client Random
    pub fn client_random(mut self, client_random: String) -> Self {
        self.key_info.client_random = client_random;
        self
    }

    /// 设置密钥数据
    pub fn secret(mut self, secret: String) -> Self {
        self.key_info.secret = secret;
        self
    }

    /// 设置TLS版本
    pub fn tls_version(mut self, version: String) -> Self {
        self.key_info.tls_version = Some(version);
        self
    }

    /// 设置连接信息
    pub fn connection_info(mut self, conn_info: ConnectionInfo) -> Self {
        self.key_info.connection_info = Some(conn_info);
        self
    }

    /// 添加元数据
    pub fn metadata(mut self, key: String, value: String) -> Self {
        self.key_info.metadata.insert(key, value);
        self
    }

    /// 设置父进程ID
    pub fn parent_pid(mut self, parent_pid: u32) -> Self {
        self.key_info.process_info.parent_pid = Some(parent_pid);
        self
    }

    /// 构建密钥信息
    pub fn build(self) -> TlsKeyInfo {
        self.key_info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_output_formats() {
        let formats = KeyOutputManager::supported_formats();
        assert_eq!(formats.len(), 5);
        assert!(formats.contains(&"wireshark"));
        assert!(formats.contains(&"json"));
        assert!(formats.contains(&"tls_keylog"));
    }

    #[test]
    fn test_format_parsing() {
        assert_eq!(
            KeyOutputManager::format_from_string("json"),
            Some(KeyOutputFormat::Json)
        );
        assert_eq!(
            KeyOutputManager::format_from_string("TLS-KEYLOG"),
            Some(KeyOutputFormat::TLSKeyLog)
        );
        assert_eq!(
            KeyOutputManager::format_from_string("invalid"),
            None
        );
    }

    #[test]
    fn test_wireshark_format() {
        let manager = KeyOutputManager::new(
            KeyOutputFormat::Wireshark,
            None,
            false,
            0
        );

        let key_info = TlsKeyInfoBuilder::new(
            1234,
            "nginx".to_string(),
            "nginx: master process".to_string()
        )
        .key_type(KeyType::ClientRandom)
        .client_random("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string())
        .secret("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string())
        .build();

        let formatted = manager.format_wireshark(&key_info);
        assert!(formatted.starts_with("CLIENT_RANDOM"));
        assert!(formatted.contains(&key_info.client_random));
        assert!(formatted.contains(&key_info.secret));
    }

    #[test]
    fn test_json_format() {
        let manager = KeyOutputManager::new(
            KeyOutputFormat::Json,
            None,
            false,
            0
        );

        let key_info = TlsKeyInfoBuilder::new(
            1234,
            "nginx".to_string(),
            "nginx: master process".to_string()
        )
        .key_type(KeyType::MasterSecret)
        .build();

        let formatted = manager.format_json(&key_info);
        assert!(formatted.contains("\"key_type\":\"MasterSecret\""));
        assert!(formatted.contains("\"pid\":1234"));
    }

    #[test]
    fn test_tls_key_info_builder() {
        let key_info = TlsKeyInfoBuilder::new(
            1234,
            "nginx".to_string(),
            "nginx: worker".to_string()
        )
        .key_type(KeyType::SessionTicket)
        .client_random("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string())
        .secret("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string())
        .tls_version("TLSv1.3".to_string())
        .metadata("test_key".to_string(), "test_value".to_string())
        .build();

        assert_eq!(key_info.process_info.pid, 1234);
        assert_eq!(key_info.process_info.name, "nginx");
        assert_eq!(key_info.key_type, KeyType::SessionTicket);
        assert_eq!(key_info.tls_version, Some("TLSv1.3".to_string()));
        assert_eq!(key_info.metadata.get("test_key"), Some(&"test_value".to_string()));
    }
}