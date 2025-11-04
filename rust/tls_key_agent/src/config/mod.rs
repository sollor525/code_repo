use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use crate::common::error::{TlsKeyAgentError, Result};
use crate::common::session::Protocol;

pub mod remote_config;
pub mod filter;
pub mod builder;

pub use remote_config::*;
pub use filter::*;
pub use builder::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub extraction: ExtractionConfig,
    pub transport: TransportConfig,
    pub filters: Vec<FilterRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub name: String,
    pub version: String,
    pub log_level: String,
    pub buffer_pool_size: usize,
    pub buffer_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionConfig {
    pub enabled: bool,
    pub capture_client_random: bool,
    pub capture_master_secret: bool,
    pub capture_session_ticket: bool,
    pub library_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub enabled_transports: Vec<TransportType>,
    pub tcp: TcpTransportConfig,
    pub file: FileTransportConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TransportType {
    Tcp,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTransportConfig {
    pub enabled: bool,
    pub server_host: String,
    pub server_port: u16,
    pub reconnect_interval: u64,
    pub max_retries: u32,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransportConfig {
    pub enabled: bool,
    pub output_path: String,
    pub rotation: bool,
    pub max_file_size: u64,
    pub max_files: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub name: String,
    pub enabled: bool,
    pub five_tuple: FiveTupleFilter,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiveTupleFilter {
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<Protocol>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: AgentConfig::default(),
            extraction: ExtractionConfig::default(),
            transport: TransportConfig::default(),
            filters: vec![
                // 默认HTTP/HTTPS流量规则
                FilterRule {
                    name: "default_http_https".to_string(),
                    enabled: true,
                    five_tuple: FiveTupleFilter {
                        src_ip: None,
                        src_port: None,
                        dst_ip: None,
                        dst_port: Some(80), // HTTP
                        protocol: Some(Protocol::TCP),
                    },
                    process_name: None,
                    pid: None,
                },
                FilterRule {
                    name: "default_https".to_string(),
                    enabled: true,
                    five_tuple: FiveTupleFilter {
                        src_ip: None,
                        src_port: None,
                        dst_ip: None,
                        dst_port: Some(443), // HTTPS
                        protocol: Some(Protocol::TCP),
                    },
                    process_name: None,
                    pid: None,
                },
                // 常见Web服务器进程
                FilterRule {
                    name: "web_servers".to_string(),
                    enabled: true,
                    five_tuple: FiveTupleFilter {
                        src_ip: None,
                        src_port: None,
                        dst_ip: None,
                        dst_port: None,
                        protocol: None,
                    },
                    process_name: Some("nginx|apache|httpd|lighttpd|caddy".to_string()),
                    pid: None,
                },
            ],
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            name: "tls_key_agent".to_string(),
            version: "0.1.0".to_string(),
            log_level: "info".to_string(),
            buffer_pool_size: 1000,
            buffer_size: 8192,
        }
    }
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            capture_client_random: true,
            capture_master_secret: true,
            capture_session_ticket: false,
            library_path: "./libtls_key_agent.so".to_string(),
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            enabled_transports: vec![TransportType::Tcp, TransportType::File],
            tcp: TcpTransportConfig::default(),
            file: FileTransportConfig::default(),
        }
    }
}

impl Default for TcpTransportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            server_port: 9999,
            reconnect_interval: 5,
            max_retries: 10,
            timeout: 10,
        }
    }
}

impl Default for FileTransportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            output_path: "./tls_keys.log".to_string(),
            rotation: true,
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_files: 10,
        }
    }
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| TlsKeyAgentError::Config(format!("读取配置文件失败: {}", e)))?;

        toml::from_str(&content)
            .map_err(|e| TlsKeyAgentError::Config(format!("解析配置文件失败: {}", e)))
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| TlsKeyAgentError::Config(format!("序列化配置失败: {}", e)))?;

        fs::write(path, content)
            .map_err(|e| TlsKeyAgentError::Config(format!("写入配置文件失败: {}", e)))?;

        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        // 验证基本配置
        if self.agent.buffer_pool_size == 0 {
            return Err(TlsKeyAgentError::Config("buffer_pool_size必须大于0".to_string()));
        }

        if self.agent.buffer_size == 0 {
            return Err(TlsKeyAgentError::Config("buffer_size必须大于0".to_string()));
        }

        // 验证传输配置
        if self.transport.enabled_transports.is_empty() {
            return Err(TlsKeyAgentError::Config("至少需要启用一种传输方式".to_string()));
        }

        // 验证TCP配置
        if self.transport.enabled_transports.contains(&TransportType::Tcp)
            && self.transport.tcp.server_port == 0 {
                return Err(TlsKeyAgentError::Config("TCP服务器端口必须大于0".to_string()));
            }

        // 验证文件配置
        if self.transport.enabled_transports.contains(&TransportType::File)
            && self.transport.file.output_path.is_empty() {
                return Err(TlsKeyAgentError::Config("文件输出路径不能为空".to_string()));
            }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.agent.name, parsed.agent.name);
    }
}