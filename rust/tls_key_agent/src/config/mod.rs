use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use crate::common::error::{TlsKeyAgentError, Result};
use crate::common::session::Protocol;

pub mod remote_config;
pub mod filter;
pub mod builder;
pub mod dynamic_config_manager;

pub use remote_config::*;
pub use filter::*;
pub use builder::*;
pub use dynamic_config_manager::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub agent: AgentConfig,
    pub extraction: ExtractionConfig,
    pub transport: TransportConfig,
    pub filters: Vec<FilterRule>,
    pub ebpf_ssl_hook: EbpfSslHookConfig,
    pub injection: InjectionConfig,
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
    pub kernel_version_requirement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub enabled_transports: Vec<TransportType>,
    pub udp: UdpTransportConfig,
    pub tcp: TcpTransportConfig, // 为了兼容性保留TCP配置
    pub remote_config: RemoteConfigConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TransportType {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpTransportConfig {
    pub enabled: bool,
    pub server_host: String,
    pub server_port: u16,
    pub batch_size: usize,
    pub batch_timeout_ms: u64,
    pub compression: bool,
    pub reconnect_interval: u64,
    pub max_retries: u32,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTransportConfig {
    pub enabled: bool,
    pub server_host: String,
    pub server_port: u16,
    pub connection_timeout: u64,
    pub keep_alive: bool,
    pub max_retries: u32,
    pub retry_delay: u64,
    pub reconnect_interval: u64,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfigConfig {
    pub enabled: bool,
    pub server_url: String,
    pub api_key: Option<String>,
    pub config_update_interval: u64,
    pub config_retry_attempts: u32,
    pub connection_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfSslHookConfig {
    pub enabled: bool,
    pub kernel_version_requirement: String,
    pub clang_path: String,
    pub bpftool_path: String,
    pub auto_compile: bool,
    pub uprobe_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionConfig {
    pub auto_inject: bool,
    pub hook_library: Option<String>,
    pub process_discovery_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub name: String,
    pub enabled: bool,
    pub five_tuple: FiveTupleFilter,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub source_ip_filter: Option<SourceIpFilter>,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiveTupleFilter {
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<Protocol>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceIpFilter {
    pub mode: String, // "whitelist", "blacklist"
    pub ip_ranges: Vec<String>, // CIDR notation
    pub priority: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent: AgentConfig::default(),
            extraction: ExtractionConfig::default(),
            transport: TransportConfig::default(),
            filters: vec![
                // 默认HTTPS流量规则
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
                    source_ip_filter: None,
                    priority: 100,
                },
                // 企业内网源IP过滤规则示例
                FilterRule {
                    name: "internal_network".to_string(),
                    enabled: false,
                    five_tuple: FiveTupleFilter {
                src_ip: None,
                src_port: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
            },
                    process_name: None,
                    pid: None,
                    source_ip_filter: Some(SourceIpFilter {
                        mode: "whitelist".to_string(),
                        ip_ranges: vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()],
                        priority: 90,
                    }),
                    priority: 90,
                },
            ],
            ebpf_ssl_hook: EbpfSslHookConfig::default(),
            injection: InjectionConfig::default(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            name: "tls_key_agent".to_string(),
            version: "2.0.0".to_string(), // 升级版本号
            log_level: "info".to_string(),
            buffer_pool_size: 5000, // 增大缓冲池用于eBPF事件
            buffer_size: 16384,  // 增大缓冲区大小
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
            kernel_version_requirement: "4.14".to_string(), // eBPF最低版本要求
        }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            enabled_transports: vec![TransportType::Udp], // 只启用UDP传输
            udp: UdpTransportConfig::default(),
            tcp: TcpTransportConfig::default(),
            remote_config: RemoteConfigConfig::default(),
        }
    }
}

impl Default for UdpTransportConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            server_port: 9999,
            batch_size: 100,
            batch_timeout_ms: 100,
            compression: true,
            reconnect_interval: 5,
            max_retries: 10,
            timeout: 10,
        }
    }
}

impl Default for TcpTransportConfig {
    fn default() -> Self {
        Self {
            enabled: false, // 在新架构中默认禁用TCP
            server_host: "127.0.0.1".to_string(),
            server_port: 8888,
            connection_timeout: 10,
            keep_alive: true,
            max_retries: 3,
            retry_delay: 1,
            reconnect_interval: 5,
            timeout: 10,
        }
    }
}

impl Default for RemoteConfigConfig {
    fn default() -> Self {
        Self {
            enabled: false, // 默认禁用，需要手动配置
            server_url: "http://localhost:8080/api/config".to_string(),
            api_key: None,
            config_update_interval: 300, // 5分钟
            config_retry_attempts: 3,
            connection_timeout: 30,
        }
    }
}

impl Default for EbpfSslHookConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            kernel_version_requirement: "4.14".to_string(),
            clang_path: "clang".to_string(),
            bpftool_path: "bpftool".to_string(),
            auto_compile: true,
            uprobe_timeout_ms: 5000,
        }
    }
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            auto_inject: false, // 默认禁用自动注入
            hook_library: None,
            process_discovery_interval: 30, // 30秒进程发现间隔
        }
    }
}

impl Default for SourceIpFilter {
    fn default() -> Self {
        Self {
            mode: "whitelist".to_string(),
            ip_ranges: Vec::new(),
            priority: 100,
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
            return Err(TlsKeyAgentError::Config("必须启用至少一种传输方式".to_string()));
        }

        // 验证eBPF SSL Hook配置
        if self.ebpf_ssl_hook.enabled {
            if self.ebpf_ssl_hook.uprobe_timeout_ms == 0 {
                return Err(TlsKeyAgentError::Config("uprobe_timeout_ms必须大于0".to_string()));
            }
        }

        // 验证UDP传输配置
        if self.transport.enabled_transports.contains(&TransportType::Udp) {
            if self.transport.udp.server_port == 0 {
                return Err(TlsKeyAgentError::Config("UDP服务器端口必须大于0".to_string()));
            }

            if self.transport.udp.batch_size == 0 {
                return Err(TlsKeyAgentError::Config("batch_size必须大于0".to_string()));
            }
        }

        // 验证远程配置
        if self.transport.remote_config.enabled {
            if self.transport.remote_config.server_url.is_empty() {
                return Err(TlsKeyAgentError::Config("远程配置服务器URL不能为空".to_string()));
            }
        }

        Ok(())
    }
}

// 为TransportType添加UDP支持
impl TransportType {
    pub fn default_udp() -> Self {
        TransportType::Udp
    }
}

// 创建默认配置的便捷函数
pub fn create_default_ebpf_config() -> Config {
    Config::default()
}

pub fn create_production_config() -> Config {
    let mut config = Config::default();

    // 生产环境配置优化
    config.agent.buffer_pool_size = 10000;
    config.transport.udp.batch_size = 200;
    config.transport.udp.batch_timeout_ms = 50;
    config.ebpf_ssl_hook.uprobe_timeout_ms = 3000;

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ebpf_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());

        // 验证eBPF配置默认值
        assert!(config.ebpf_ssl_hook.enabled);
        assert_eq!(config.ebpf_ssl_hook.kernel_version_requirement, "4.14");
        assert_eq!(config.ebpf_ssl_hook.auto_compile, true);

        // 验证只有UDP传输
        assert_eq!(config.transport.enabled_transports, vec![TransportType::Udp]);
        assert!(config.transport.udp.enabled);
    }

    #[test]
    fn test_production_config() {
        let config = create_production_config();
        assert!(config.validate().is_ok());

        assert_eq!(config.agent.buffer_pool_size, 10000);
        assert_eq!(config.transport.udp.batch_size, 200);
        assert_eq!(config.transport.udp.batch_timeout_ms, 50);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.agent.name, parsed.agent.name);
        assert_eq!(config.extraction.kernel_version_requirement, "4.14");
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();

        // 有效配置应该通过验证
        assert!(config.validate().is_ok());

        // 测试无效配置
        config.ebpf_ssl_hook.uprobe_timeout_ms = 0;
        assert!(config.validate().is_err());

        config.ebpf_ssl_hook.uprobe_timeout_ms = 1000; // 修复
        config.transport.udp.server_port = 0;
        assert!(config.validate().is_err());

        config.transport.udp.server_port = 9999; // 修复
        assert!(config.validate().is_ok());
    }
}