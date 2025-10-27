//! YAML模板解析器
//!
//! 负责解析YAML模板文件并转换为内部数据结构

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, Context};

/// YAML模板的完整结构
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct YamlTemplate {
    /// 模板名称和描述
    pub metadata: TemplateMetadata,
    /// 网络配置
    pub network: NetworkConfig,
    /// 会话配置
    pub sessions: Vec<SessionTemplate>,
    /// 默认的全局设置
    pub defaults: Option<DefaultSettings>,
}

/// 模板元数据
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TemplateMetadata {
    pub name: String,
    pub description: Option<String>,
    pub version: Option<String>,
    pub author: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// 网络配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkConfig {
    /// 默认源MAC地址
    pub src_mac: Option<String>,
    /// 默认目标MAC地址
    pub dst_mac: Option<String>,
    /// MAC地址池（用于多个连接）
    pub mac_pools: Option<MacAddressPool>,
    /// VLAN配置
    pub vlan: Option<VlanConfig>,
}

/// MAC地址池
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MacAddressPool {
    pub src_macs: Vec<String>,
    pub dst_macs: Vec<String>,
}

/// VLAN配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VlanConfig {
    /// VLAN标签配置
    pub tags: Vec<VlanTag>,
    /// 是否使用双层VLAN (QinQ)
    pub qinq: Option<bool>,
}

/// VLAN标签配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VlanTag {
    /// VLAN ID (1-4094)
    pub vlan_id: u16,
    /// VLAN优先级 (0-7, 可选)
    pub priority: Option<u8>,
    /// DEI位 (Drop Eligible Indicator, 可选)
    pub dei: Option<bool>,
    /// 标签类型 (outer/inner, 用于双层VLAN)
    pub tag_type: Option<String>,
}

/// 会话模板
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionTemplate {
    /// 会话名称
    pub name: String,
    /// 会话类型
    pub session_type: SessionType,
    /// 连接配置
    pub connection: ConnectionConfig,
    /// 应用层配置
    pub application: Option<ApplicationConfig>,
    /// 重复次数（相同配置的多个会话）
    pub repeat: Option<u32>,
}

/// 会话类型
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum SessionType {
    /// TCP会话
    Tcp {
        ports: Option<Vec<u16>>,
        duration_ms: Option<u32>,
    },
    /// UDP会话（未来扩展）
    Udp {
        ports: Option<Vec<u16>>,
        duration_ms: Option<u32>,
    },
}

/// 连接配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnectionConfig {
    /// 源地址配置
    pub src: Option<AddressConfig>,
    /// 目标地址配置
    pub dst: Option<AddressConfig>,
}

/// 地址配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AddressConfig {
    /// IP地址或范围
    pub ip: Option<String>,
    /// 端口或范围
    pub port: Option<u16>,
    /// MAC地址
    pub mac: Option<String>,
}

/// 应用层配置
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "protocol")]
pub enum ApplicationConfig {
    /// HTTP协议
    Http {
        requests: Vec<HttpRequestConfig>,
        responses: Vec<HttpResponseConfig>,
        timing: Option<HttpTimingConfig>,
    },
    /// 原始TCP（无应用层）
    Tcp {
        data_size: Option<usize>,
        flags: Option<Vec<String>>,
    },
}

/// HTTP请求配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpRequestConfig {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
}

/// HTTP响应配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpResponseConfig {
    pub status_code: Option<u16>,
    pub status_text: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
}

/// HTTP时序配置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpTimingConfig {
    pub request_delay_ms: Option<u32>,
    pub response_delay_ms: Option<u32>,
    pub think_time_ms: Option<u32>,
}

/// 默认设置
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DefaultSettings {
    pub default_headers: Option<HashMap<String, String>>,
    pub default_timing: Option<HttpTimingConfig>,
}

/// 模板配置（包含解析的模板和生成选项）
#[derive(Debug)]
pub struct TemplateConfig {
    pub template: YamlTemplate,
    pub options: TemplateOptions,
}

/// 生成选项
#[derive(Debug, Clone)]
pub struct TemplateOptions {
    pub packet_count_override: Option<u32>,
    pub randomize_ports: bool,
    pub randomize_ips: bool,
}

/// 模板错误类型
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("YAML解析错误: {0}")]
    ParseError(#[from] serde_yaml::Error),
    #[error("模板配置错误: {0}")]
    ConfigError(String),
    #[error("地址格式错误: {0}")]
    AddressError(String),
    #[error("端口错误: {0}")]
    PortError(String),
    #[error("MAC地址格式错误: {0}")]
    MacAddressError(String),
    #[error("HTTP配置错误: {0}")]
    HttpConfigError(String),
}

impl TemplateError {
    pub fn kind(&self) -> TemplateErrorKind {
        match self {
            TemplateError::ParseError(_) => TemplateErrorKind::ParseError,
            TemplateError::ConfigError(_) => TemplateErrorKind::ConfigError,
            TemplateError::AddressError(_) => TemplateErrorKind::AddressError,
            TemplateError::PortError(_) => TemplateErrorKind::PortError,
            TemplateError::MacAddressError(_) => TemplateErrorKind::MacAddressError,
            TemplateError::HttpConfigError(_) => TemplateErrorKind::HttpConfigError,
        }
    }
}

/// 模板错误种类
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateErrorKind {
    ParseError,
    ConfigError,
    AddressError,
    PortError,
    MacAddressError,
    HttpConfigError,
}

/// 模板解析器
pub struct TemplateParser;

impl TemplateParser {
    pub fn new() -> Self {
        Self {}
    }

    /// 从文件解析模板
    pub fn parse_file<P: AsRef<std::path::Path>>(path: P) -> Result<YamlTemplate> {
        let path_ref = path.as_ref();
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("无法读取模板文件: {:?}", path_ref))?;

        let template: YamlTemplate = serde_yaml::from_str(&content)
            .with_context(|| format!("解析YAML模板失败: {:?}", path_ref))?;

        Self::validate_template(&template)?;
        Ok(template)
    }

    /// 从字符串解析模板
    pub fn parse_string(content: &str) -> Result<YamlTemplate> {
        let template: YamlTemplate = serde_yaml::from_str(content)
            .with_context(|| "解析YAML模板失败")?;

        Self::validate_template(&template)?;
        Ok(template)
    }

    /// 验证模板的有效性
    fn validate_template(template: &YamlTemplate) -> Result<()> {
        // 验证MAC地址格式
        if let Some(src_mac) = &template.network.src_mac {
            Self::validate_mac_address(src_mac)?;
        }
        if let Some(dst_mac) = &template.network.dst_mac {
            Self::validate_mac_address(dst_mac)?;
        }

        // 验证会话配置
        for session in &template.sessions {
            Self::validate_session_config(session)?;
        }

        Ok(())
    }

    /// 验证MAC地址格式
    fn validate_mac_address(mac: &str) -> Result<()> {
        if mac.split(':').count() != 6 {
            return Err(TemplateError::MacAddressError(format!(
                "无效的MAC地址格式: {}. 期望格式: XX:XX:XX:XX:XX:XX", mac
            )).into());
        }
        Ok(())
    }

    /// 验证会话配置
    fn validate_session_config(session: &SessionTemplate) -> Result<()> {
        // 验证端口范围
        if let SessionType::Tcp { ports: Some(ports), .. } = &session.session_type {
            for port in ports {
                if *port == 0  {
                    return Err(TemplateError::PortError(format!(
                        "无效的端口: {}. 有效范围: 1-65535", port
                    )).into());
                }
            }
        }

        Ok(())
    }
}

impl TemplateConfig {
    pub fn new(template: YamlTemplate) -> Self {
        Self {
            template,
            options: TemplateOptions::default(),
        }
    }

    /// 从YAML文件创建模板配置
    pub fn from_yaml_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let template = TemplateParser::parse_file(path)?;
        Ok(Self::new(template))
    }
}

impl Default for TemplateOptions {
    fn default() -> Self {
        Self {
            packet_count_override: None,
            randomize_ports: true,
            randomize_ips: true,
        }
    }
}