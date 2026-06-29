// 错误类型定义

use std::fmt;

// 建造错误类型
#[derive(Debug, Clone)]
pub enum BuildError {
    MissingConnection,
    InvalidConfiguration(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::MissingConnection => write!(f, "Missing network connection"),
            BuildError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
        }
    }
}

impl std::error::Error for BuildError {}

// PCAP生成错误类型
#[derive(Debug, Clone)]
pub enum PcapError {
    IoError(String),
    InvalidPacket(String),
    NetworkError(String),
}

impl fmt::Display for PcapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcapError::IoError(msg) => write!(f, "IO error: {}", msg),
            PcapError::InvalidPacket(msg) => write!(f, "Invalid packet: {}", msg),
            PcapError::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for PcapError {}

impl From<std::io::Error> for PcapError {
    fn from(err: std::io::Error) -> Self {
        PcapError::IoError(err.to_string())
    }
}