//! 统一错误处理模块

use thiserror::Error;

/// TLS JA4 库的统一错误类型
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TlsJa4Error {
    #[error("Invalid parameter")]
    InvalidParameter,

    #[error("Invalid packet format")]
    InvalidPacket,

    #[error("Not a TLS packet")]
    NotTls,

    #[error("Not a Client Hello packet")]
    NotClientHello,

    #[error("Insufficient data")]
    InsufficientData,

    #[error("Cache overflow")]
    CacheOverflow,

    #[error("Segment cached")]
    SegmentCached,

    #[error("IPv6 not supported")]
    Ipv6NotSupported,

    #[error("Database operation failed: {0}")]
    DatabaseError(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

impl TlsJa4Error {
    /// 转换为C API错误码
    pub fn to_c_error_code(&self) -> i32 {
        match self {
            TlsJa4Error::InvalidParameter => -1,
            TlsJa4Error::InvalidPacket => -2,
            TlsJa4Error::NotTls => -3,
            TlsJa4Error::NotClientHello => -4,
            TlsJa4Error::InsufficientData => -5,
            TlsJa4Error::CacheOverflow => -6,
            TlsJa4Error::SegmentCached => -7,
            TlsJa4Error::Ipv6NotSupported => -8,
            TlsJa4Error::DatabaseError(_) => -9,
            TlsJa4Error::IoError(_) => -10,
            TlsJa4Error::ParseError(_) => -11,
        }
    }

    /// 从C API错误码创建错误
    pub fn from_c_error_code(code: i32) -> Self {
        match code {
            -1 => TlsJa4Error::InvalidParameter,
            -2 => TlsJa4Error::InvalidPacket,
            -3 => TlsJa4Error::NotTls,
            -4 => TlsJa4Error::NotClientHello,
            -5 => TlsJa4Error::InsufficientData,
            -6 => TlsJa4Error::CacheOverflow,
            -7 => TlsJa4Error::SegmentCached,
            -8 => TlsJa4Error::Ipv6NotSupported,
            -9 => TlsJa4Error::DatabaseError("Unknown database error".to_string()),
            -10 => TlsJa4Error::IoError("Unknown IO error".to_string()),
            -11 => TlsJa4Error::ParseError("Unknown parse error".to_string()),
            _ => TlsJa4Error::InvalidParameter,
        }
    }
}

/// 结果类型别名
pub type TlsJa4Result<T> = Result<T, TlsJa4Error>;

impl From<std::io::Error> for TlsJa4Error {
    fn from(err: std::io::Error) -> Self {
        TlsJa4Error::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for TlsJa4Error {
    fn from(err: serde_json::Error) -> Self {
        TlsJa4Error::ParseError(format!("JSON parse error: {}", err))
    }
}