use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsKeyAgentError {
    #[error("配置错误: {0}")]
    Config(String),

    #[error("网络错误: {0}")]
    Network(String),

    #[error("序列化错误: {0}")]
    Serialization(String),

    #[error("TLS解析错误: {0}")]
    TlsParse(String),

    #[error("传输错误: {0}")]
    Transport(String),

    #[error("内存分配错误: {0}")]
    Memory(String),

    #[error("权限错误: {0}")]
    Permission(String),

    #[error("提取错误: {0}")]
    Extraction(String),

    #[error("注入错误: {0}")]
    Injection(String),

    #[error("检测错误: {0}")]
    Detection(String),

    #[error("Hook错误: {0}")]
    Hook(String),

    #[error("FFI错误: {0}")]
    Ffi(String),

    #[error("IO错误: {0}")]
    Io(#[from] std::io::Error),

    #[error("监控错误: {0}")]
    Monitoring(String),

    #[error("故障恢复错误: {0}")]
    Recovery(String),

    #[error("健康检查错误: {0}")]
    HealthCheck(String),

    #[error("负载均衡错误: {0}")]
    LoadBalance(String),

    #[error("通用错误: {0}")]
    Anyhow(#[from] anyhow::Error),

    #[error("未知错误: {0}")]
    Unknown(String),
}

pub type Result<T> = std::result::Result<T, TlsKeyAgentError>;