//! Web扫描检测引擎的错误处理模块
//! 
//! 这个模块定义了所有可能出现的错误类型，并提供统一的错误处理机制。
//! Rust的错误处理基于Result类型，这是一种类型安全的错误处理方式。

// 导入thiserror crate，它提供了方便的错误类型定义宏
use thiserror::Error;

// 定义一个类型别名，简化Result类型的使用
// 这样我们就可以写 Result<T> 而不是 std::result::Result<T, WebScanError>
pub type Result<T> = std::result::Result<T, WebScanError>;

// 定义错误枚举类型
// #[derive(Error, Debug)] 自动为枚举实现Error trait和Debug trait
// Error trait是Rust标准库中所有错误类型必须实现的trait
// Debug trait允许使用{:?}格式化输出错误信息
#[derive(Error, Debug)]
pub enum WebScanError {
    // 每个错误变体都有一个#[error]属性，定义错误消息格式
    // {0}表示第一个字段的值会被插入到错误消息中
    
    /// 协议检测失败错误
    #[error("Protocol detection failed: {0}")]
    ProtocolDetection(String),  // String类型存储具体的错误信息

    /// 规则解析错误
    #[error("Rule parsing error: {0}")]
    RuleParsing(String),

    /// Hyperscan库相关错误
    #[error("Hyperscan error: {0}")]
    Hyperscan(String),

    /// 配置错误
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// IO错误（文件读写等）
    /// #[from]属性表示可以自动从std::io::Error转换为WebScanError::Io
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON解析错误
    /// 同样可以自动从serde_json::Error转换
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    /// TOML解析错误
    /// 可以自动从toml::de::Error转换
    #[error("TOML parsing error: {0}")]
    Toml(#[from] toml::de::Error),

    /// 无效输入错误
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// 引擎未初始化错误
    #[error("Engine not initialized")]
    NotInitialized,

    /// 内容处理错误
    #[error("Content processing error: {0}")]
    ContentProcessing(String),

    /// 内存分配失败错误
    #[error("Memory allocation failed")]
    MemoryAllocation,
}

// 为WebScanError实现方法
impl WebScanError {
    /// 将Rust错误转换为C兼容的错误代码
    /// 
    /// 这个方法使用模式匹配（match表达式）来处理不同的错误类型
    /// 返回负数错误代码，这是C语言中常见的错误处理约定
    pub fn to_error_code(&self) -> i32 {
        // match表达式类似于其他语言的switch语句，但更强大
        // self是当前WebScanError实例的引用
        match self {
            // 每个分支匹配一种错误类型，返回对应的错误代码
            WebScanError::ProtocolDetection(_) => -1,  // _表示忽略String内容
            WebScanError::RuleParsing(_) => -2,
            WebScanError::Hyperscan(_) => -3,
            WebScanError::Configuration(_) => -4,
            WebScanError::Io(_) => -5,
            WebScanError::Json(_) => -6,
            WebScanError::Toml(_) => -7,
            WebScanError::InvalidInput(_) => -8,
            WebScanError::NotInitialized => -9,
            WebScanError::MemoryAllocation => -10,
            WebScanError::ContentProcessing(_) => -11,
        }
    }
}