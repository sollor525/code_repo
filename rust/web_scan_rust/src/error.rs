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

/// 错误严重程度枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub enum ErrorSeverity {
    /// 警告 - 可以继续执行
    Warning = 1,
    /// 错误 - 跳过当前项但继续
    Error = 2,
    /// 致命错误 - 必须终止
    Fatal = 3,
}

/// 规则错误详细信息
#[derive(Debug, Clone)]
pub struct RuleError {
    pub rule_id: u32,
    pub line_number: usize,
    pub error_type: RuleErrorType,
    pub message: String,
    pub severity: ErrorSeverity,
}

/// 规则警告信息
#[derive(Debug, Clone)]
pub struct RuleWarning {
    pub rule_id: u32,
    pub line_number: usize,
    pub warning_type: RuleWarningType,
    pub message: String,
}

/// 规则错误类型
#[derive(Debug, Clone)]
pub enum RuleErrorType {
    SyntaxError(String),
    HyperscanIncompatibility(String),
    PcreError(String),
    ContentError(String),
    MetadataError(String),
}

/// 规则警告类型
#[derive(Debug, Clone)]
pub enum RuleWarningType {
    HyperscanCompatibilityWarning(String),
    PerformanceWarning(String),
    VersionDeprecated(String),
    OptimizationSuggestion(String),
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

/// 规则加载统计结构
#[derive(Debug, Clone, Default)]
pub struct RuleLoadingStats {
    pub total_rules: usize,
    pub successful_rules: usize,
    pub failed_rules: Vec<RuleError>,
    pub skipped_rules: usize,
    pub warnings: Vec<RuleWarning>,
}

/// 错误返回数据结构（用于C接口）
#[repr(C)]
#[derive(Debug)]
pub struct rule_loading_error_t {
    pub rule_id: u32,
    pub line_number: u32,
    pub error_code: i32,
    pub severity: i32,  // ErrorSeverity enum value
    pub message: [u8; 256],
}

impl Default for rule_loading_error_t {
    fn default() -> Self {
        Self {
            rule_id: 0,
            line_number: 0,
            error_code: 0,
            severity: 0,
            message: [0; 256],
        }
    }
}

impl RuleLoadingStats {
    /// 创建新的规则加载统计实例
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取失败规则数量
    pub fn failed_count(&self) -> usize {
        self.failed_rules.len()
    }

    /// 获取警告数量
    pub fn warning_count(&self) -> usize {
        self.warnings.len()
    }

    /// 格式化错误详情为字符串
    pub fn format_error_details(&self) -> String {
        let mut details = String::new();

        for error in &self.failed_rules {
            details.push_str(&format!("❌ [规则{}] {}: {}\n",
                error.rule_id,
                match error.severity {
                    ErrorSeverity::Warning => "警告",
                    ErrorSeverity::Error => "错误",
                    ErrorSeverity::Fatal => "致命错误",
                },
                error.message));
        }

        for warning in &self.warnings {
            details.push_str(&format!("⚠️  [规则{}] {}\n", warning.rule_id, warning.message));
        }

        details
    }
}