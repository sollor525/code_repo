//! Web扫描检测引擎 - Rust实现
//! 
//! 这是一个高性能的Web扫描检测引擎，提供FFI接口用于与C代码集成。
//! 
//! # 模块说明
//! - `protocol`: 协议检测模块，用于识别HTTP/HTTPS等协议
//! - `rules`: 规则管理模块，负责加载和解析检测规则
//! - `engine`: 检测引擎核心，协调各个模块工作
//! - `stats`: 统计收集模块，记录性能和检测数据
//! - `ffi`: 外部函数接口，提供C语言兼容的API
//! - `error`: 错误处理模块，定义各种错误类型

// 声明子模块 - 在Rust中，每个.rs文件都是一个模块
pub mod protocol;  // 协议检测模块
pub mod rules;     // 规则管理模块
pub mod engine;    // 检测引擎模块
pub mod stats;     // 统计收集模块
pub mod ffi;       // FFI接口模块
pub mod error;     // 错误处理模块
pub mod hyperscan; // Hyperscan集成模块

// 重新导出协议类型，供测试使用
pub use crate::protocol::Protocol;

// 导入标准库中的类型
use std::sync::Once;  // Once类型用于确保某个操作只执行一次
use log::info;        // 日志宏，用于输出信息级别的日志

// 静态变量，用于确保初始化只执行一次
// static关键字定义静态变量，生命周期为整个程序运行期间
static INIT: Once = Once::new();

/// 初始化Web扫描检测引擎
/// 
/// 这个函数使用Once类型确保初始化代码只执行一次，
/// 即使被多次调用也是安全的。
pub fn init() {
    // call_once方法确保闭包内的代码只执行一次
    INIT.call_once(|| {
        // 初始化环境日志记录器
        env_logger::init();
        // 输出初始化成功的信息
        info!("Web Scan Detection Engine (Rust) initialized");
    });
}

// 重新导出主要类型，方便外部使用
// pub use语句将其他模块的公共类型重新导出到当前模块
// 这样外部代码就可以直接使用 web_scan_rust::WebScanEngine
// 而不需要写 web_scan_rust::engine::WebScanEngine
pub use engine::{WebScanEngine, WebScanResult, WebScanAction};
pub use rules::{RuleManager, Rule, RuleAction};
pub use protocol::ProtocolDetector;
pub use stats::{StatsCollector, WebScanStats};
pub use error::{WebScanError, Result};
pub use hyperscan::{HyperscanCompiler, HyperscanScanner, HyperscanDatabase, MatchResult};

// 条件编译：只在测试时编译以下代码
#[cfg(test)]
mod tests {
    // 导入父模块的所有公共项
    use super::*;

    // 测试函数，函数名前加#[test]属性
    #[test]
    fn test_init() {
        // 测试初始化函数
        init();
        // 多次调用不应该panic（程序崩溃）
        init();
    }
}