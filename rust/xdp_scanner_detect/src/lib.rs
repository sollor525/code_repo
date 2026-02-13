//! xdp-scanner-detect - 基于 eBPF/XDP 的高性能网络处理系统库
//!
//! 这个库提供了 xdp-scanner-detect 的核心功能模块，可以用于其他项目集成或测试。

pub mod config;
pub mod session;
pub mod scanner;
pub mod stats;
pub mod utils;
pub mod xdp;

// 公共导出
pub use config::Config;
pub use session::{SessionManager, SessionStats};
pub use scanner::{ScannerDetector, ScannerStats};
pub use stats::StatsCollector;
pub use xdp::XdpManager;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");