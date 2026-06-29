//! # 核心模块
//!
//! 定义基础类型和接口，包括网络连接、会话抽象和错误类型。

pub mod network;
pub mod session;
pub mod error;

// 重新导出公共接口
pub use network::{IpRange, IpVersion, PortRange, NetworkConnection};
pub use session::{ApplicationFlow, ApplicationFlowType, TcpOnlyFlow, HttpFlow};
pub use error::{BuildError, PcapError};