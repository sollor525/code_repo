//! 多线程并行处理模块
//!
//! 提供PCAP文件的多线程处理能力，包括：
//! - 数据包解析并行化
//! - 流管理的线程安全
//! - 结果聚合

pub mod processor;
pub mod stream_manager;
pub mod worker_pool;

pub use processor::{ParallelProcessor, ParallelConfig};
pub use stream_manager::ThreadSafeStreamManager;
pub use worker_pool::WorkerPool;