//! 线程安全的流管理器
//!
//! 为多线程环境提供线程安全的流管理功能

use std::sync::{RwLock, Mutex};
use std::time::{Duration, Instant};

use crate::stream::{StreamManager, StreamManagerConfig};
use crate::types::flow::FlowKey;
use crate::types::{PacketInfo, stream::TcpStream};

/// 用于输出功能的参数结构体
pub struct OutputArgs {
    pub output: Option<String>,
    pub verbose: bool,
}

/// 线程安全的流管理器包装器
pub struct ThreadSafeStreamManager {
    /// 内部的流管理器，使用RwLock保护
    inner: RwLock<StreamManager>,
    /// 统计信息，使用Mutex保护
    pub stats: Mutex<ThreadSafeStats>,
}

/// 线程安全的统计信息
#[derive(Debug, Default)]
pub struct ThreadSafeStats {
    /// 总处理的数据包数
    pub total_packets: u64,
    /// 解析失败的数据包数
    pub parse_errors: u64,
    /// 处理开始时间
    pub start_time: Option<Instant>,
    /// 处理结束时间
    pub end_time: Option<Instant>,
}

impl ThreadSafeStreamManager {
    /// 创建新的线程安全流管理器
    pub fn new(config: StreamManagerConfig) -> Self {
        Self {
            inner: RwLock::new(StreamManager::new(config)),
            stats: Mutex::new(ThreadSafeStats::default()),
        }
    }

    /// 处理数据包（线程安全）
    pub fn process_packet(&self, packet: &PacketInfo) {
        // 更新统计
        {
            let mut stats = self.stats.lock().unwrap();
            if stats.start_time.is_none() {
                stats.start_time = Some(Instant::now());
            }
            stats.total_packets += 1;
        }

        // 处理数据包
        let mut manager = self.inner.write().unwrap();
        manager.process_packet(packet);
    }

    /// 获取所有流的只读视图（线程安全）
    pub fn get_all_streams(&self) -> Vec<TcpStream> {
        let manager = self.inner.read().unwrap();
        manager.get_all_streams().cloned().collect()
    }

    /// 清理过期流（线程安全）
    pub fn cleanup_expired_streams(&self) {
        let mut manager = self.inner.write().unwrap();
        manager.cleanup_expired_streams();
    }

    /// 获取流数量（线程安全）
    pub fn stream_count(&self) -> usize {
        let manager = self.inner.read().unwrap();
        manager.stream_count()
    }

    /// 获取统计信息（线程安全）
    pub fn get_stats(&self) -> ThreadSafeStats {
        let stats = self.stats.lock().unwrap();
        ThreadSafeStats {
            total_packets: stats.total_packets,
            parse_errors: stats.parse_errors,
            start_time: stats.start_time,
            end_time: stats.end_time,
        }
    }

    /// 标记处理完成
    pub fn mark_completed(&self) {
        let mut stats = self.stats.lock().unwrap();
        stats.end_time = Some(Instant::now());
    }

    /// 获取处理持续时间
    pub fn processing_duration(&self) -> Option<Duration> {
        let stats = self.stats.lock().unwrap();
        match (stats.start_time, stats.end_time) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            (Some(start), None) => Some(start.elapsed()),
            _ => None,
        }
    }

    /// 插入一个流到管理器中（用于从其他管理器复制流）
    pub fn insert_stream(&self, stream: crate::types::stream::TcpStream) {
        let mut manager = self.inner.write().unwrap();
        manager.insert_stream(stream);
    }
}

/// 流分片器
///
/// 用于将流分配到不同的处理线程
pub struct StreamSharder {
    /// 线程数量
    num_shards: usize,
}

impl StreamSharder {
    /// 创建新的流分片器
    pub fn new(num_shards: usize) -> Self {
        Self { num_shards }
    }

    /// 根据流键计算分片ID
    pub fn shard_for_flow(&self, flow_key: &FlowKey) -> usize {
        // 使用流键的哈希值来分配分片
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        flow_key.hash(&mut hasher);
        (hasher.finish() as usize) % self.num_shards
    }

    /// 根据IP地址和端口计算分片ID
    pub fn shard_for_packet(&self, src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> usize {
        // 简单的哈希函数
        let hash = (src_ip as u64).wrapping_mul(31)
            .wrapping_add(dst_ip as u64)
            .wrapping_mul(31)
            .wrapping_add(src_port as u64)
            .wrapping_mul(31)
            .wrapping_add(dst_port as u64);
        (hash as usize) % self.num_shards
    }
}

impl ThreadSafeStreamManager {
    /// 输出 SYN-RST-888 检测结果
    pub fn output_syn_rst_888_detection_results(&self, args: &OutputArgs) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::{self, Write};

        let manager = self.inner.read().unwrap();
        let mut total_streams = 0;
        let mut streams_with_rst_888 = 0;
        let mut streams_without_rst_888 = 0;

        // 创建输出写入器
        let mut writer: Box<dyn Write> = if let Some(ref output_path) = args.output {
            Box::new(File::create(output_path)?)
        } else {
            Box::new(io::stdout())
        };

        // 写入标题
        writeln!(writer, "# RST-888检测结果报告")?;
        writeln!(writer, "# 检测SYN包后窗口大小为888的RST-ACK报文")?;
        writeln!(writer, "")?;

        for stream in manager.get_all_streams() {
            total_streams += 1;

            // 只检查TCP流
            if stream.flow_key.protocol() != 6 {
                continue;
            }

            // 检查是否有数据包（意味着有活动）
            if stream.stats.packet_count == 0 {
                continue;
            }

            if stream.has_rst_888_after_syn {
                streams_with_rst_888 += 1;
            } else {
                streams_without_rst_888 += 1;
            }
        }

        // 写入统计信息
        writeln!(writer, "# 统计摘要:")?;
        writeln!(writer, "# 总TCP流数: {}", total_streams)?;
        writeln!(writer, "# 三次握手完成且有RST-888报文的流数: {}", streams_with_rst_888)?;
        writeln!(writer, "# 三次握手完成且无RST-888报文的流数: {}", streams_without_rst_888)?;

        if args.verbose {
            eprintln!("\n统计摘要:");
            eprintln!("  总TCP流数: {}", total_streams);
            eprintln!("  三次握手完成且有RST-888报文的流数: {}", streams_with_rst_888);
            eprintln!("  三次握手完成且无RST-888报文的流数: {}", streams_without_rst_888);
        }

        Ok(())
    }

    /// 输出三次握手ACK后的RST-888检测结果
    pub fn output_handshake_ack_rst_888_detection_results(&self, args: &OutputArgs) -> Result<(), Box<dyn std::error::Error>> {
        use std::fs::File;
        use std::io::{self, Write};

        let manager = self.inner.read().unwrap();
        let mut total_streams = 0;
        let mut streams_with_rst_888 = 0;
        let mut streams_without_rst_888 = 0;
        let mut handshake_complete_count = 0;

        // 创建输出写入器
        let mut writer: Box<dyn Write> = if let Some(ref output_path) = args.output {
            Box::new(File::create(output_path)?)
        } else {
            Box::new(io::stdout())
        };

        // 写入标题
        writeln!(writer, "# 三次握手ACK后RST-888检测结果报告")?;
        writeln!(writer, "# 检测三次握手完成后的ACK报文后窗口大小为888的RST报文")?;
        writeln!(writer, "")?;

        for stream in manager.get_all_streams() {
            total_streams += 1;

            // 只检查TCP流
            if stream.flow_key.protocol() != 6 {
                continue;
            }

            // 检查是否有数据包
            if stream.stats.packet_count == 0 {
                continue;
            }

            // 检查是否有完整的三次握手
            if !stream.connection.handshake.is_complete() {
                continue;
            }

            handshake_complete_count += 1;

            if stream.has_rst_888_after_handshake_ack {
                streams_with_rst_888 += 1;
            } else {
                streams_without_rst_888 += 1;
            }
        }

        // 写入统计信息
        writeln!(writer, "# 统计摘要:")?;
        writeln!(writer, "# 总TCP流数: {}", total_streams)?;
        writeln!(writer, "# 三次握手完成的流数: {}", handshake_complete_count)?;
        writeln!(writer, "# 三次握手完成且有RST-888报文的流数: {}", streams_with_rst_888)?;
        writeln!(writer, "# 三次握手完成且无RST-888报文的流数: {}", streams_without_rst_888)?;

        if args.verbose {
            eprintln!("\n三次握手ACK后RST-888检测结果:");
            eprintln!("总TCP流数: {}", total_streams);
            eprintln!("三次握手完成的流数: {}", handshake_complete_count);
            eprintln!("检测到三次握手ACK后RST-888的流数: {}", streams_with_rst_888);
        }

        Ok(())
    }
}