//! 基于 Rayon 的按流并行分析
//!
//! 按 `FlowKey` 把数据包分组，不同流并行处理、同一流内报文按时间有序，
//! 每条流由独立的 `StreamManager` 处理，因此处理阶段完全无锁。

use std::collections::HashMap;
use std::time::{Duration, Instant};
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};

use crate::stream::{StreamManager, StreamManagerConfig};
use crate::types::PacketInfo;
use crate::types::flow::FlowKey;
use crate::types::stream::TcpStream;

/// Rayon 并行处理器
pub struct RayonProcessor {
    config: RayonConfig,
}

/// Rayon 并行处理配置
#[derive(Debug, Clone)]
pub struct RayonConfig {
    /// 流管理器配置
    pub stream_config: StreamManagerConfig,
    /// 是否启用进度条
    pub enable_progress: bool,
    /// 线程池大小（None 表示使用默认，即 CPU 核心数）
    pub thread_pool_size: Option<usize>,
}

impl Default for RayonConfig {
    fn default() -> Self {
        Self {
            stream_config: StreamManagerConfig::default(),
            enable_progress: true,
            thread_pool_size: None,
        }
    }
}

/// Rayon 处理结果
#[derive(Debug)]
pub struct RayonResult {
    /// 处理的数据包总数
    pub packet_count: u64,
    /// 识别的流数量
    pub stream_count: usize,
    /// 总处理时间
    pub processing_time: Duration,
    /// 所有流的列表
    pub streams: Vec<TcpStream>,
}

impl RayonResult {
    /// 计算处理速度（包/秒）
    pub fn packets_per_second(&self) -> f64 {
        let seconds = self.processing_time.as_secs_f64();
        if seconds > 0.0 {
            self.packet_count as f64 / seconds
        } else {
            0.0
        }
    }

    /// 计算平均处理时间（微秒/包）
    pub fn avg_packet_time_us(&self) -> f64 {
        if self.packet_count > 0 {
            self.processing_time.as_micros() as f64 / self.packet_count as f64
        } else {
            0.0
        }
    }
}

impl RayonProcessor {
    /// 创建新的 Rayon 处理器
    pub fn new(config: RayonConfig) -> Self {
        // 全局线程池只能初始化一次，重复设置会返回 Err，忽略即可
        if let Some(pool_size) = config.thread_pool_size {
            let _ = rayon::ThreadPoolBuilder::new()
                .num_threads(pool_size)
                .build_global();
        }
        Self { config }
    }

    /// 按流分组并行分析
    ///
    /// 不同流并行、同一流内报文按时间戳有序由单一线程处理。
    /// 由于各流互不相交，每条流用独立的 `StreamManager`，处理阶段无需任何锁。
    pub fn process_packets_by_flow(&self, packets: Vec<PacketInfo>) -> RayonResult {
        // 按流键分组
        let mut flow_map: HashMap<FlowKey, Vec<PacketInfo>> = HashMap::new();
        for packet in packets {
            let flow_key = FlowKey::new(
                packet.src_ip,
                packet.dst_ip,
                packet.src_port,
                packet.dst_port,
                packet.protocol,
            );
            flow_map.entry(flow_key).or_default().push(packet);
        }

        let start_time = Instant::now();
        let total_packets: u64 = flow_map.values().map(|v| v.len() as u64).sum();

        let progress = if self.config.enable_progress {
            let pb = ProgressBar::new(total_packets);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            Some(pb)
        } else {
            None
        };

        // 每条流独立处理，结果汇总
        let streams: Vec<TcpStream> = flow_map
            .into_par_iter()
            .flat_map_iter(|(_flow_key, mut packets)| {
                packets.sort_by_key(|p| p.timestamp);
                let mut manager = StreamManager::new(self.config.stream_config.clone());
                for packet in &packets {
                    manager.process_packet(packet);
                }
                if let Some(pb) = &progress {
                    pb.inc(packets.len() as u64);
                }
                manager.into_streams()
            })
            .collect();

        if let Some(pb) = progress {
            pb.finish_with_message("处理完成");
        }

        RayonResult {
            packet_count: total_packets,
            stream_count: streams.len(),
            processing_time: start_time.elapsed(),
            streams,
        }
    }
}
