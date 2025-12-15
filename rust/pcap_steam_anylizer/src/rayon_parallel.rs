//! 基于 Rayon 的并行处理模块
//!
//! Rayon 提供了数据并行处理能力，可以轻松地将迭代操作并行化
//! 无需手动管理线程，使用起来更简单高效

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};

use crate::stream::{StreamManager, StreamManagerConfig};
use crate::types::PacketInfo;
use crate::types::flow::FlowKey;

/// Rayon 并行处理器
pub struct RayonProcessor {
    /// 线程安全的流管理器
    stream_manager: Arc<Mutex<StreamManager>>,
    /// 并行配置
    config: RayonConfig,
}

/// Rayon 并行处理配置
#[derive(Debug, Clone)]
pub struct RayonConfig {
    /// 流管理器配置
    pub stream_config: StreamManagerConfig,
    /// 批处理大小
    pub batch_size: usize,
    /// 是否启用进度条
    pub enable_progress: bool,
    /// 线程池大小（None 表示使用默认）
    pub thread_pool_size: Option<usize>,
}

impl Default for RayonConfig {
    fn default() -> Self {
        Self {
            stream_config: StreamManagerConfig::default(),
            batch_size: 1000,
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
    pub streams: Vec<crate::types::stream::TcpStream>,
    /// 解析错误的数据包数
    pub parse_errors: u64,
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
        // 设置线程池配置
        if let Some(pool_size) = config.thread_pool_size {
            rayon::ThreadPoolBuilder::new()
                .num_threads(pool_size)
                .build_global()
                .unwrap();
        }

        let stream_manager = Arc::new(Mutex::new(StreamManager::new(
            config.stream_config.clone()
        )));

        Self {
            stream_manager,
            config,
        }
    }

    /// 并行处理数据包批次
    pub fn process_packets_parallel(&self, packets: Vec<PacketInfo>) -> Result<RayonResult, Box<dyn std::error::Error>> {
        let start_time = Instant::now();
        let total_packets = packets.len() as u64;

        // 创建进度条
        let progress = if self.config.enable_progress {
            let pb = ProgressBar::new(total_packets);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                    .unwrap()
                    .progress_chars("#>-")
            );
            Some(pb)
        } else {
            None
        };

        // 按批次分割数据包
        let batches: Vec<_> = packets
            .chunks(self.config.batch_size)
            .map(|chunk| chunk.to_vec())
            .collect();

        // 使用 Rayon 并行处理批次
        let _batch_count = batches.len();

        // 使用 Mutex 保护计数器
        let processed_counter = Mutex::new(0u64);
        let error_counter = Mutex::new(0u64);

        batches.into_par_iter()
            .for_each(|batch| {
                // 在本地线程中处理批次
                let local_processed = batch.len() as u64;
                let local_errors = 0u64; // 这里可以添加错误处理逻辑

                // 获取流管理器的锁
                {
                    let mut manager = self.stream_manager.lock().unwrap();

                    // 批量处理数据包
                    for packet in batch {
                        manager.process_packet(&packet);
                    }
                }

                // 更新计数器
                {
                    let mut processed = processed_counter.lock().unwrap();
                    *processed += local_processed;

                    let mut errors = error_counter.lock().unwrap();
                    *errors += local_errors;
                }

                // 更新进度条
                if let Some(ref pb) = progress {
                    pb.inc(local_processed);
                }
            });

        // 获取最终计数
        let (processed_packets, parse_errors) = {
            (*processed_counter.lock().unwrap(), *error_counter.lock().unwrap())
        };

        // 完成进度条
        if let Some(pb) = progress {
            pb.finish_with_message("处理完成");
        }

        let processing_time = start_time.elapsed();

        // 获取所有流
        let streams: Vec<crate::types::stream::TcpStream> = {
            let manager = self.stream_manager.lock().unwrap();
            manager.get_all_streams().cloned().collect()
        };

        let stream_count = streams.len();

        Ok(RayonResult {
            packet_count: processed_packets,
            stream_count,
            processing_time,
            streams,
            parse_errors,
        })
    }

    /// 使用 Rayon 的并行迭代器处理单个数据包
    pub fn process_packets_iter<'a, I>(&self, packets: I) -> Result<RayonResult, Box<dyn std::error::Error>>
    where
        I: IntoIterator<Item = &'a PacketInfo> + Send + 'a,
        <I as IntoIterator>::IntoIter: ExactSizeIterator + Send,
    {
        let packets: Vec<_> = packets.into_iter().cloned().collect();
        self.process_packets_parallel(packets)
    }

    /// 按流键并行处理数据包（保持同一线程处理同一个流）
    pub fn process_packets_by_flow(&self, packets: Vec<PacketInfo>) -> Result<RayonResult, Box<dyn std::error::Error>> {
        // 按流键分组
        let mut flow_map: std::collections::HashMap<FlowKey, Vec<PacketInfo>> = std::collections::HashMap::new();

        for packet in packets {
            let flow_key = FlowKey::new(
                packet.src_ip,
                packet.dst_ip,
                packet.src_port,
                packet.dst_port,
                packet.protocol,
            );
            flow_map.entry(flow_key).or_insert_with(Vec::new).push(packet);
        }

        let start_time = Instant::now();
        let total_packets: u64 = flow_map.values().map(|v| v.len() as u64).sum();

        // 创建进度条
        let progress = if self.config.enable_progress {
            let pb = ProgressBar::new(total_packets);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                    .unwrap()
                    .progress_chars("#>-")
            );
            Some(pb)
        } else {
            None
        };

        // 并行处理每个流
        let processed_counter = Mutex::new(0u64);

        flow_map.into_par_iter()
            .for_each(|(_flow_key, mut packets)| {
                // 按时间排序每个流的数据包
                packets.sort_by_key(|p| p.timestamp);

                // 获取流管理器的锁
                {
                    let mut manager = self.stream_manager.lock().unwrap();

                    // 处理整个流
                    for packet in packets {
                        manager.process_packet(&packet);

                        // 更新进度
                        let mut processed = processed_counter.lock().unwrap();
                        *processed += 1;

                        if let Some(ref pb) = progress {
                            pb.inc(1);
                        }
                    }
                }
            });

        if let Some(pb) = progress {
            pb.finish_with_message("处理完成");
        }

        let processing_time = start_time.elapsed();

        // 获取所有流
        let streams: Vec<crate::types::stream::TcpStream> = {
            let manager = self.stream_manager.lock().unwrap();
            manager.get_all_streams().cloned().collect()
        };

        let stream_count = streams.len();

        Ok(RayonResult {
            packet_count: total_packets,
            stream_count,
            processing_time,
            streams,
            parse_errors: 0,
        })
    }

    /// 获取流管理器的引用（用于获取结果）
    pub fn stream_manager(&self) -> &Arc<Mutex<StreamManager>> {
        &self.stream_manager
    }

    /// 并行清理过期流
    pub fn cleanup_expired_streams_parallel(&self) {
        let manager = self.stream_manager.lock().unwrap();
        // 在锁内完成清理
        // 由于清理是只读操作，可以在锁外并行处理
        drop(manager);

        // 注意：由于 Rust 的借用检查器限制，这里需要获取锁
        let mut manager = self.stream_manager.lock().unwrap();
        manager.cleanup_expired_streams();
    }

    /// 并行统计流信息
    pub fn compute_statistics_parallel(&self) -> Vec<(FlowKey, crate::types::flow::FlowStats)> {
        let manager = self.stream_manager.lock().unwrap();
        let streams: Vec<_> = manager.get_all_streams().cloned().collect();
        drop(manager);

        // 使用 Rayon 并行计算统计
        streams.into_par_iter()
            .map(|stream| {
                let stats = stream.stats.clone();
                (stream.flow_key.clone(), stats)
            })
            .collect()
    }
}