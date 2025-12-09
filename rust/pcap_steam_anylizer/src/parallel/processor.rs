//! 并行PCAP处理器
//!
//! 提供多线程处理PCAP文件的主要接口

use std::sync::Arc;
use std::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};

use crate::parallel::{ThreadSafeStreamManager, WorkerPool};
use crate::pcap::{reader::PcapReader, parser::PacketParser};
use crate::stream::StreamManagerConfig;
use crate::types::PacketInfo;

/// 并行处理配置
#[derive(Debug, Clone)]
pub struct ParallelConfig {
    /// 工作线程数量（None表示使用CPU核心数）
    pub num_workers: Option<usize>,
    /// 流管理器配置
    pub stream_config: StreamManagerConfig,
    /// 批处理大小
    pub batch_size: usize,
    /// 是否启用进度条
    pub enable_progress: bool,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            num_workers: None, // 使用CPU核心数
            stream_config: StreamManagerConfig {
                stream_timeout: Duration::from_secs(300),
                max_streams: 100000,
                enable_event_logging: false, // 多线程环境下关闭事件日志以提高性能
                max_events_per_stream: 0,
                cleanup_interval: Duration::from_secs(60),
                syn_rst_888: false,
                handshake_ack_rst_888: false,
            },
            batch_size: 1000,
            enable_progress: true,
        }
    }
}

/// 并行PCAP处理器
pub struct ParallelProcessor {
    /// 配置
    config: ParallelConfig,
    /// 工作线程池
    worker_pool: Option<WorkerPool>,
    /// 线程安全的流管理器
    stream_manager: Arc<ThreadSafeStreamManager>,
}

impl ParallelProcessor {
    /// 创建新的并行处理器
    pub fn new(config: ParallelConfig) -> Self {
        let _num_workers = config.num_workers.unwrap_or_else(|| {
            // 默认使用CPU核心数
            num_cpus::get()
        });

        let stream_manager = Arc::new(ThreadSafeStreamManager::new(
            config.stream_config.clone()
        ));

        Self {
            config,
            worker_pool: None,
            stream_manager,
        }
    }

    /// 处理PCAP文件
    pub fn process_file(&mut self, pcap_path: &str) -> Result<ParallelResult, Box<dyn std::error::Error>> {
        // 打开PCAP文件
        let mut pcap_reader = PcapReader::open(pcap_path)?;

        // 获取文件信息
        let linktype = pcap_reader.global_header().linktype;
        let packet_parser = PacketParser::new(false, false, linktype);

        // 创建工作线程池
        let num_workers = self.config.num_workers.unwrap_or_else(|| num_cpus::get());
        let worker_pool = WorkerPool::new(num_workers, Arc::clone(&self.stream_manager));
        self.worker_pool = Some(worker_pool);

        // 创建进度条
        let progress = if self.config.enable_progress {
            Some(ProgressBar::new_spinner())
        } else {
            None
        };

        if let Some(ref pb) = progress {
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] 处理中: {pos} 个数据包 (速度: {per_sec} 包/秒)")
                    .unwrap()
            );
        }

        // 批量处理数据包
        let mut batch = Vec::with_capacity(self.config.batch_size);
        let mut packet_count = 0u64;
        let start_time = std::time::Instant::now();

        for packet_result in pcap_reader {
            match packet_result {
                Ok(packet) => {
                    // 解析数据包
                    let parsed_packet = match packet_parser.parse(packet) {
                        Ok(p) => p,
                        Err(e) => {
                            // 记录解析错误
                            let mut stats = self.stream_manager.stats.lock().unwrap();
                            stats.parse_errors += 1;
                            continue;
                        }
                    };

                    // 转换为PacketInfo
                    let packet_info: PacketInfo = parsed_packet.into();
                    batch.push(packet_info);

                    // 批量提交
                    if batch.len() >= self.config.batch_size {
                        self.submit_batch(&mut batch)?;
                        packet_count += batch.len() as u64;

                        // 更新进度条
                        if let Some(ref pb) = progress {
                            pb.set_position(packet_count);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("读取数据包错误: {}", e);
                }
            }
        }

        // 提交剩余的数据包
        if !batch.is_empty() {
            self.submit_batch(&mut batch)?;
            packet_count += batch.len() as u64;
        }

        // 标记处理完成
        self.stream_manager.mark_completed();

        // 等待所有工作线程完成
        if let Some(pool) = self.worker_pool.take() {
            pool.shutdown();
        }

        // 更新最终进度
        if let Some(ref pb) = progress {
            pb.finish_with_message("处理完成");
        }

        // 获取所有流
        let streams = self.stream_manager.get_all_streams();

        // 返回结果
        Ok(ParallelResult {
            packet_count,
            stream_count: streams.len(),
            processing_time: start_time.elapsed(),
            streams,
            parse_errors: {
                let stats = self.stream_manager.get_stats();
                stats.parse_errors
            },
        })
    }

    /// 提交一批数据包到工作线程
    fn submit_batch(&self, batch: &mut Vec<PacketInfo>) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref pool) = self.worker_pool {
            for packet in batch.drain(..) {
                pool.submit_packet(packet)?;
            }
        }
        Ok(())
    }

    /// 获取流管理器的引用
    pub fn stream_manager(&self) -> &Arc<ThreadSafeStreamManager> {
        &self.stream_manager
    }
}

/// 并行处理结果
#[derive(Debug)]
pub struct ParallelResult {
    /// 处理的数据包总数
    pub packet_count: u64,
    /// 识别的流数量
    pub stream_count: usize,
    /// 总处理时间
    pub processing_time: Duration,
    /// 所有流的列表
    pub streams: Vec<crate::TcpStream>,
    /// 解析错误的数据包数
    pub parse_errors: u64,
}

impl ParallelResult {
    /// 计算处理速度（包/秒）
    pub fn packets_per_second(&self) -> f64 {
        let seconds = self.processing_time.as_secs_f64();
        if seconds > 0.0 {
            self.packet_count as f64 / seconds
        } else {
            0.0
        }
    }

    /// 计算平均每个包的处理时间（微秒）
    pub fn avg_packet_time_us(&self) -> f64 {
        if self.packet_count > 0 {
            self.processing_time.as_micros() as f64 / self.packet_count as f64
        } else {
            0.0
        }
    }
}