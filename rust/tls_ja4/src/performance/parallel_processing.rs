//! 并行处理优化模块
//! 
//! 提供高性能的并行TLS解析和指纹计算

use rayon::prelude::*;
use std::sync::Arc;
use parking_lot::Mutex;
// use tls_parser::TlsVersion;
use crate::performance::memory_pool::HighPerformanceMemoryPool;

/// 并行TLS处理器
pub struct ParallelTlsProcessor {
    // 工作线程池
    thread_pool: rayon::ThreadPool,
    // 内存池
    #[allow(dead_code)]
    memory_pool: Arc<HighPerformanceMemoryPool>,
    // 统计信息
    stats: Arc<Mutex<ProcessingStats>>,
}

/// 处理统计信息
#[derive(Debug, Default, Clone)]
pub struct ProcessingStats {
    pub total_processed: u64,
    pub successful_parses: u64,
    pub failed_parses: u64,
    pub total_processing_time: std::time::Duration,
    pub average_processing_time: std::time::Duration,
}

/// TLS处理任务
#[derive(Clone)]
pub struct TlsProcessingTask {
    pub payload: Vec<u8>,
    pub task_id: u64,
    pub timestamp: std::time::Instant,
}

/// 处理结果
pub struct ProcessingResult {
    pub task_id: u64,
    pub success: bool,
    pub ja4: Option<String>,
    pub ja3: Option<String>,
    pub processing_time: std::time::Duration,
    pub error: Option<String>,
}

impl ParallelTlsProcessor {
    pub fn new() -> Self {
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_cpus::get())
            .thread_name(|i| format!("tls-worker-{}", i))
            .build()
            .unwrap();
        
        Self {
            thread_pool,
            memory_pool: Arc::new(HighPerformanceMemoryPool::new()),
            stats: Arc::new(Mutex::new(ProcessingStats::default())),
        }
    }
    
    /// 并行处理TLS数据包
    pub fn process_parallel(&self, tasks: Vec<TlsProcessingTask>) -> Vec<ProcessingResult> {
        let start_time = std::time::Instant::now();
        
        let results: Vec<ProcessingResult> = self.thread_pool.install(|| {
            tasks.par_iter()
                .map(|task| self.process_single_task(task))
                .collect()
        });
        
        let total_time = start_time.elapsed();
        self.update_stats(results.len(), total_time);
        
        results
    }
    
    /// 处理单个任务
    fn process_single_task(&self, task: &TlsProcessingTask) -> ProcessingResult {
        let start_time = std::time::Instant::now();
        
        match self.parse_and_calculate_fingerprints(&task.payload) {
            Ok((ja4, ja3)) => ProcessingResult {
                task_id: task.task_id,
                success: true,
                ja4: Some(ja4),
                ja3: Some(ja3),
                processing_time: start_time.elapsed(),
                error: None,
            },
            Err(error) => ProcessingResult {
                task_id: task.task_id,
                success: false,
                ja4: None,
                ja3: None,
                processing_time: start_time.elapsed(),
                error: Some(error),
            },
        }
    }
    
    /// 解析并计算指纹
    fn parse_and_calculate_fingerprints(&self, payload: &[u8]) -> Result<(String, String), String> {
        use crate::performance::tls_parser_optimized::OptimizedTlsParser;
        use crate::performance::fingerprint_optimized::{UltraFastJa4Calculator, UltraFastJa3Calculator};
        
        let mut parser = OptimizedTlsParser::new();
        let parsed = parser.parse_tls_optimized(payload)
            .ok_or("Failed to parse TLS")?;
        
        let mut ja4_calc = UltraFastJa4Calculator::new();
        let mut ja3_calc = UltraFastJa3Calculator::new();
        
        let ja4 = ja4_calc.calculate_ja4_ultra_fast(
            parsed.version,
            &parsed.ciphers,
            &parsed.extensions,
            &parsed.signature_algorithms,
            payload,
        );
        
        let ja3 = ja3_calc.calculate_ja3_ultra_fast(
            parsed.version,
            &parsed.ciphers,
            &parsed.extensions,
            &parsed.elliptic_curves,
            &parsed.ec_point_formats,
        ).ok_or("Failed to calculate JA3")?;
        
        Ok((ja4, ja3))
    }
    
    /// 更新统计信息
    fn update_stats(&self, processed_count: usize, total_time: std::time::Duration) {
        let mut stats = self.stats.lock();
        stats.total_processed += processed_count as u64;
        stats.total_processing_time += total_time;
        stats.average_processing_time = if stats.total_processed > 0 {
            std::time::Duration::from_nanos(
                stats.total_processing_time.as_nanos() as u64 / stats.total_processed
            )
        } else {
            std::time::Duration::ZERO
        };
    }
    
    /// 获取统计信息
    pub fn get_stats(&self) -> ProcessingStats {
        self.stats.lock().clone()
    }
    
    /// 重置统计信息
    pub fn reset_stats(&self) {
        let mut stats = self.stats.lock();
        *stats = ProcessingStats::default();
    }
}

impl Default for ParallelTlsProcessor {
    fn default() -> Self {
        Self::new()
    }
}

/// 批量并行处理器
pub struct BatchParallelProcessor {
    processor: ParallelTlsProcessor,
    batch_size: usize,
    #[allow(dead_code)]
    max_batch_size: usize,
}

impl BatchParallelProcessor {
    pub fn new(batch_size: usize) -> Self {
        Self {
            processor: ParallelTlsProcessor::new(),
            batch_size,
            max_batch_size: batch_size * 4,
        }
    }
    
    /// 批量处理
    pub fn process_batch(&self, tasks: Vec<TlsProcessingTask>) -> Vec<ProcessingResult> {
        if tasks.len() <= self.batch_size {
            return self.processor.process_parallel(tasks);
        }
        
        // 分批处理
        let mut results = Vec::new();
        for chunk in tasks.chunks(self.batch_size) {
            let chunk_results = self.processor.process_parallel(chunk.to_vec());
            results.extend(chunk_results);
        }
        
        results
    }
    
    /// 自适应批量处理
    pub fn process_adaptive(&self, tasks: Vec<TlsProcessingTask>) -> Vec<ProcessingResult> {
        let task_count = tasks.len();
        let optimal_batch_size = if task_count < 100 {
            task_count
        } else if task_count < 1000 {
            task_count / 4
        } else {
            self.batch_size
        };
        
        let mut results = Vec::new();
        for chunk in tasks.chunks(optimal_batch_size) {
            let chunk_results = self.processor.process_parallel(chunk.to_vec());
            results.extend(chunk_results);
        }
        
        results
    }
}

impl Default for BatchParallelProcessor {
    fn default() -> Self {
        Self::new(100)
    }
}

/// 流式并行处理器
pub struct StreamingParallelProcessor {
    processor: ParallelTlsProcessor,
    buffer: Arc<Mutex<Vec<TlsProcessingTask>>>,
    buffer_size: usize,
    flush_interval: std::time::Duration,
    last_flush: std::time::Instant,
}

impl StreamingParallelProcessor {
    pub fn new(buffer_size: usize, flush_interval: std::time::Duration) -> Self {
        Self {
            processor: ParallelTlsProcessor::new(),
            buffer: Arc::new(Mutex::new(Vec::with_capacity(buffer_size))),
            buffer_size,
            flush_interval,
            last_flush: std::time::Instant::now(),
        }
    }
    
    /// 添加任务到缓冲区
    pub fn add_task(&mut self, task: TlsProcessingTask) -> Option<Vec<ProcessingResult>> {
        {
            let mut buffer = self.buffer.lock();
            buffer.push(task);
        }
        
        // 检查是否需要刷新
        let should_flush = {
            let buffer = self.buffer.lock();
            buffer.len() >= self.buffer_size || 
            self.last_flush.elapsed() >= self.flush_interval
        };
        
        if should_flush {
            return self.flush_buffer();
        }
        
        None
    }
    
    /// 刷新缓冲区
    pub fn flush_buffer(&mut self) -> Option<Vec<ProcessingResult>> {
        let tasks = {
            let mut buffer = self.buffer.lock();
            if buffer.is_empty() {
                return None;
            }
            let tasks = buffer.clone();
            buffer.clear();
            tasks
        };
        
        self.last_flush = std::time::Instant::now();
        Some(self.processor.process_parallel(tasks))
    }
    
    /// 强制刷新
    pub fn force_flush(&mut self) -> Vec<ProcessingResult> {
        self.flush_buffer().unwrap_or_default()
    }
}

/// 性能监控器
pub struct PerformanceMonitor {
    start_time: std::time::Instant,
    samples: Vec<PerformanceSample>,
    max_samples: usize,
}

#[derive(Debug, Clone)]
pub struct PerformanceSample {
    pub timestamp: std::time::Instant,
    pub processing_time: std::time::Duration,
    pub throughput: f64, // 处理速度 (tasks/second)
    pub memory_usage: usize,
}

impl PerformanceMonitor {
    pub fn new(max_samples: usize) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            samples: Vec::with_capacity(max_samples),
            max_samples,
        }
    }
    
    /// 记录性能样本
    pub fn record_sample(&mut self, processing_time: std::time::Duration, task_count: usize) {
        let throughput = task_count as f64 / processing_time.as_secs_f64();
        let memory_usage = self.get_memory_usage();
        
        let sample = PerformanceSample {
            timestamp: std::time::Instant::now(),
            processing_time,
            throughput,
            memory_usage,
        };
        
        if self.samples.len() >= self.max_samples {
            self.samples.remove(0);
        }
        self.samples.push(sample);
    }
    
    /// 获取平均吞吐量
    pub fn get_average_throughput(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        
        let total_throughput: f64 = self.samples.iter()
            .map(|s| s.throughput)
            .sum();
        
        total_throughput / self.samples.len() as f64
    }
    
    /// 获取峰值吞吐量
    pub fn get_peak_throughput(&self) -> f64 {
        self.samples.iter()
            .map(|s| s.throughput)
            .fold(0.0, f64::max)
    }
    
    /// 获取内存使用情况
    fn get_memory_usage(&self) -> usize {
        // 简化的内存使用计算
        std::process::id() as usize * 1024 // 占位符实现
    }
    
    /// 获取性能报告
    pub fn get_performance_report(&self) -> PerformanceReport {
        PerformanceReport {
            total_runtime: self.start_time.elapsed(),
            sample_count: self.samples.len(),
            average_throughput: self.get_average_throughput(),
            peak_throughput: self.get_peak_throughput(),
            average_processing_time: self.get_average_processing_time(),
            memory_efficiency: self.get_memory_efficiency(),
        }
    }
    
    /// 获取平均处理时间
    fn get_average_processing_time(&self) -> std::time::Duration {
        if self.samples.is_empty() {
            return std::time::Duration::ZERO;
        }
        
        let total_time: std::time::Duration = self.samples.iter()
            .map(|s| s.processing_time)
            .sum();
        
        std::time::Duration::from_nanos(
            total_time.as_nanos() as u64 / self.samples.len() as u64
        )
    }
    
    /// 获取内存效率
    fn get_memory_efficiency(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        
        let avg_memory: f64 = self.samples.iter()
            .map(|s| s.memory_usage as f64)
            .sum::<f64>() / self.samples.len() as f64;
        
        // 简化的内存效率计算
        1.0 / (1.0 + avg_memory / 1_000_000.0)
    }
}

#[derive(Debug)]
pub struct PerformanceReport {
    pub total_runtime: std::time::Duration,
    pub sample_count: usize,
    pub average_throughput: f64,
    pub peak_throughput: f64,
    pub average_processing_time: std::time::Duration,
    pub memory_efficiency: f64,
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new(1000)
    }
}
