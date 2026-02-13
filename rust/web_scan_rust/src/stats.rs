//! 统计收集模块
//! 
//! 负责收集和记录Web扫描检测引擎的各种统计信息，
//! 包括性能指标、检测结果统计、系统运行状态等。
//! 这些统计信息对于监控系统性能、调试问题和优化配置非常重要。

// 导入标准库中的原子类型，用于无锁的并发计数
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};
// 导入时间相关类型
use std::time::{Duration, SystemTime, UNIX_EPOCH};
// 导入序列化trait，用于将统计信息转换为JSON等格式
use serde::{Deserialize, Serialize};

/// Web扫描统计信息结构体
/// 
/// 包含引擎运行过程中的各种统计指标。
/// 所有字段都使用原子类型，确保在多线程环境下的线程安全。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(C)]  // C兼容的内存布局
pub struct WebScanStats {
    // 数据包处理统计
    pub packets_processed: u64,      // 已处理的数据包总数
    pub packets_matched: u64,        // 匹配到规则的数据包数量
    pub packets_alerted: u64,        // 触发告警的数据包数量
    pub packets_dropped: u64,        // 被丢弃的数据包数量
    pub packets_reset: u64,          // 触发TCP重置的数据包数量
    
    // 协议检测统计
    pub http_packets: u64,           // HTTP协议数据包数量
    pub https_packets: u64,          // HTTPS协议数据包数量
    pub http2_packets: u64,          // HTTP/2协议数据包数量
    pub unknown_packets: u64,        // 未知协议数据包数量
    
    // 性能统计
    pub total_processing_time: u64,  // 总处理时间（微秒）
    pub avg_processing_time: u64,    // 平均处理时间（微秒）
    pub max_processing_time: u64,    // 最大处理时间（微秒）
    pub min_processing_time: u64,    // 最小处理时间（微秒）
    
    // 规则统计
    pub rules_loaded: u32,           // 当前加载的规则数量
    pub rules_active: u32,           // 活跃的规则数量
    
    // 系统状态
    pub start_time: u64,             // 引擎启动时间（Unix时间戳）
    pub uptime: u64,                 // 运行时间（秒）
    pub last_activity: u64,          // 最后活动时间（Unix时间戳）
}

// 为WebScanStats实现Default trait
// 提供默认的统计信息初始值
impl Default for WebScanStats {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            // 初始化所有计数器为0
            packets_processed: 0,
            packets_matched: 0,
            packets_alerted: 0,
            packets_dropped: 0,
            packets_reset: 0,
            
            // 协议统计初始化为0
            http_packets: 0,
            https_packets: 0,
            http2_packets: 0,
            unknown_packets: 0,
            
            // 性能统计初始化为0
            total_processing_time: 0,
            avg_processing_time: 0,
            max_processing_time: 0,
            min_processing_time: u64::MAX,  // 最小时间初始化为最大值
            
            // 规则统计初始化为0
            rules_loaded: 0,
            rules_active: 0,
            
            // 系统状态
            start_time: now,
            uptime: 0,
            last_activity: now,
        }
    }
}

/// 统计收集器结构体
/// 
/// 负责收集和更新各种统计信息。
/// 使用原子类型确保在多线程环境下的线程安全，
/// 无需使用锁机制，提高性能。
pub struct StatsCollector {
    // 数据包处理统计（原子计数器）
    packets_processed: AtomicU64,    // 已处理数据包计数
    packets_matched: AtomicU64,      // 匹配数据包计数
    packets_alerted: AtomicU64,      // 告警数据包计数
    packets_dropped: AtomicU64,      // 丢弃数据包计数
    packets_reset: AtomicU64,        // 重置数据包计数
    
    // 协议检测统计（原子计数器）
    http_packets: AtomicU64,         // HTTP数据包计数
    https_packets: AtomicU64,        // HTTPS数据包计数
    http2_packets: AtomicU64,        // HTTP/2数据包计数
    unknown_packets: AtomicU64,      // 未知协议数据包计数
    
    // 性能统计（原子计数器）
    total_processing_time: AtomicU64, // 总处理时间（微秒）
    processing_count: AtomicU64,     // 处理次数（用于计算平均值）
    max_processing_time: AtomicU64,  // 最大处理时间（微秒）
    min_processing_time: AtomicU64,  // 最小处理时间（微秒）
    
    // 规则统计（原子计数器）
    rules_loaded: AtomicU32,         // 加载的规则数量
    rules_active: AtomicU32,         // 活跃的规则数量
    
    // 系统状态
    start_time: AtomicU64,           // 启动时间（Unix时间戳）
    last_activity: AtomicU64,        // 最后活动时间（Unix时间戳）
}

// 为StatsCollector实现Default trait
impl Default for StatsCollector {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        Self {
            // 初始化所有原子计数器
            packets_processed: AtomicU64::new(0),
            packets_matched: AtomicU64::new(0),
            packets_alerted: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_reset: AtomicU64::new(0),
            
            // 协议统计
            http_packets: AtomicU64::new(0),
            https_packets: AtomicU64::new(0),
            http2_packets: AtomicU64::new(0),
            unknown_packets: AtomicU64::new(0),
            
            // 性能统计
            total_processing_time: AtomicU64::new(0),
            processing_count: AtomicU64::new(0),
            max_processing_time: AtomicU64::new(0),
            min_processing_time: AtomicU64::new(u64::MAX),
            
            // 规则统计
            rules_loaded: AtomicU32::new(0),
            rules_active: AtomicU32::new(0),
            
            // 系统状态
            start_time: AtomicU64::new(now),
            last_activity: AtomicU64::new(now),
        }
    }
}

impl StatsCollector {
    /// 创建新的统计收集器实例
    /// 
    /// 初始化所有计数器为0，记录启动时间。
    pub fn new() -> Self {
        Self::default()
    }

    /// 增加已处理数据包计数
    /// 
    /// 每次处理数据包时调用此方法。
    /// 使用Relaxed内存顺序，因为我们只关心计数，不关心严格的顺序。
    pub fn increment_packets_processed(&self) {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.update_last_activity();
    }

    /// 增加匹配数据包计数
    /// 
    /// 当数据包匹配到规则时调用此方法。
    pub fn increment_packets_matched(&self) {
        self.packets_matched.fetch_add(1, Ordering::Relaxed);
    }

    /// 增加告警数据包计数
    /// 
    /// 当数据包触发告警时调用此方法。
    pub fn increment_packets_alerted(&self) {
        self.packets_alerted.fetch_add(1, Ordering::Relaxed);
    }

    /// 增加丢弃数据包计数
    /// 
    /// 当数据包被丢弃时调用此方法。
    pub fn increment_packets_dropped(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// 增加重置数据包计数
    /// 
    /// 当数据包触发TCP重置时调用此方法。
    pub fn increment_packets_reset(&self) {
        self.packets_reset.fetch_add(1, Ordering::Relaxed);
    }

    /// 记录协议检测结果
    /// 
    /// 根据检测到的协议类型更新相应的计数器。
    /// 
    /// # 参数
    /// * `protocol` - 检测到的协议类型
    pub fn record_protocol(&self, protocol: crate::protocol::Protocol) {
        match protocol {
            crate::protocol::Protocol::Http => {
                self.http_packets.fetch_add(1, Ordering::Relaxed);
            }
            crate::protocol::Protocol::Https => {
                self.https_packets.fetch_add(1, Ordering::Relaxed);
            }
            crate::protocol::Protocol::Http2 => {
                self.http2_packets.fetch_add(1, Ordering::Relaxed);
            }
            crate::protocol::Protocol::Unknown => {
                self.unknown_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// 记录处理时间
    /// 
    /// 用于性能统计，记录单个数据包的处理时间。
    /// 
    /// # 参数
    /// * `duration` - 处理耗时
    pub fn record_processing_time(&self, duration: Duration) {
        let micros = duration.as_micros() as u64;
        
        // 更新总处理时间
        self.total_processing_time.fetch_add(micros, Ordering::Relaxed);
        
        // 更新处理次数
        self.processing_count.fetch_add(1, Ordering::Relaxed);
        
        // 更新最大处理时间（使用CAS操作确保原子性）
        loop {
            let current_max = self.max_processing_time.load(Ordering::Relaxed);
            if micros <= current_max {
                break;
            }
            if self.max_processing_time.compare_exchange_weak(
                current_max, 
                micros, 
                Ordering::Relaxed, 
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
        
        // 更新最小处理时间（使用CAS操作确保原子性）
        loop {
            let current_min = self.min_processing_time.load(Ordering::Relaxed);
            if micros >= current_min {
                break;
            }
            if self.min_processing_time.compare_exchange_weak(
                current_min, 
                micros, 
                Ordering::Relaxed, 
                Ordering::Relaxed
            ).is_ok() {
                break;
            }
        }
    }

    /// 设置规则数量
    /// 
    /// 当规则加载或卸载时调用此方法。
    /// 
    /// # 参数
    /// * `loaded` - 加载的规则数量
    /// * `active` - 活跃的规则数量
    pub fn set_rule_counts(&self, loaded: u32, active: u32) {
        self.rules_loaded.store(loaded, Ordering::Relaxed);
        self.rules_active.store(active, Ordering::Relaxed);
    }

    /// 更新最后活动时间
    /// 
    /// 记录最后一次统计更新的时间。
    /// 这个方法是私有的，由其他方法自动调用。
    fn update_last_activity(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_activity.store(now, Ordering::Relaxed);
    }

    /// 获取当前统计信息快照
    /// 
    /// 返回当前所有统计信息的副本。
    /// 这个方法是线程安全的，可以在任何时候调用。
    /// 
    /// # 返回值
    /// * `WebScanStats` - 当前统计信息的快照
    pub fn get_stats(&self) -> WebScanStats {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let start_time = self.start_time.load(Ordering::Relaxed);
        let uptime = now.saturating_sub(start_time);
        
        // 计算平均处理时间 - 使用实际处理的包数而不是记录次数
        let total_time = self.total_processing_time.load(Ordering::Relaxed);
        let processed_count = self.packets_processed.load(Ordering::Relaxed);
        let avg_time = if processed_count > 0 { total_time / processed_count } else { 0 };
        
        WebScanStats {
            // 数据包统计
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            packets_matched: self.packets_matched.load(Ordering::Relaxed),
            packets_alerted: self.packets_alerted.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            packets_reset: self.packets_reset.load(Ordering::Relaxed),
            
            // 协议统计
            http_packets: self.http_packets.load(Ordering::Relaxed),
            https_packets: self.https_packets.load(Ordering::Relaxed),
            http2_packets: self.http2_packets.load(Ordering::Relaxed),
            unknown_packets: self.unknown_packets.load(Ordering::Relaxed),
            
            // 性能统计
            total_processing_time: total_time,
            avg_processing_time: avg_time,
            max_processing_time: self.max_processing_time.load(Ordering::Relaxed),
            min_processing_time: {
                let min = self.min_processing_time.load(Ordering::Relaxed);
                if min == u64::MAX { 0 } else { min }
            },
            
            // 规则统计
            rules_loaded: self.rules_loaded.load(Ordering::Relaxed),
            rules_active: self.rules_active.load(Ordering::Relaxed),
            
            // 系统状态
            start_time,
            uptime,
            last_activity: self.last_activity.load(Ordering::Relaxed),
        }
    }

    /// 重置所有统计信息
    /// 
    /// 将所有计数器重置为0，重新开始统计。
    /// 启动时间保持不变，但其他所有指标都会重置。
    pub fn reset(&self) {
        // 重置所有计数器
        self.packets_processed.store(0, Ordering::Relaxed);
        self.packets_matched.store(0, Ordering::Relaxed);
        self.packets_alerted.store(0, Ordering::Relaxed);
        self.packets_dropped.store(0, Ordering::Relaxed);
        self.packets_reset.store(0, Ordering::Relaxed);
        
        // 重置协议统计
        self.http_packets.store(0, Ordering::Relaxed);
        self.https_packets.store(0, Ordering::Relaxed);
        self.http2_packets.store(0, Ordering::Relaxed);
        self.unknown_packets.store(0, Ordering::Relaxed);
        
        // 重置性能统计
        self.total_processing_time.store(0, Ordering::Relaxed);
        self.processing_count.store(0, Ordering::Relaxed);
        self.max_processing_time.store(0, Ordering::Relaxed);
        self.min_processing_time.store(u64::MAX, Ordering::Relaxed);
        
        // 重置规则统计
        self.rules_loaded.store(0, Ordering::Relaxed);
        self.rules_active.store(0, Ordering::Relaxed);
        
        // 更新最后活动时间
        self.update_last_activity();
    }

    /// 获取性能指标
    /// 
    /// 返回关键的性能统计信息，用于实时监控。
    /// 
    /// # 返回值
    /// * `(u64, u64, u64)` - (平均处理时间, 最大处理时间, 最小处理时间) 单位：微秒
    pub fn get_performance_metrics(&self) -> (u64, u64, u64) {
        let total_time = self.total_processing_time.load(Ordering::Relaxed);
        let count = self.processing_count.load(Ordering::Relaxed);
        let avg_time = if count > 0 { total_time / count } else { 0 };
        let max_time = self.max_processing_time.load(Ordering::Relaxed);
        let min_time = {
            let min = self.min_processing_time.load(Ordering::Relaxed);
            if min == u64::MAX { 0 } else { min }
        };
        
        (avg_time, max_time, min_time)
    }

    /// 获取吞吐量统计
    /// 
    /// 计算当前的处理吞吐量（每秒处理的数据包数量）。
    /// 
    /// # 返回值
    /// * `f64` - 每秒处理的数据包数量
    pub fn get_throughput(&self) -> f64 {
        let start_time = self.start_time.load(Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let uptime = now.saturating_sub(start_time);
        if uptime == 0 {
            0.0
        } else {
            let processed = self.packets_processed.load(Ordering::Relaxed);
            processed as f64 / uptime as f64
        }
    }
}

// 条件编译：只在测试时编译以下代码
#[cfg(test)]
mod tests {
    // 导入父模块的所有公共项
    use super::*;
    use std::thread;
    use std::time::Duration;

    /// 测试统计收集器的基本功能
    #[test]
    fn test_stats_collector_basic() {
        let collector = StatsCollector::new();
        
        // 测试初始状态
        let stats = collector.get_stats();
        assert_eq!(stats.packets_processed, 0);
        assert_eq!(stats.packets_matched, 0);
        
        // 测试计数增加
        collector.increment_packets_processed();
        collector.increment_packets_matched();
        
        let stats = collector.get_stats();
        assert_eq!(stats.packets_processed, 1);
        assert_eq!(stats.packets_matched, 1);
    }

    /// 测试性能时间记录
    #[test]
    fn test_processing_time_recording() {
        let collector = StatsCollector::new();
        
        // 记录一些处理时间
        collector.record_processing_time(Duration::from_micros(100));
        collector.record_processing_time(Duration::from_micros(200));
        collector.record_processing_time(Duration::from_micros(50));
        
        let (avg, max, min) = collector.get_performance_metrics();
        assert_eq!(avg, 116);  // (100 + 200 + 50) / 3 ≈ 116
        assert_eq!(max, 200);
        assert_eq!(min, 50);
    }

    /// 测试多线程安全性
    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        
        let collector = Arc::new(StatsCollector::new());
        let mut handles = vec![];
        
        // 创建多个线程同时更新统计信息
        for _ in 0..10 {
            let collector_clone = Arc::clone(&collector);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    collector_clone.increment_packets_processed();
                    collector_clone.increment_packets_matched();
                }
            });
            handles.push(handle);
        }
        
        // 等待所有线程完成
        for handle in handles {
            handle.join().unwrap();
        }
        
        // 验证最终结果
        let stats = collector.get_stats();
        assert_eq!(stats.packets_processed, 1000);  // 10线程 × 100次
        assert_eq!(stats.packets_matched, 1000);
    }

    /// 测试统计信息重置
    #[test]
    fn test_stats_reset() {
        let collector = StatsCollector::new();
        
        // 添加一些统计信息
        collector.increment_packets_processed();
        collector.increment_packets_matched();
        
        // 验证有数据
        let stats = collector.get_stats();
        assert_eq!(stats.packets_processed, 1);
        assert_eq!(stats.packets_matched, 1);
        
        // 重置统计信息
        collector.reset();
        
        // 验证已重置
        let stats = collector.get_stats();
        assert_eq!(stats.packets_processed, 0);
        assert_eq!(stats.packets_matched, 0);
        
        // 启动时间应该保持不变
        assert!(stats.start_time > 0);
    }
}