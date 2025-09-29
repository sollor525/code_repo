//! 缓存管理器

use std::collections::HashMap;
use super::config::CacheConfig;

/// 分段缓存结构体
#[derive(Debug, Clone)]
pub struct SegmentCache {
    pub data: Vec<u8>,
    pub expected_len: usize,
    pub is_complete: bool,
    pub last_activity: u64, // 时间戳（毫秒）
    pub flow_id: u32,
}

/// 内部上下文结构体
pub struct InternalContext {
    pub segment_cache: HashMap<String, SegmentCache>,
    pub config: CacheConfig,
    pub next_flow_id: u32,
}

impl InternalContext {
    pub fn new() -> Self {
        Self {
            segment_cache: HashMap::new(),
            config: CacheConfig::default(),
            next_flow_id: 1,
        }
    }
    
    /// 设置缓存限制
    pub fn set_cache_limits(&mut self, max_flows: u32, max_bytes_per_flow: u32, timeout_ms: u64) {
        self.config.max_flows = max_flows;
        self.config.max_bytes_per_flow = max_bytes_per_flow;
        self.config.timeout_ms = timeout_ms;
    }
    
    /// 清理超时的缓存
    pub fn cleanup_timeout_cache(&mut self) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        let timeout_threshold = current_time - self.config.timeout_ms;
        
        // 清理超时的缓存
        self.segment_cache.retain(|_, cache| cache.last_activity > timeout_threshold);
    }
    
    /// 获取缓存统计信息
    pub fn get_cache_stats(&self) -> (u32, u32) {
        let flows = self.segment_cache.len() as u32;
        let total_bytes: u32 = self.segment_cache.values()
            .map(|cache| cache.data.len() as u32)
            .sum();
        (flows, total_bytes)
    }
}
