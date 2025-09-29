//! 缓存配置

/// 缓存配置结构体
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_flows: u32,
    pub max_bytes_per_flow: u32,
    pub timeout_ms: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_flows: 1000,
            max_bytes_per_flow: 65536,
            timeout_ms: 30000, // 30秒
        }
    }
}
