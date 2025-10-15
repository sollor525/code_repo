//! 缓存优化模块
//! 
//! 提供高性能的缓存机制，减少重复计算和解析

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{Duration, Instant};
use tls_parser::TlsVersion;

/// 高性能LRU缓存
pub struct HighPerformanceCache<K, V> {
    cache: Arc<RwLock<HashMap<K, CacheEntry<V>>>>,
    max_size: usize,
    ttl: Duration,
    stats: Arc<RwLock<CacheStats>>,
}

/// 缓存条目
#[derive(Debug, Clone)]
pub struct CacheEntry<V> {
    pub value: V,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub access_count: u64,
}

/// 缓存统计信息
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub total_requests: u64,
}

impl<K, V> HighPerformanceCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    pub fn new(max_size: usize, ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_size,
            ttl,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }
    
    /// 获取缓存值
    pub fn get(&self, key: &K) -> Option<V> {
        let mut cache = self.cache.write();
        let mut stats = self.stats.write();
        
        stats.total_requests += 1;
        
        if let Some(entry) = cache.get_mut(key) {
            // 检查TTL
            if entry.created_at.elapsed() > self.ttl {
                cache.remove(key);
                stats.misses += 1;
                return None;
            }
            
            // 更新访问信息
            entry.last_accessed = Instant::now();
            entry.access_count += 1;
            stats.hits += 1;
            
            Some(entry.value.clone())
        } else {
            stats.misses += 1;
            None
        }
    }
    
    /// 插入缓存值
    pub fn insert(&self, key: K, value: V) {
        let mut cache = self.cache.write();
        
        // 检查容量限制
        if cache.len() >= self.max_size {
            self.evict_least_recently_used(&mut cache);
        }
        
        let entry = CacheEntry {
            value,
            created_at: Instant::now(),
            last_accessed: Instant::now(),
            access_count: 1,
        };
        
        cache.insert(key, entry);
    }
    
    /// 移除最少使用的条目
    fn evict_least_recently_used(&self, cache: &mut HashMap<K, CacheEntry<V>>) {
        let mut oldest_key = None;
        let mut oldest_time = Instant::now();
        
        for (key, entry) in cache.iter() {
            if entry.last_accessed < oldest_time {
                oldest_time = entry.last_accessed;
                oldest_key = Some(key.clone());
            }
        }
        
        if let Some(key) = oldest_key {
            cache.remove(&key);
            self.stats.write().evictions += 1;
        }
    }
    
    /// 清理过期条目
    pub fn cleanup_expired(&self) {
        let mut cache = self.cache.write();
        let now = Instant::now();
        
        cache.retain(|_, entry| now.duration_since(entry.created_at) <= self.ttl);
    }
    
    /// 获取缓存统计信息
    pub fn get_stats(&self) -> CacheStats {
        self.stats.read().clone()
    }
    
    /// 获取命中率
    pub fn get_hit_rate(&self) -> f64 {
        let stats = self.stats.read();
        if stats.total_requests == 0 {
            0.0
        } else {
            stats.hits as f64 / stats.total_requests as f64
        }
    }
    
    /// 清空缓存
    pub fn clear(&self) {
        self.cache.write().clear();
        let mut stats = self.stats.write();
        *stats = CacheStats::default();
    }
    
    /// 获取缓存大小
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }
    
    /// 检查是否为空
    pub fn is_empty(&self) -> bool {
        self.cache.read().is_empty()
    }
}

/// TLS解析结果缓存
pub struct TlsParseCache {
    cache: HighPerformanceCache<u64, ParsedTlsResult>,
}

/// 解析后的TLS结果
#[derive(Debug, Clone)]
pub struct ParsedTlsResult {
    pub version: TlsVersion,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub sni: Option<Vec<u8>>,
}

impl TlsParseCache {
    pub fn new() -> Self {
        Self {
            cache: HighPerformanceCache::new(1000, Duration::from_secs(300)), // 5分钟TTL
        }
    }
    
    /// 计算载荷哈希
    fn calculate_payload_hash(&self, payload: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        payload.hash(&mut hasher);
        hasher.finish()
    }
    
    /// 获取解析结果
    pub fn get_parse_result(&self, payload: &[u8]) -> Option<ParsedTlsResult> {
        let hash = self.calculate_payload_hash(payload);
        self.cache.get(&hash)
    }
    
    /// 缓存解析结果
    pub fn cache_parse_result(&self, payload: &[u8], result: ParsedTlsResult) {
        let hash = self.calculate_payload_hash(payload);
        self.cache.insert(hash, result);
    }
    
    /// 获取缓存统计信息
    pub fn get_cache_stats(&self) -> CacheStats {
        self.cache.get_stats()
    }
    
    /// 清理过期条目
    pub fn cleanup(&self) {
        self.cache.cleanup_expired();
    }
}

impl Default for TlsParseCache {
    fn default() -> Self {
        Self::new()
    }
}

/// 指纹计算缓存
pub struct FingerprintCache {
    ja4_cache: HighPerformanceCache<u64, String>,
    ja3_cache: HighPerformanceCache<u64, String>,
}

impl FingerprintCache {
    pub fn new() -> Self {
        Self {
            ja4_cache: HighPerformanceCache::new(2000, Duration::from_secs(600)), // 10分钟TTL
            ja3_cache: HighPerformanceCache::new(2000, Duration::from_secs(600)),
        }
    }
    
    /// 计算指纹参数哈希
    fn calculate_fingerprint_hash(
        &self,
        version: TlsVersion,
        ciphers: &[u16],
        extensions: &[u16],
        elliptic_curves: &[u16],
        ec_point_formats: &[u8],
    ) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        
        // 组合所有参数进行哈希
        // 简化版本哈希
        match version {
            TlsVersion::Ssl30 => 0u8.hash(&mut hasher),
            TlsVersion::Tls10 => 1u8.hash(&mut hasher),
            TlsVersion::Tls11 => 2u8.hash(&mut hasher),
            TlsVersion::Tls12 => 3u8.hash(&mut hasher),
            TlsVersion::Tls13 => 4u8.hash(&mut hasher),
            _ => 5u8.hash(&mut hasher),
        }
        for &cipher in ciphers {
            cipher.hash(&mut hasher);
        }
        for &extension in extensions {
            extension.hash(&mut hasher);
        }
        for &curve in elliptic_curves {
            curve.hash(&mut hasher);
        }
        for &format in ec_point_formats {
            format.hash(&mut hasher);
        }
        
        hasher.finish()
    }
    
    /// 获取JA4指纹
    pub fn get_ja4(&self, version: TlsVersion, ciphers: &[u16], extensions: &[u16]) -> Option<String> {
        let hash = self.calculate_fingerprint_hash(version, ciphers, extensions, &[], &[]);
        self.ja4_cache.get(&hash)
    }
    
    /// 缓存JA4指纹
    pub fn cache_ja4(&self, version: TlsVersion, ciphers: &[u16], extensions: &[u16], ja4: String) {
        let hash = self.calculate_fingerprint_hash(version, ciphers, extensions, &[], &[]);
        self.ja4_cache.insert(hash, ja4);
    }
    
    /// 获取JA3指纹
    pub fn get_ja3(&self, version: TlsVersion, ciphers: &[u16], extensions: &[u16], elliptic_curves: &[u16], ec_point_formats: &[u8]) -> Option<String> {
        let hash = self.calculate_fingerprint_hash(version, ciphers, extensions, elliptic_curves, ec_point_formats);
        self.ja3_cache.get(&hash)
    }
    
    /// 缓存JA3指纹
    pub fn cache_ja3(&self, version: TlsVersion, ciphers: &[u16], extensions: &[u16], elliptic_curves: &[u16], ec_point_formats: &[u8], ja3: String) {
        let hash = self.calculate_fingerprint_hash(version, ciphers, extensions, elliptic_curves, ec_point_formats);
        self.ja3_cache.insert(hash, ja3);
    }
    
    /// 获取缓存统计信息
    pub fn get_stats(&self) -> (CacheStats, CacheStats) {
        (self.ja4_cache.get_stats(), self.ja3_cache.get_stats())
    }
    
    /// 清理过期条目
    pub fn cleanup(&self) {
        self.ja4_cache.cleanup_expired();
        self.ja3_cache.cleanup_expired();
    }
}

impl Default for FingerprintCache {
    fn default() -> Self {
        Self::new()
    }
}

/// 多级缓存系统
pub struct MultiLevelCache {
    l1_cache: HighPerformanceCache<u64, String>, // 快速缓存
    l2_cache: HighPerformanceCache<u64, String>, // 中等缓存
    l3_cache: HighPerformanceCache<u64, String>, // 慢速缓存
    stats: Arc<RwLock<MultiLevelCacheStats>>,
}

/// 多级缓存统计信息
#[derive(Debug, Default, Clone)]
pub struct MultiLevelCacheStats {
    pub l1_hits: u64,
    pub l2_hits: u64,
    pub l3_hits: u64,
    pub misses: u64,
    pub total_requests: u64,
}

impl MultiLevelCache {
    pub fn new() -> Self {
        Self {
            l1_cache: HighPerformanceCache::new(100, Duration::from_secs(60)),   // 1分钟TTL
            l2_cache: HighPerformanceCache::new(500, Duration::from_secs(300)),  // 5分钟TTL
            l3_cache: HighPerformanceCache::new(2000, Duration::from_secs(1800)), // 30分钟TTL
            stats: Arc::new(RwLock::new(MultiLevelCacheStats::default())),
        }
    }
    
    /// 获取值
    pub fn get(&self, key: &u64) -> Option<String> {
        let mut stats = self.stats.write();
        stats.total_requests += 1;
        
        // 尝试L1缓存
        if let Some(value) = self.l1_cache.get(key) {
            stats.l1_hits += 1;
            return Some(value);
        }
        
        // 尝试L2缓存
        if let Some(value) = self.l2_cache.get(key) {
            stats.l2_hits += 1;
            // 提升到L1缓存
            self.l1_cache.insert(*key, value.clone());
            return Some(value);
        }
        
        // 尝试L3缓存
        if let Some(value) = self.l3_cache.get(key) {
            stats.l3_hits += 1;
            // 提升到L1和L2缓存
            self.l1_cache.insert(*key, value.clone());
            self.l2_cache.insert(*key, value.clone());
            return Some(value);
        }
        
        stats.misses += 1;
        None
    }
    
    /// 插入值
    pub fn insert(&self, key: u64, value: String) {
        // 插入到所有级别的缓存
        self.l1_cache.insert(key, value.clone());
        self.l2_cache.insert(key, value.clone());
        self.l3_cache.insert(key, value);
    }
    
    /// 获取统计信息
    pub fn get_stats(&self) -> MultiLevelCacheStats {
        self.stats.read().clone()
    }
    
    /// 获取整体命中率
    pub fn get_overall_hit_rate(&self) -> f64 {
        let stats = self.stats.read();
        if stats.total_requests == 0 {
            0.0
        } else {
            (stats.l1_hits + stats.l2_hits + stats.l3_hits) as f64 / stats.total_requests as f64
        }
    }
    
    /// 清理所有缓存
    pub fn cleanup(&self) {
        self.l1_cache.cleanup_expired();
        self.l2_cache.cleanup_expired();
        self.l3_cache.cleanup_expired();
    }
}

impl Default for MultiLevelCache {
    fn default() -> Self {
        Self::new()
    }
}

/// 缓存管理器
pub struct CacheManager {
    tls_parse_cache: Arc<TlsParseCache>,
    fingerprint_cache: Arc<FingerprintCache>,
    multi_level_cache: Arc<MultiLevelCache>,
}

impl CacheManager {
    pub fn new() -> Self {
        Self {
            tls_parse_cache: Arc::new(TlsParseCache::new()),
            fingerprint_cache: Arc::new(FingerprintCache::new()),
            multi_level_cache: Arc::new(MultiLevelCache::new()),
        }
    }
    
    /// 获取TLS解析缓存
    pub fn get_tls_parse_cache(&self) -> Arc<TlsParseCache> {
        self.tls_parse_cache.clone()
    }
    
    /// 获取指纹缓存
    pub fn get_fingerprint_cache(&self) -> Arc<FingerprintCache> {
        self.fingerprint_cache.clone()
    }
    
    /// 获取多级缓存
    pub fn get_multi_level_cache(&self) -> Arc<MultiLevelCache> {
        self.multi_level_cache.clone()
    }
    
    /// 清理所有缓存
    pub fn cleanup_all(&self) {
        self.tls_parse_cache.cleanup();
        self.fingerprint_cache.cleanup();
        self.multi_level_cache.cleanup();
    }
    
    /// 获取所有缓存统计信息
    pub fn get_all_stats(&self) -> CacheManagerStats {
        let tls_stats = self.tls_parse_cache.get_cache_stats();
        let (ja4_stats, ja3_stats) = self.fingerprint_cache.get_stats();
        let multi_stats = self.multi_level_cache.get_stats();
        
        CacheManagerStats {
            tls_parse_stats: tls_stats,
            ja4_stats,
            ja3_stats,
            multi_level_stats: multi_stats,
        }
    }
}

#[derive(Debug)]
pub struct CacheManagerStats {
    pub tls_parse_stats: CacheStats,
    pub ja4_stats: CacheStats,
    pub ja3_stats: CacheStats,
    pub multi_level_stats: MultiLevelCacheStats,
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}
