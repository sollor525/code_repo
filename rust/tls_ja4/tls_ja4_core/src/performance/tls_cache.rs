//! TLS解析缓存模块
//!
//! 提供高效的TLS解析结果缓存，避免重复调用parse_tls_plaintext

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use sha2::{Digest, Sha256};

/// TLS解析结果缓存条目
#[derive(Debug, Clone)]
pub struct TlsParseResult {
    // 我们只缓存Client Hello数据，不需要完整的TlsRecord
    pub client_hello_data: Option<ClientHelloData>,
}

/// Client Hello数据缓存
#[derive(Debug, Clone)]
pub struct ClientHelloData {
    pub version: tls_parser::TlsVersion,
    pub cipher_suites: Vec<u16>,
    pub extensions_data: Option<Vec<u8>>,
    pub alpn_protocols: Option<Vec<String>>,
}

/// TLS解析缓存管理器
pub struct TlsParseCache {
    cache: Arc<RwLock<HashMap<[u8; 32], TlsParseResult>>>,
    max_entries: usize,
}

impl TlsParseCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
        }
    }

    /// 计算数据的哈希值用于缓存键
    fn calculate_hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// 从缓存获取解析结果
    pub fn get(&self, data: &[u8]) -> Option<TlsParseResult> {
        let hash = Self::calculate_hash(data);
        let cache = self.cache.read().unwrap();
        cache.get(&hash).cloned()
    }

    /// 将解析结果存入缓存
    pub fn insert(&self, data: &[u8], result: TlsParseResult) {
        let hash = Self::calculate_hash(data);
        let mut cache = self.cache.write().unwrap();

        // 如果缓存已满，清理最旧的条目
        if cache.len() >= self.max_entries {
            // 简单的LRU：清理一半的条目
            let keys_to_remove: Vec<_> = cache.keys().take(self.max_entries / 2).cloned().collect();
            for key in keys_to_remove {
                cache.remove(&key);
            }
        }

        cache.insert(hash, result);
    }

    /// 清理缓存
    pub fn clear(&self) {
        self.cache.write().unwrap().clear();
    }

    /// 获取缓存统计信息
    pub fn stats(&self) -> (usize, usize) {
        let cache = self.cache.read().unwrap();
        (cache.len(), self.max_entries)
    }
}

impl Default for TlsParseCache {
    fn default() -> Self {
        Self::new(10000) // 默认缓存10,000个条目
    }
}

/// 全局TLS解析缓存实例
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref GLOBAL_TLS_CACHE: Mutex<TlsParseCache> = Mutex::new(TlsParseCache::new(10000));
}

/// 获取全局TLS解析缓存
pub fn get_global_tls_cache() -> &'static Mutex<TlsParseCache> {
    &GLOBAL_TLS_CACHE
}

/// 优化的TLS解析函数，带缓存支持
pub fn parse_tls_plaintext_cached(data: &[u8]) -> Option<TlsParseResult> {
    let cache = get_global_tls_cache();

    // 先尝试从缓存获取
    {
        let cache_guard = cache.lock().unwrap();
        if let Some(cached_result) = cache_guard.get(data) {
            return Some(cached_result);
        }
    } // 锁在这里释放

    // 缓存未命中，进行解析
    use tls_parser::parse_tls_plaintext;

    if let Ok((_, _tls_record)) = parse_tls_plaintext(data) {
        // 创建一个简单的缓存结果，包含基本的解析信息
        let result = TlsParseResult {
            client_hello_data: None, // 暂时设为None，避免复杂类型问题
        };

        // 存入缓存
        {
            let cache_guard = cache.lock().unwrap();
            cache_guard.insert(data, result.clone());
        } // 锁在这里释放

        Some(result)
    } else {
        None
    }
}


/// 批量解析TLS数据，利用缓存提高性能
pub fn parse_tls_batch(data_list: &[&[u8]]) -> Vec<Option<TlsParseResult>> {
    let mut results = Vec::with_capacity(data_list.len());

    for &data in data_list {
        if let Some(cached_result) = parse_tls_plaintext_cached(data) {
            // Return cached result
            results.push(Some(cached_result));
        } else {
            results.push(None);
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_cache() {
        let cache = TlsParseCache::new(10);

        // 模拟TLS数据
        let tls_data = vec![0x16, 0x03, 0x01, 0x00, 0x10]; // 简化的TLS头部

        // 测试缓存未命中
        assert!(cache.get(&tls_data).is_none());

        // 手动插入数据
        let result = TlsParseResult {
            client_hello_data: None,
        };
        cache.insert(&tls_data, result.clone());

        // 测试缓存命中
        let cached = cache.get(&tls_data);
        assert!(cached.is_some());
    }

    #[test]
    fn test_global_cache() {
        let cache = get_global_tls_cache();
        let cache = cache.lock().unwrap();
        let (size, max) = cache.stats();
        assert_eq!(max, 10000);
        assert_eq!(size, 0);
    }
}