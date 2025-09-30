//! 内存池优化模块
//! 
//! 提供高性能的内存池管理，减少内存分配和垃圾回收开销

use std::sync::Arc;
use std::collections::VecDeque;
use parking_lot::Mutex;

/// 高性能内存池
pub struct HighPerformanceMemoryPool {
    // 不同大小的缓冲区池
    small_buffers: Arc<Mutex<VecDeque<Vec<u8>>>>,
    medium_buffers: Arc<Mutex<VecDeque<Vec<u8>>>>,
    large_buffers: Arc<Mutex<VecDeque<Vec<u8>>>>,
    // 字符串池
    string_pool: Arc<Mutex<VecDeque<String>>>,
    // 统计信息
    stats: Arc<Mutex<PoolStats>>,
}

/// 内存池统计信息
#[derive(Debug, Default, Clone)]
pub struct PoolStats {
    pub allocations: u64,
    pub deallocations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl HighPerformanceMemoryPool {
    pub fn new() -> Self {
        Self {
            small_buffers: Arc::new(Mutex::new(VecDeque::new())),
            medium_buffers: Arc::new(Mutex::new(VecDeque::new())),
            large_buffers: Arc::new(Mutex::new(VecDeque::new())),
            string_pool: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(Mutex::new(PoolStats::default())),
        }
    }
    
    /// 获取小缓冲区 (<= 256 bytes)
    pub fn get_small_buffer(&self) -> Vec<u8> {
        let mut pool = self.small_buffers.lock();
        if let Some(mut buffer) = pool.pop_front() {
            buffer.clear();
            self.stats.lock().cache_hits += 1;
            buffer
        } else {
            self.stats.lock().cache_misses += 1;
            self.stats.lock().allocations += 1;
            Vec::with_capacity(256)
        }
    }
    
    /// 获取中等缓冲区 (257-1024 bytes)
    pub fn get_medium_buffer(&self) -> Vec<u8> {
        let mut pool = self.medium_buffers.lock();
        if let Some(mut buffer) = pool.pop_front() {
            buffer.clear();
            self.stats.lock().cache_hits += 1;
            buffer
        } else {
            self.stats.lock().cache_misses += 1;
            self.stats.lock().allocations += 1;
            Vec::with_capacity(1024)
        }
    }
    
    /// 获取大缓冲区 (> 1024 bytes)
    pub fn get_large_buffer(&self) -> Vec<u8> {
        let mut pool = self.large_buffers.lock();
        if let Some(mut buffer) = pool.pop_front() {
            buffer.clear();
            self.stats.lock().cache_hits += 1;
            buffer
        } else {
            self.stats.lock().cache_misses += 1;
            self.stats.lock().allocations += 1;
            Vec::with_capacity(4096)
        }
    }
    
    /// 获取字符串缓冲区
    pub fn get_string_buffer(&self) -> String {
        let mut pool = self.string_pool.lock();
        if let Some(mut string) = pool.pop_front() {
            string.clear();
            self.stats.lock().cache_hits += 1;
            string
        } else {
            self.stats.lock().cache_misses += 1;
            self.stats.lock().allocations += 1;
            String::with_capacity(512)
        }
    }
    
    /// 返回小缓冲区
    pub fn return_small_buffer(&self, mut buffer: Vec<u8>) {
        if buffer.capacity() <= 256 {
            buffer.clear();
            let mut pool = self.small_buffers.lock();
            if pool.len() < 100 { // 限制池大小
                pool.push_back(buffer);
            }
            self.stats.lock().deallocations += 1;
        }
    }
    
    /// 返回中等缓冲区
    pub fn return_medium_buffer(&self, mut buffer: Vec<u8>) {
        if buffer.capacity() <= 1024 {
            buffer.clear();
            let mut pool = self.medium_buffers.lock();
            if pool.len() < 50 {
                pool.push_back(buffer);
            }
            self.stats.lock().deallocations += 1;
        }
    }
    
    /// 返回大缓冲区
    pub fn return_large_buffer(&self, mut buffer: Vec<u8>) {
        if buffer.capacity() <= 4096 {
            buffer.clear();
            let mut pool = self.large_buffers.lock();
            if pool.len() < 20 {
                pool.push_back(buffer);
            }
            self.stats.lock().deallocations += 1;
        }
    }
    
    /// 返回字符串缓冲区
    pub fn return_string_buffer(&self, mut string: String) {
        if string.capacity() <= 1024 {
            string.clear();
            let mut pool = self.string_pool.lock();
            if pool.len() < 50 {
                pool.push_back(string);
            }
            self.stats.lock().deallocations += 1;
        }
    }
    
    /// 获取统计信息
    pub fn get_stats(&self) -> PoolStats {
        self.stats.lock().clone()
    }
    
    /// 清理内存池
    pub fn cleanup(&self) {
        self.small_buffers.lock().clear();
        self.medium_buffers.lock().clear();
        self.large_buffers.lock().clear();
        self.string_pool.lock().clear();
    }
}

impl Default for HighPerformanceMemoryPool {
    fn default() -> Self {
        Self::new()
    }
}

/// 线程本地内存池
pub struct ThreadLocalMemoryPool {
    small_buffers: Vec<Vec<u8>>,
    medium_buffers: Vec<Vec<u8>>,
    large_buffers: Vec<Vec<u8>>,
    string_buffers: Vec<String>,
}

impl ThreadLocalMemoryPool {
    pub fn new() -> Self {
        Self {
            small_buffers: Vec::new(),
            medium_buffers: Vec::new(),
            large_buffers: Vec::new(),
            string_buffers: Vec::new(),
        }
    }
    
    /// 获取缓冲区
    pub fn get_buffer(&mut self, size: usize) -> Vec<u8> {
        let capacity = if size <= 256 {
            if let Some(mut buffer) = self.small_buffers.pop() {
                buffer.clear();
                return buffer;
            }
            256
        } else if size <= 1024 {
            if let Some(mut buffer) = self.medium_buffers.pop() {
                buffer.clear();
                return buffer;
            }
            1024
        } else {
            if let Some(mut buffer) = self.large_buffers.pop() {
                buffer.clear();
                return buffer;
            }
            4096
        };
        
        Vec::with_capacity(capacity)
    }
    
    /// 返回缓冲区
    pub fn return_buffer(&mut self, mut buffer: Vec<u8>) {
        let capacity = buffer.capacity();
        buffer.clear();
        
        if capacity <= 256 && self.small_buffers.len() < 20 {
            self.small_buffers.push(buffer);
        } else if capacity <= 1024 && self.medium_buffers.len() < 10 {
            self.medium_buffers.push(buffer);
        } else if capacity <= 4096 && self.large_buffers.len() < 5 {
            self.large_buffers.push(buffer);
        }
    }
    
    /// 获取字符串缓冲区
    pub fn get_string_buffer(&mut self) -> String {
        if let Some(mut string) = self.string_buffers.pop() {
            string.clear();
            string
        } else {
            String::with_capacity(512)
        }
    }
    
    /// 返回字符串缓冲区
    pub fn return_string_buffer(&mut self, mut string: String) {
        string.clear();
        if self.string_buffers.len() < 10 {
            self.string_buffers.push(string);
        }
    }
}

impl Default for ThreadLocalMemoryPool {
    fn default() -> Self {
        Self::new()
    }
}

/// 内存池管理器
pub struct MemoryPoolManager {
    global_pool: Arc<HighPerformanceMemoryPool>,
    thread_local_pools: Arc<Mutex<Vec<ThreadLocalMemoryPool>>>,
}

impl MemoryPoolManager {
    pub fn new() -> Self {
        Self {
            global_pool: Arc::new(HighPerformanceMemoryPool::new()),
            thread_local_pools: Arc::new(Mutex::new(Vec::new())),
        }
    }
    
    /// 获取线程本地池
    pub fn get_thread_local_pool(&self) -> ThreadLocalMemoryPool {
        ThreadLocalMemoryPool::new()
    }
    
    /// 获取全局池
    pub fn get_global_pool(&self) -> Arc<HighPerformanceMemoryPool> {
        self.global_pool.clone()
    }
    
    /// 清理所有池
    pub fn cleanup_all(&self) {
        self.global_pool.cleanup();
        self.thread_local_pools.lock().clear();
    }
    
    /// 获取全局统计信息
    pub fn get_global_stats(&self) -> PoolStats {
        self.global_pool.get_stats()
    }
}

impl Default for MemoryPoolManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 内存池包装器，提供便捷的API
pub struct PooledBuffer<T> 
where
    T: Clone,
{
    data: T,
    #[allow(dead_code)]
    pool: Arc<HighPerformanceMemoryPool>,
}

impl<T> PooledBuffer<T> 
where
    T: Clone,
{
    pub fn new(data: T, pool: Arc<HighPerformanceMemoryPool>) -> Self {
        Self { data, pool }
    }
    
    pub fn get(&self) -> &T {
        &self.data
    }
    
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<T> Drop for PooledBuffer<T> 
where
    T: Clone,
{
    fn drop(&mut self) {
        // 通用Drop实现，不进行特殊处理
    }
}
