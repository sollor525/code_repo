//! 性能优化模块
//!
//! 提供高性能的TLS解析、指纹计算和数据处理功能

pub mod tls_parser_optimized;
pub mod fingerprint_optimized;
pub mod memory_pool;
pub mod parallel_processing;
pub mod cache_optimized;
pub mod simd_utils;

// 避免重名问题，使用具体的重导出
pub use tls_parser_optimized::{
    OptimizedTlsParser, ParsedTlsData, BatchTlsParser
};
pub use simd_utils::{
    find_byte_simd, memcmp_simd, is_grease_batch_simd,
    filter_grease_simd, sort_u16_simd, join_u16_simd,
    calculate_hash_simd
};
pub use fingerprint_optimized::{
    UltraFastJa4Calculator, UltraFastJa3Calculator, 
    BatchFingerprintCalculator, PooledFingerprintCalculator
};
pub use memory_pool::{
    HighPerformanceMemoryPool, ThreadLocalMemoryPool, 
    MemoryPoolManager, PooledBuffer
};
pub use parallel_processing::{
    ParallelTlsProcessor, ProcessingStats, TlsProcessingTask, 
    ProcessingResult, BatchParallelProcessor, StreamingParallelProcessor,
    PerformanceMonitor, PerformanceSample, PerformanceReport
};
pub use cache_optimized::{
    HighPerformanceCache, CacheEntry, CacheStats, TlsParseCache,
    ParsedTlsResult, FingerprintCache, MultiLevelCache, 
    MultiLevelCacheStats, CacheManager, CacheManagerStats
};
