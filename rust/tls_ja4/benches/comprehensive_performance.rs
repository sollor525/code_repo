use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use tls_ja4::performance::*;
use tls_ja4::fingerprint::{
    calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data,
    calculate_ja4_optimized, calculate_ja3_optimized,
};
use tls_parser::TlsVersion;
// use std::time::Duration;

fn generate_test_data() -> (TlsVersion, Vec<u16>, Vec<u16>, Vec<u16>, Vec<u8>) {
    let version = TlsVersion::Tls13;
    let ciphers = (0x1301..=0x130f).collect::<Vec<u16>>();
    let extensions = (0x0000..=0x0010).collect::<Vec<u16>>();
    let elliptic_curves = vec![29, 23, 30, 25, 24];
    let payload = b"comprehensive performance test payload for TLS fingerprint calculation with optimization";
    
    (version, ciphers, extensions, elliptic_curves, payload.to_vec())
}

fn benchmark_original_vs_optimized(c: &mut Criterion) {
    let (version, ciphers, extensions, elliptic_curves, payload) = generate_test_data();
    let ec_point_formats = vec![0, 1, 2];
    
    let mut group = c.benchmark_group("original_vs_optimized");
    
    // 原始实现
    group.bench_function("ja4_original", |b| {
        b.iter(|| {
            black_box(calculate_ja4_from_parsed_data(
                version,
                &ciphers,
                &extensions,
                &[],
                &payload,
            ))
        })
    });
    
    // 优化实现
    group.bench_function("ja4_optimized", |b| {
        b.iter(|| {
            black_box(calculate_ja4_optimized(
                version,
                &ciphers,
                &extensions,
                &[],
                &payload,
            ))
        })
    });
    
    // 原始JA3实现
    group.bench_function("ja3_original", |b| {
        b.iter(|| {
            black_box(calculate_ja3_from_parsed_data(
                version,
                &ciphers,
                &extensions,
                &elliptic_curves,
                &ec_point_formats,
            ))
        })
    });
    
    // 优化JA3实现
    group.bench_function("ja3_optimized", |b| {
        b.iter(|| {
            black_box(calculate_ja3_optimized(
                version,
                &ciphers,
                &extensions,
                &elliptic_curves,
                &ec_point_formats,
            ))
        })
    });
    
    group.finish();
}

fn benchmark_ultra_fast_calculators(c: &mut Criterion) {
    let (version, ciphers, extensions, elliptic_curves, payload) = generate_test_data();
    let ec_point_formats = vec![0, 1, 2];
    
    let mut group = c.benchmark_group("ultra_fast_calculators");
    
    // 超快速JA4计算器
    group.bench_function("ja4_ultra_fast", |b| {
        let mut calculator = UltraFastJa4Calculator::new();
        b.iter(|| {
            black_box(calculator.calculate_ja4_ultra_fast(
                version,
                &ciphers,
                &extensions,
                &[],
                &payload,
            ))
        })
    });
    
    // 超快速JA3计算器
    group.bench_function("ja3_ultra_fast", |b| {
        let mut calculator = UltraFastJa3Calculator::new();
        b.iter(|| {
            black_box(calculator.calculate_ja3_ultra_fast(
                version,
                &ciphers,
                &extensions,
                &elliptic_curves,
                &ec_point_formats,
            ))
        })
    });
    
    group.finish();
}

fn benchmark_memory_pool_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_pool_performance");
    
    // 内存池性能测试
    group.bench_function("memory_pool_allocations", |b| {
        let pool = HighPerformanceMemoryPool::new();
        b.iter(|| {
            let buffer = pool.get_small_buffer();
            pool.return_small_buffer(buffer);
        })
    });
    
    // 线程本地内存池
    group.bench_function("thread_local_pool", |b| {
        let mut pool = ThreadLocalMemoryPool::new();
        b.iter(|| {
            let buffer = pool.get_buffer(256);
            pool.return_buffer(buffer);
        })
    });
    
    // 标准分配对比
    group.bench_function("standard_allocation", |b| {
        b.iter(|| {
            let buffer: Vec<u8> = Vec::with_capacity(256);
            black_box(buffer);
        })
    });
    
    group.finish();
}

fn benchmark_parallel_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_processing");
    
    // 生成测试任务
    let tasks: Vec<TlsProcessingTask> = (0..1000)
        .map(|i| TlsProcessingTask {
            payload: generate_test_data().4,
            task_id: i,
            timestamp: std::time::Instant::now(),
        })
        .collect();
    
    // 并行处理
    group.bench_function("parallel_processing", |b| {
        let processor = ParallelTlsProcessor::new();
        b.iter(|| {
            black_box(processor.process_parallel(tasks.clone()))
        })
    });
    
    // 批量并行处理
    group.bench_function("batch_parallel_processing", |b| {
        let processor = BatchParallelProcessor::new(100);
        b.iter(|| {
            black_box(processor.process_adaptive(tasks.clone()))
        })
    });
    
    group.finish();
}

fn benchmark_cache_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_performance");
    
    // TLS解析缓存
    group.bench_function("tls_parse_cache", |b| {
        let cache = TlsParseCache::new();
        let payload = generate_test_data().4;
        let result = ParsedTlsResult {
            version: TlsVersion::Tls13,
            ciphers: vec![0x1301, 0x1302],
            extensions: vec![0x000a, 0x000b],
            elliptic_curves: vec![29, 23],
            ec_point_formats: vec![0, 1],
            signature_algorithms: vec![0x0403, 0x0503],
            alpn_protocols: vec![b"http/1.1".to_vec()],
            sni: Some(b"example.com".to_vec()),
        };
        
        cache.cache_parse_result(&payload, result);
        
        b.iter(|| {
            black_box(cache.get_parse_result(&payload))
        })
    });
    
    // 指纹缓存
    group.bench_function("fingerprint_cache", |b| {
        let cache = FingerprintCache::new();
        let (version, ciphers, extensions, elliptic_curves, _) = generate_test_data();
        let ec_point_formats = vec![0, 1, 2];
        
        cache.cache_ja4(version, &ciphers, &extensions, "t130d20h0_0_37effddb63e8_0".to_string());
        cache.cache_ja3(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats, "af236ae680d7741a172c340dbd5ca7dacff8e684d303b57a60c2ca142ef9a017".to_string());
        
        b.iter(|| {
            let ja4 = black_box(cache.get_ja4(version, &ciphers, &extensions));
            let ja3 = black_box(cache.get_ja3(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats));
            (ja4, ja3)
        })
    });
    
    // 多级缓存
    group.bench_function("multi_level_cache", |b| {
        let cache = MultiLevelCache::new();
        let key = 12345u64;
        let value = "test_value".to_string();
        
        cache.insert(key, value);
        
        b.iter(|| {
            black_box(cache.get(&key))
        })
    });
    
    group.finish();
}

fn benchmark_throughput_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput_scaling");
    
    for size in [10, 100, 1000, 10000].iter() {
        let tasks: Vec<TlsProcessingTask> = (0..*size)
            .map(|i| TlsProcessingTask {
                payload: generate_test_data().4,
                task_id: i,
                timestamp: std::time::Instant::now(),
            })
            .collect();
        
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::new("batch_processing", size), size, |b, _| {
            let processor = BatchParallelProcessor::new(100);
            b.iter(|| {
                black_box(processor.process_adaptive(tasks.clone()))
            })
        });
    }
    
    group.finish();
}

fn benchmark_memory_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_efficiency");
    
    // 内存池效率测试
    group.bench_function("memory_pool_efficiency", |b| {
        let pool = HighPerformanceMemoryPool::new();
        b.iter(|| {
            for _ in 0..1000 {
                let buffer = pool.get_small_buffer();
                pool.return_small_buffer(buffer);
            }
        })
    });
    
    // 标准分配效率测试
    group.bench_function("standard_allocation_efficiency", |b| {
        b.iter(|| {
            for _ in 0..1000 {
                let buffer: Vec<u8> = Vec::with_capacity(256);
                black_box(buffer);
            }
        })
    });
    
    group.finish();
}

fn benchmark_simd_optimizations(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_optimizations");
    
    // SIMD优化的字节搜索
    group.bench_function("simd_byte_search", |b| {
        let haystack = vec![0u8; 1000];
        let needle = 42u8;
        
        b.iter(|| {
            unsafe {
                black_box(simd_utils::find_byte_simd(&haystack, needle))
            }
        })
    });
    
    // 标量字节搜索对比
    group.bench_function("scalar_byte_search", |b| {
        let haystack = vec![0u8; 1000];
        let needle = 42u8;
        
        b.iter(|| {
            black_box(haystack.iter().position(|&b| b == needle))
        })
    });
    
    // SIMD内存比较
    group.bench_function("simd_memcmp", |bench| {
        let a = vec![1u8; 1000];
        let b = vec![1u8; 1000];
        
        bench.iter(|| {
            unsafe {
                black_box(simd_utils::memcmp_simd(&a, &b))
            }
        })
    });
    
    // 标准内存比较
    group.bench_function("standard_memcmp", |bench| {
        let a = vec![1u8; 1000];
        let b = vec![1u8; 1000];
        
        bench.iter(|| {
            black_box(a == b)
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_original_vs_optimized,
    benchmark_ultra_fast_calculators,
    benchmark_memory_pool_performance,
    benchmark_parallel_processing,
    benchmark_cache_performance,
    benchmark_throughput_scaling,
    benchmark_memory_efficiency,
    benchmark_simd_optimizations
);

criterion_main!(benches);
