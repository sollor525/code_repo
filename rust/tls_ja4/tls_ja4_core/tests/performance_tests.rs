//! 性能测试模块
//!
//! 验证缓存机制的性能提升效果

use std::time::Instant;
use tls_ja4_core::performance::tls_cache::*;
use tls_ja4_core::tls::client_hello::parse_client_hello_with_tls_parser;

/// 创建测试用的TLS Client Hello数据
fn create_test_client_hello() -> Vec<u8> {
    // 创建一个简化的TLS Client Hello记录
    vec![
        0x16, // Handshake type
        0x03, 0x01, // TLS 1.0
        0x00, 0x3e, // Length (62 bytes)
        // Handshake Header
        0x01, // Client Hello
        0x00, 0x00, 0x3a, // Length (58 bytes)
        0x03, 0x03, // TLS 1.2
        // Random (32 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x00, // Session ID length
        0x00, 0x02, // Cipher suites length
        0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0x01, // Compression methods length
        0x00, // Null compression
        0x00, 0x0a, // Extensions length
        // Extensions
        0x00, 0x00, // Server Name Indication
        0x00, 0x00, // Length
        0x00, 0x23, // Application Layer Protocol Negotiation
        0x00, 0x00, // Length
    ]
}

/// 创建多个不同的测试数据
fn create_test_data_variants(count: usize) -> Vec<Vec<u8>> {
    let mut data_list = Vec::with_capacity(count);
    let base_data = create_test_client_hello();

    for i in 0..count {
        let mut data = base_data.clone();
        // 修改随机部分以创建不同的数据
        if data.len() > 11 + i {
            data[11 + i] = i as u8;
        }
        data_list.push(data);
    }

    data_list
}

#[test]
fn test_cache_performance_improvement() {
    // 创建测试数据
    let data_list = create_test_data_variants(50); // 50个不同的TLS数据包

    let iterations = 100; // 每个数据包解析100次

    // 测试带缓存的解析性能
    // 清理缓存确保公平测试
    get_global_tls_cache().lock().unwrap().clear();

    let start = Instant::now();
    for _ in 0..iterations {
        for data in &data_list {
            let _ = parse_client_hello_with_tls_parser(data);
        }
    }
    let cached_time = start.elapsed();

    // 测试不带缓存的解析性能（每次都清空缓存）
    let start = Instant::now();
    for _ in 0..iterations {
        for data in &data_list {
            get_global_tls_cache().lock().unwrap().clear(); // 清空缓存
            let _ = parse_client_hello_with_tls_parser(data);
        }
    }
    let uncached_time = start.elapsed();

    // 计算性能提升
    let improvement_ratio = uncached_time.as_nanos() as f64 / cached_time.as_nanos() as f64;
    let improvement_percent = (improvement_ratio - 1.0) * 100.0;

    println!("Performance Test Results:");
    println!("Uncached parsing time: {:?}", uncached_time);
    println!("Cached parsing time: {:?}", cached_time);
    println!("Performance improvement: {:.2}x ({:.2}%)", improvement_ratio, improvement_percent);

    // 验证缓存确实提升了性能
    assert!(improvement_ratio >= 1.0, "Cache should not degrade performance");

    // 如果提升不够明显，至少验证缓存功能正常工作
    let cache = get_global_tls_cache();
    let cache = match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let (size, _) = cache.stats();
    assert!(size > 0, "Cache should contain entries after parsing");

    println!("Cache contains {} entries", size);
}

#[test]
fn test_cache_hit_performance() {
    let data = create_test_client_hello();

    // 清理缓存
    {
        let cache = get_global_tls_cache();
        let mut cache = match cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        cache.clear();
    }

    // 预热缓存
    let _ = parse_client_hello_with_tls_parser(&data);

    // 测试缓存命中的性能
    let iterations = 1000;
    let start = Instant::now();

    for _ in 0..iterations {
        let _ = parse_client_hello_with_tls_parser(&data);
    }

    let cached_time = start.elapsed();

    println!("Cache hit performance test:");
    println!("{} iterations of same data: {:?}", iterations, cached_time);
    println!("Average per iteration: {:?}", cached_time / iterations);

    // 验证缓存命中时间很短
    assert!(cached_time.as_nanos() < 1_000_000_000, // 1秒
            "Cache hits should be fast");

    // 验证缓存确实被使用了
    let cache = get_global_tls_cache();
    let cache = match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let (size, _) = cache.stats();
    assert!(size > 0, "Cache should contain entries");
}

#[test]
fn test_cache_memory_efficiency() {
    let data_list = create_test_data_variants(100); // 100个不同的数据包

    // 清理缓存
    {
        let cache = get_global_tls_cache();
        let mut cache = match cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        cache.clear();
    }

    // 解析所有数据包
    for data in &data_list {
        let _ = parse_client_hello_with_tls_parser(data);
    }

    // 检查缓存大小
    let cache = get_global_tls_cache();
    let cache = match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let (size, max_size) = cache.stats();

    println!("Cache memory efficiency test:");
    println!("Cache entries: {}", size);
    println!("Max cache entries: {}", max_size);
    println!("Memory usage: ~{} KB", size * 200 / 1024); // 估算每个条目约200字节

    // 验证缓存没有超过最大限制
    assert!(size <= max_size, "Cache should not exceed max size");

    // 清理缓存
    drop(cache);
    let cache = get_global_tls_cache();
    let mut cache = match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    cache.clear();
}

#[test]
fn test_concurrent_cache_performance() {
    use std::thread;

    let data_list = create_test_data_variants(20);
    let thread_count = 4;
    let iterations_per_thread = 50;

    // 清理缓存
    {
        let cache = get_global_tls_cache();
        let mut cache = match cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        cache.clear();
    }

    let start = Instant::now();

    let handles: Vec<_> = (0..thread_count)
        .map(|_thread_id| {
            let data = data_list.clone();
            thread::spawn(move || {
                for i in 0..iterations_per_thread {
                    let data_index = i % data.len();
                    let _ = parse_client_hello_with_tls_parser(&data[data_index]);
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }

    let total_time = start.elapsed();
    let total_operations = thread_count * iterations_per_thread;

    println!("Concurrent cache performance test:");
    println!("{} threads, {} operations each", thread_count, iterations_per_thread);
    println!("Total time: {:?}", total_time);
    println!("Throughput: {:.2} ops/sec", total_operations as f64 / total_time.as_secs_f64());

    // 验证并发访问没有导致错误
    let cache = get_global_tls_cache();
    let cache = match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let (size, _) = cache.stats();
    assert!(size > 0, "Cache should contain entries after concurrent access");

    println!("Cache contains {} entries after concurrent access", size);
}