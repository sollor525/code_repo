//! 使用Criterion的性能基准测试
//!
//! 比较缓存与非缓存TLS解析的性能差异

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;
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

/// 基准测试：缓存命中性能
fn bench_cache_hit(c: &mut Criterion) {
    let data = create_test_client_hello();

    // 预热缓存
    let _ = parse_client_hello_with_tls_parser(&data);

    c.bench_function("cache_hit", |b| {
        b.iter(|| {
            black_box(parse_client_hello_with_tls_parser(black_box(&data)));
        });
    });
}

/// 基准测试：缓存未命中性能
fn bench_cache_miss(c: &mut Criterion) {
    // 清理缓存
    get_global_tls_cache().lock().unwrap().clear();

    let data = create_test_client_hello();

    c.bench_function("cache_miss", |b| {
        b.iter(|| {
            // 每次都清理缓存确保未命中
            get_global_tls_cache().lock().unwrap().clear();
            black_box(parse_client_hello_with_tls_parser(black_box(&data)));
        });
    });
}

/// 基准测试：不同数量数据包的解析性能
fn bench_batch_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_parsing");

    for size in [10, 50, 100, 500, 1000].iter() {
        let data_list = create_test_data_variants(*size);

        // 清理缓存进行非缓存测试
        get_global_tls_cache().lock().unwrap().clear();

        group.bench_with_input(
            BenchmarkId::new("without_cache", size),
            size,
            |b, _| {
                b.iter(|| {
                    for data in &data_list {
                        get_global_tls_cache().lock().unwrap().clear(); // 每次都清空缓存
                        black_box(parse_client_hello_with_tls_parser(black_box(data)));
                    }
                });
            },
        );

        // 清理缓存进行缓存测试
        get_global_tls_cache().lock().unwrap().clear();

        group.bench_with_input(
            BenchmarkId::new("with_cache", size),
            size,
            |b, _| {
                b.iter(|| {
                    for data in &data_list {
                        black_box(parse_client_hello_with_tls_parser(black_box(data)));
                    }
                });
            },
        );
    }

    group.finish();
}

/// 基准测试：重复解析相同数据的性能
fn bench_repeated_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("repeated_parsing");

    for iterations in [100, 500, 1000, 5000].iter() {
        let data = create_test_client_hello();

        // 清理缓存进行非缓存测试
        get_global_tls_cache().lock().unwrap().clear();

        group.bench_with_input(
            BenchmarkId::new("without_cache", iterations),
            iterations,
            |b, &iterations| {
                b.iter(|| {
                    for _ in 0..iterations {
                        get_global_tls_cache().lock().unwrap().clear(); // 每次都清空缓存
                        black_box(parse_client_hello_with_tls_parser(black_box(&data)));
                    }
                });
            },
        );

        // 清理缓存进行缓存测试
        get_global_tls_cache().lock().unwrap().clear();

        group.bench_with_input(
            BenchmarkId::new("with_cache", iterations),
            iterations,
            |b, &iterations| {
                b.iter(|| {
                    for _ in 0..iterations {
                        black_box(parse_client_hello_with_tls_parser(black_box(&data)));
                    }
                });
            },
        );
    }

    group.finish();
}

/// 基准测试：缓存操作开销
fn bench_cache_operations(c: &mut Criterion) {
    let data = create_test_client_hello();
    let cache = TlsParseCache::new(1000);

    c.bench_function("cache_insert", |b| {
        b.iter(|| {
            let result = TlsParseResult {
                client_hello_data: None,
            };
            cache.insert(black_box(&data), black_box(result));
        });
    });

    // 先插入一些数据
    for i in 0..100 {
        let mut test_data = data.clone();
        test_data.push(i as u8);
        let result = TlsParseResult {
            client_hello_data: None,
        };
        cache.insert(&test_data, result);
    }

    c.bench_function("cache_get", |b| {
        b.iter(|| {
            black_box(cache.get(black_box(&data)));
        });
    });
}

criterion_group!(
    benches,
    bench_cache_hit,
    bench_cache_miss,
    bench_batch_parsing,
    bench_repeated_parsing,
    bench_cache_operations
);
criterion_main!(benches);