use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use tls_ja4::fingerprint::{
    calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data,
    calculate_ja4_optimized, calculate_ja3_optimized,
    OptimizedFingerprintCalculator
};
use tls_parser::TlsVersion;
// use std::time::Duration;

fn generate_test_data() -> (TlsVersion, Vec<u16>, Vec<u16>, Vec<u16>, Vec<u8>) {
    let version = TlsVersion::Tls13;
    let ciphers = (0x1301..=0x130f).collect::<Vec<u16>>();
    let extensions = (0x0000..=0x0010).collect::<Vec<u16>>();
    let elliptic_curves = vec![29, 23, 30, 25, 24];
    let payload = b"performance test payload for TLS fingerprint calculation";
    
    (version, ciphers, extensions, elliptic_curves, payload.to_vec())
}

fn benchmark_ja4_original(c: &mut Criterion) {
    let (version, ciphers, extensions, _, payload) = generate_test_data();
    
    c.bench_function("ja4_original", |b| {
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
}

fn benchmark_ja4_optimized(c: &mut Criterion) {
    let (version, ciphers, extensions, _, payload) = generate_test_data();
    
    c.bench_function("ja4_optimized", |b| {
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
}

fn benchmark_ja3_original(c: &mut Criterion) {
    let (version, ciphers, extensions, elliptic_curves, _) = generate_test_data();
    let ec_point_formats = vec![0, 1, 2];
    
    c.bench_function("ja3_original", |b| {
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
}

fn benchmark_ja3_optimized(c: &mut Criterion) {
    let (version, ciphers, extensions, elliptic_curves, _) = generate_test_data();
    let ec_point_formats = vec![0, 1, 2];
    
    c.bench_function("ja3_optimized", |b| {
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
}

fn benchmark_memory_pooled(c: &mut Criterion) {
    let (version, ciphers, extensions, elliptic_curves, payload) = generate_test_data();
    let ec_point_formats = vec![0, 1, 2];
    let mut calculator = OptimizedFingerprintCalculator::new();
    
    c.bench_function("memory_pooled", |b| {
        b.iter(|| {
            let ja4 = black_box(calculator.calculate_ja4_pooled(
                version,
                &ciphers,
                &extensions,
                &payload,
            ));
            let ja3 = black_box(calculator.calculate_ja3_pooled(
                version,
                &ciphers,
                &extensions,
                &elliptic_curves,
                &ec_point_formats,
            ));
            (ja4, ja3)
        })
    });
}

fn benchmark_batch_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_processing");
    
    for size in [10, 100, 1000].iter() {
        let test_data = (0..*size)
            .map(|_| generate_test_data())
            .collect::<Vec<_>>();
        
        group.bench_with_input(BenchmarkId::new("batch", size), size, |b, _| {
            b.iter(|| {
                // 简化的批量计算测试
                for (version, ciphers, extensions, elliptic_curves, payload) in &test_data {
                    let _ja4 = calculate_ja4_optimized(*version, ciphers, extensions, &[], payload);
                    let _ja3 = calculate_ja3_optimized(*version, ciphers, extensions, elliptic_curves, &[]);
                }
            })
        });
    }
    
    group.finish();
}

fn benchmark_different_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("different_sizes");
    
    for size in [5, 20, 50, 100].iter() {
        let ciphers = (0x1301..=0x1301 + *size as u16).collect::<Vec<u16>>();
        let extensions = (0x0000..=*size as u16).collect::<Vec<u16>>();
        let version = TlsVersion::Tls13;
        let payload = b"test payload";
        
        group.bench_with_input(BenchmarkId::new("ja4_size", size), size, |b, _| {
            b.iter(|| {
                black_box(calculate_ja4_optimized(
                    version,
                    &ciphers,
                    &extensions,
                    &[],
                    payload,
                ))
            })
        });
    }
    
    group.finish();
}

fn benchmark_string_operations(c: &mut Criterion) {
    let ciphers = (0x1301..=0x130f).collect::<Vec<u16>>();
    
    c.bench_function("string_join_original", |b| {
        b.iter(|| {
            let result = ciphers.iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(",");
            black_box(result)
        })
    });
    
    c.bench_function("string_join_optimized", |b| {
        b.iter(|| {
            let mut result = String::with_capacity(ciphers.len() * 6);
            for (i, &cipher) in ciphers.iter().enumerate() {
                if i > 0 { result.push(','); }
                use std::fmt::Write;
                write!(result, "{}", cipher).unwrap();
            }
            black_box(result)
        })
    });
}

criterion_group!(
    benches,
    benchmark_ja4_original,
    benchmark_ja4_optimized,
    benchmark_ja3_original,
    benchmark_ja3_optimized,
    benchmark_memory_pooled,
    benchmark_batch_processing,
    benchmark_different_sizes,
    benchmark_string_operations
);

criterion_main!(benches);
