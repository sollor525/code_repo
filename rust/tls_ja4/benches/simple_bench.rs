use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tls_ja4::{
    parse_client_hello_with_tls_parser,
    calculate_ja4_from_parsed_data,
    calculate_ja3_from_parsed_data,
    is_tls_packet,
};
use tls_parser::TlsVersion;

// 简单的TLS Client Hello数据包
fn create_simple_client_hello() -> Vec<u8> {
    vec![
        // TLS Record Header
        0x16, 0x03, 0x01, 0x00, 0x4a,
        // Handshake Header  
        0x01, 0x00, 0x00, 0x46,
        // TLS Version
        0x03, 0x03,
        // Random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        // Session ID length
        0x00,
        // Cipher suites length
        0x00, 0x08,
        // Cipher suites
        0x00, 0x2f, 0x00, 0x35, 0x00, 0x3c, 0x00, 0x3d,
        // Compression methods length
        0x01,
        // Compression method
        0x00,
        // Extensions length
        0x00, 0x1a,
        // Extensions
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
        0x00, 0x0d, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01, 0x04, 0x03,
    ]
}

fn bench_tls_parsing(c: &mut Criterion) {
    let client_hello = create_simple_client_hello();
    
    c.bench_function("parse_client_hello", |b| {
        b.iter(|| {
            let result = parse_client_hello_with_tls_parser(black_box(&client_hello));
            black_box(result)
        })
    });
    
    c.bench_function("is_tls_packet", |b| {
        b.iter(|| {
            let result = is_tls_packet(black_box(&client_hello));
            black_box(result)
        })
    });
}

fn bench_fingerprint_calculation(c: &mut Criterion) {
    let client_hello = create_simple_client_hello();
    
    // 解析一次以获得测试数据
    if let Some((version, cipher_suites, extensions, elliptic_curves, ec_point_formats, signature_algorithms)) = 
        parse_client_hello_with_tls_parser(&client_hello) {
        
        c.bench_function("calculate_ja4", |b| {
            b.iter(|| {
                let result = calculate_ja4_from_parsed_data(
                    black_box(version),
                    black_box(&cipher_suites),
                    black_box(&extensions),
                    black_box(&signature_algorithms),
                    black_box(None)
                );
                black_box(result)
            })
        });
        
        c.bench_function("calculate_ja3", |b| {
            b.iter(|| {
                let result = calculate_ja3_from_parsed_data(
                    black_box(version),
                    black_box(&cipher_suites),
                    black_box(&extensions),
                    black_box(&elliptic_curves),
                    black_box(&ec_point_formats)
                );
                black_box(result)
            })
        });
    }
}

criterion_group!(benches, bench_tls_parsing, bench_fingerprint_calculation);
criterion_main!(benches);
