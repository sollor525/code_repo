use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::time::Duration;
use tls_ja4::{
    Config, 
    parse_client_hello_with_tls_parser,
    calculate_ja4_from_parsed_data,
    calculate_ja4b_from_parsed_data,
    calculate_ja4c_from_parsed_data,
    calculate_ja3_from_parsed_data,
    is_grease_value,
    is_tls_packet,
    parse_vlan_tags,
    extract_tls_data_from_packet,
    process_pcap_file,
    load_config,
    generate_session_key,
    extract_alpn_from_extensions,
};
use tls_parser::TlsVersion;

// 创建真实的TLS Client Hello数据包
fn create_realistic_client_hello() -> Vec<u8> {
    // 基于真实的TLS 1.3 Client Hello数据包
    vec![
        // TLS Record Header (5 bytes)
        0x16, 0x03, 0x01, 0x02, 0x00, // Content Type: Handshake, Version: TLS 1.0, Length: 512
        
        // Handshake Header (4 bytes)
        0x01, 0x00, 0x01, 0xfc, // Handshake Type: Client Hello, Length: 508
        
        // Client Hello
        0x03, 0x03, // Version: TLS 1.2
        
        // Random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        
        // Session ID
        0x20, // Session ID Length: 32
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        
        // Cipher Suites
        0x00, 0x20, // Cipher Suites Length: 32
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2c,
        0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8,
        0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
        0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23,
        
        // Compression Methods
        0x01, 0x00, // Compression Methods Length: 1, Method: null
        
        // Extensions
        0x01, 0x55, // Extensions Length: 341
        
        // Server Name Indication (SNI)
        0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00,
        0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
        0x73, 0x74,
        
        // Supported Groups
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d,
        0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
        
        // EC Point Formats
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
        
        // Signature Algorithms
        0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x04, 0x03,
        0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
        0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04,
        0x08, 0x05, 0x08, 0x06,
        
        // Supported Versions
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
        
        // Key Share
        0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d,
        0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58,
        0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91,
        0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e,
        0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16,
        0x62, 0x54,
        
        // Application Layer Protocol Negotiation (ALPN)
        0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08, 0x68,
        0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31,
        
        // Padding to make it realistic size
        0x00, 0x15, 0x00, 0x92, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

// 创建不同大小的Client Hello数据包
fn create_client_hello_variants() -> Vec<(String, Vec<u8>)> {
    let base = create_realistic_client_hello();
    
    vec![
        ("small".to_string(), base[..200.min(base.len())].to_vec()),
        ("medium".to_string(), base[..300.min(base.len())].to_vec()),
        ("large".to_string(), base.clone()),
        ("extra_large".to_string(), {
            let mut large = base.clone();
            // 添加更多扩展来创建更大的数据包
            large.extend_from_slice(&[0x00; 1000]);
            large
        }),
    ]
}

// 基准测试：TLS解析性能
fn bench_tls_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("tls_parsing");
    group.measurement_time(Duration::from_secs(10));
    
    let client_hellos = create_client_hello_variants();
    
    // 测试parse_client_hello_with_tls_parser函数
    for (name, client_hello) in &client_hellos {
        group.throughput(Throughput::Bytes(client_hello.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("parse_client_hello", name), 
            client_hello, 
            |b, data| {
                b.iter(|| {
                    let result = parse_client_hello_with_tls_parser(black_box(data));
                    black_box(result)
                })
            }
        );
    }
    
    // 测试TLS检测函数
    for (name, client_hello) in &client_hellos {
        group.throughput(Throughput::Bytes(client_hello.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("is_tls_packet", name), 
            client_hello, 
            |b, data| {
                b.iter(|| {
                    let result = is_tls_packet(black_box(data));
                    black_box(result)
                })
            }
        );
    }
    
    group.finish();
}

// 基准测试：JA4/JA3指纹计算性能
fn bench_fingerprint_calculation(c: &mut Criterion) {
    let mut group = c.benchmark_group("fingerprint_calculation");
    group.measurement_time(Duration::from_secs(10));
    
    let client_hello = create_realistic_client_hello();
    
    // 解析一次以获得测试数据
    let parsed_data = parse_client_hello_with_tls_parser(&client_hello);
    
    if let Some((version, cipher_suites, extensions, elliptic_curves, ec_point_formats, signature_algorithms)) = parsed_data {
        // JA4指纹计算
        group.bench_function("ja4_full", |b| {
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
        
        // JA4_b组件
        group.bench_function("ja4b_component", |b| {
            b.iter(|| {
                let result = calculate_ja4b_from_parsed_data(black_box(&cipher_suites));
                black_box(result)
            })
        });
        
        // JA4_c组件
        group.bench_function("ja4c_component", |b| {
            b.iter(|| {
                let result = calculate_ja4c_from_parsed_data(
                    black_box(&extensions),
                    black_box(&signature_algorithms)
                );
                black_box(result)
            })
        });
        
        // JA3指纹计算
        group.bench_function("ja3_full", |b| {
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
        
        // GREASE过滤性能
        group.bench_function("grease_filtering", |b| {
            b.iter(|| {
                let mut filtered: Vec<u16> = cipher_suites.iter()
                    .filter(|&&c| !is_grease_value(c))
                    .copied()
                    .collect();
                filtered.sort();
                black_box(filtered)
            })
        });
    }
    
    group.finish();
}

// 基准测试：网络层解析性能
fn bench_network_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("network_parsing");
    group.measurement_time(Duration::from_secs(10));
    
    // 创建带VLAN的以太网帧
    let vlan_packet = vec![
        // Ethernet header with VLAN
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dst MAC
        0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, // Src MAC
        0x81, 0x00, // VLAN Tag Protocol ID
        0x00, 0x64, // VLAN Tag Control Info (VLAN 100)
        0x08, 0x00, // EtherType: IPv4
        // IPv4 header
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02,
        // TCP header
        0x04, 0x38, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02, 0x50, 0x18, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // TLS data
        0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05,
    ];
    
    // VLAN解析性能
    group.bench_function("parse_vlan_tags", |b| {
        b.iter(|| {
            let result = parse_vlan_tags(black_box(&vlan_packet[14..]));
            black_box(result)
        })
    });
    
    // 完整数据包解析性能
    group.throughput(Throughput::Bytes(vlan_packet.len() as u64));
    group.bench_function("extract_tls_data", |b| {
        b.iter(|| {
            let result = extract_tls_data_from_packet(black_box(&vlan_packet));
            black_box(result)
        })
    });
    
    group.finish();
}

// 基准测试：完整pcap文件处理
fn bench_pcap_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcap_processing");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10); // 减少样本数量，因为pcap处理比较耗时
    
    let pcap_files = vec![
        ("tls.pcap", "/root/workspace/pcap/tls.pcap"),
        ("tls2.pcap", "/root/workspace/pcap/tls2.pcap"),
        ("mulit_tls.pcap", "/root/workspace/pcap/mulit_tls.pcap"),
    ];
    
    for (name, path) in pcap_files {
        if std::path::Path::new(path).exists() {
            // 获取文件大小用于吞吐量计算
            if let Ok(metadata) = std::fs::metadata(path) {
                group.throughput(Throughput::Bytes(metadata.len()));
            }
            
            group.bench_with_input(BenchmarkId::new("process_pcap", name), &path, |b, &path| {
                b.iter(|| {
                    let config = Config {
                        include_server_hello: false,
                        max_packets_per_session: 10,
                        include_ja3: true,
                        verbose: false,
                    };
                    let result = process_pcap_file(black_box(path), &config);
                    black_box(result)
                })
            });
        }
    }
    
    group.finish();
}

// 基准测试：配置加载和会话管理
fn bench_utilities(c: &mut Criterion) {
    let mut group = c.benchmark_group("utilities");
    group.measurement_time(Duration::from_secs(5));
    
    // 配置加载性能
    group.bench_function("load_config", |b| {
        b.iter(|| {
            let result = load_config(black_box("config.json"));
            black_box(result)
        })
    });
    
    // 会话键生成性能
    use std::net::IpAddr;
    let src_ip = "192.168.1.1".parse::<IpAddr>().unwrap();
    let dst_ip = "192.168.1.2".parse::<IpAddr>().unwrap();
    
    group.bench_function("generate_session_key", |b| {
        b.iter(|| {
            let result = generate_session_key(
                black_box(src_ip),
                black_box(8080),
                black_box(dst_ip),
                black_box(443),
                black_box(true)
            );
            black_box(result)
        })
    });
    
    // ALPN提取性能
    let extensions = vec![0, 10, 11, 13, 16, 43, 45, 51];
    group.bench_function("extract_alpn", |b| {
        b.iter(|| {
            let result = extract_alpn_from_extensions(black_box(&extensions));
            black_box(result)
        })
    });
    
    group.finish();
}

// 压力测试：大量数据处理
fn bench_stress_tests(c: &mut Criterion) {
    let mut group = c.benchmark_group("stress_tests");
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(10);
    
    // 大量Client Hello解析
    let client_hellos: Vec<Vec<u8>> = (0..1000)
        .map(|_| create_realistic_client_hello())
        .collect();
    
    group.throughput(Throughput::Elements(client_hellos.len() as u64));
    group.bench_function("batch_parse_client_hellos", |b| {
        b.iter(|| {
            let mut successful_parses = 0;
            for client_hello in &client_hellos {
                if let Some(_) = parse_client_hello_with_tls_parser(black_box(client_hello)) {
                    successful_parses += 1;
                }
            }
            black_box(successful_parses)
        })
    });
    
    // 大量指纹计算
    if let Some((version, cipher_suites, extensions, elliptic_curves, ec_point_formats, signature_algorithms)) 
        = parse_client_hello_with_tls_parser(&client_hellos[0]) {
        
        group.throughput(Throughput::Elements(1000));
        group.bench_function("batch_ja4_calculation", |b| {
            b.iter(|| {
                let mut fingerprints = Vec::new();
                for _ in 0..1000 {
                    let ja4 = calculate_ja4_from_parsed_data(
                        black_box(version),
                        black_box(&cipher_suites),
                        black_box(&extensions),
                        black_box(&signature_algorithms),
                        black_box(None)
                    );
                    fingerprints.push(ja4);
                }
                black_box(fingerprints)
            })
        });
        
        group.bench_function("batch_ja3_calculation", |b| {
            b.iter(|| {
                let mut fingerprints = Vec::new();
                for _ in 0..1000 {
                    if let Some(ja3) = calculate_ja3_from_parsed_data(
                        black_box(version),
                        black_box(&cipher_suites),
                        black_box(&extensions),
                        black_box(&elliptic_curves),
                        black_box(&ec_point_formats)
                    ) {
                        fingerprints.push(ja3);
                    }
                }
                black_box(fingerprints)
            })
        });
    }
    
    group.finish();
}

// 内存性能测试
fn bench_memory_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_efficiency");
    group.measurement_time(Duration::from_secs(5));
    
    let client_hello = create_realistic_client_hello();
    
    // 测试零拷贝vs拷贝的性能差异
    group.bench_function("zero_copy_parsing", |b| {
        b.iter(|| {
            // 使用引用，避免拷贝
            let result = parse_client_hello_with_tls_parser(black_box(&client_hello));
            black_box(result)
        })
    });
    
    group.bench_function("copy_parsing", |b| {
        b.iter(|| {
            // 强制拷贝数据
            let copied_data = client_hello.clone();
            let result = parse_client_hello_with_tls_parser(black_box(&copied_data));
            black_box(result)
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_tls_parsing,
    bench_fingerprint_calculation,
    bench_network_parsing,
    bench_pcap_processing,
    bench_utilities,
    bench_stress_tests,
    bench_memory_efficiency
);

criterion_main!(benches);