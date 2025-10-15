//! PCAP解析库的性能基准测试
//!
//! 测试数据包处理和TCP流重组的性能

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tls_ja4_pcap::packet_processor::*;

/// 创建模拟的以太网数据包
fn create_mock_ethernet_packet(is_ipv6: bool, is_vlan: bool) -> Vec<u8> {
    let mut packet = Vec::new();

    // 以太网目标MAC (6 bytes)
    packet.extend_from_slice(&[0x08, 0x00, 0x27, 0x9b, 0xf4, 0x88]);

    // 以太网源MAC (6 bytes)
    packet.extend_from_slice(&[0x08, 0x00, 0x27, 0x6c, 0x3a, 0x1b]);

    // VLAN标签 (可选)
    if is_vlan {
        packet.extend_from_slice(&[0x81, 0x00]); // VLAN TPID
        packet.extend_from_slice(&[0x00, 0x01]); // VLAN TCI (VLAN 1)
    }

    // EtherType
    if is_ipv6 {
        packet.extend_from_slice(&[0x86, 0xdd]); // IPv6
    } else {
        packet.extend_from_slice(&[0x08, 0x00]); // IPv4
    }

    // IP头部
    if is_ipv6 {
        // IPv6头部 (40 bytes)
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // Version, Traffic Class, Flow Label
        packet.extend_from_slice(&[0x00, 0x20]); // Payload Length (32 bytes)
        packet.extend_from_slice(&[0x06]); // Next Header (TCP)
        packet.extend_from_slice(&[0x40]); // Hop Limit
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]); // Source IP (2001:db8::1)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]); // Dest IP (2001:db8::2)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
    } else {
        // IPv4头部 (20 bytes)
        packet.extend_from_slice(&[0x45]); // Version, IHL
        packet.extend_from_slice(&[0x00]); // DSCP, ECN
        packet.extend_from_slice(&[0x00, 0x28]); // Total Length (40 bytes)
        packet.extend_from_slice(&[0x12, 0x34]); // Identification
        packet.extend_from_slice(&[0x40, 0x00]); // Flags, Fragment Offset
        packet.extend_from_slice(&[0x40]); // TTL
        packet.extend_from_slice(&[0x06]); // Protocol (TCP)
        packet.extend_from_slice(&[0x00, 0x00]); // Header Checksum (placeholder)
        packet.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]); // Source IP (192.168.1.1)
        packet.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x02]); // Dest IP (192.168.1.2)
    }

    // TCP头部 (20 bytes)
    packet.extend_from_slice(&[0x1f, 0x90]); // Source Port (8080)
    packet.extend_from_slice(&[0x50, 0x00]); // Dest Port (20480)
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Sequence Number
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Acknowledgment Number
    packet.extend_from_slice(&[0x50]); // Data Offset, Reserved, Flags
    packet.extend_from_slice(&[0x00, 0x10]); // Window Size
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum (placeholder)
    packet.extend_from_slice(&[0x00, 0x00]); // Urgent Pointer

    // TLS数据 (简化)
    packet.extend_from_slice(&[
        0x16, // Handshake type
        0x03, 0x01, // TLS 1.0
        0x00, 0x10, // Length
        // Handshake data
        0x01, // Client Hello
        0x00, 0x00, 0x0c, // Length
        0x03, 0x03, // TLS 1.2
        // Random (8 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ]);

    packet
}

/// 创建模拟的QUIC数据包
fn create_mock_quic_packet(is_ipv6: bool) -> Vec<u8> {
    let mut packet = Vec::new();

    // 以太网头部
    packet.extend_from_slice(&[0x08, 0x00, 0x27, 0x9b, 0xf4, 0x88]);
    packet.extend_from_slice(&[0x08, 0x00, 0x27, 0x6c, 0x3a, 0x1b]);

    // EtherType
    if is_ipv6 {
        packet.extend_from_slice(&[0x86, 0xdd]); // IPv6
    } else {
        packet.extend_from_slice(&[0x08, 0x00]); // IPv4
    }

    // IP头部
    if is_ipv6 {
        // IPv6头部
        packet.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x40]); // Payload Length (64 bytes)
        packet.extend_from_slice(&[0x11]); // Next Header (UDP)
        packet.extend_from_slice(&[0x40]); // Hop Limit
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]); // Source IP
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        packet.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]); // Dest IP
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
    } else {
        // IPv4头部
        packet.extend_from_slice(&[0x45]);
        packet.extend_from_slice(&[0x00]);
        packet.extend_from_slice(&[0x00, 0x3c]); // Total Length (60 bytes)
        packet.extend_from_slice(&[0x12, 0x34]);
        packet.extend_from_slice(&[0x40, 0x00]);
        packet.extend_from_slice(&[0x40]);
        packet.extend_from_slice(&[0x11]); // Protocol (UDP)
        packet.extend_from_slice(&[0x00, 0x00]);
        packet.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x01]);
        packet.extend_from_slice(&[0xc0, 0xa8, 0x01, 0x02]);
    }

    // UDP头部
    packet.extend_from_slice(&[0x1f, 0x90]); // Source Port
    packet.extend_from_slice(&[0x08, 0x18]); // Dest Port (2072)
    packet.extend_from_slice(&[0x00, 0x24]); // Length (36 bytes)
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum

    // QUIC数据
    packet.extend_from_slice(&[
        // QUIC Long Header
        0xc0, // Header Form (1), Fixed Bit (1), Long Packet Type (0), Reserved
        0x00, 0x00, 0x00, 0x01, // Version (1)
        0x00, 0x00, 0x00, 0x00, // Destination Connection ID Length (0)
        0x00, 0x00, 0x00, 0x00, // Source Connection ID Length (0)
        // Token Length (0)
        0x00, 0x00, 0x00, 0x10, // Length (16 bytes)
        // TLS Client Hello data
        0x16, 0x03, 0x01, 0x00, 0x0a, // TLS record header
        0x01, 0x00, 0x00, 0x06, // Handshake header
        0x03, 0x03, // TLS version
        0x01, 0x02, 0x03, 0x04, // Random (4 bytes)
    ]);

    packet
}

/// 基准测试：数据包解析性能
fn bench_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_parsing");

    let ipv4_packet = create_mock_ethernet_packet(false, false);
    let ipv6_packet = create_mock_ethernet_packet(true, false);
    let vlan_packet = create_mock_ethernet_packet(false, true);
    let quic_packet = create_mock_quic_packet(false);

    group.bench_function("ipv4_tcp", |b| {
        b.iter(|| {
            black_box(extract_tls_data_from_packet(black_box(&ipv4_packet)));
        });
    });

    group.bench_function("ipv6_tcp", |b| {
        b.iter(|| {
            black_box(extract_tls_data_from_packet(black_box(&ipv6_packet)));
        });
    });

    group.bench_function("vlan_tcp", |b| {
        b.iter(|| {
            black_box(extract_tls_data_from_packet(black_box(&vlan_packet)));
        });
    });

    group.bench_function("quic_udp", |b| {
        b.iter(|| {
            black_box(extract_tls_data_from_packet(black_box(&quic_packet)));
        });
    });

    group.finish();
}

/// 基准测试：VLAN标签解析性能
fn bench_vlan_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("vlan_parsing");

    // 不同VLAN层数的数据
    let no_vlan_data = [0x08, 0x00]; // IPv4 ether type
    let single_vlan_data = [0x81, 0x00, 0x00, 0x01, 0x08, 0x00]; // 1 VLAN tag + IPv4
    let double_vlan_data = [0x81, 0x00, 0x00, 0x01, 0x88, 0xa8, 0x00, 0x02, 0x08, 0x00]; // 2 VLAN tags + IPv4

    group.bench_function("no_vlan", |b| {
        b.iter(|| {
            black_box(parse_vlan_tags(black_box(&no_vlan_data)));
        });
    });

    group.bench_function("single_vlan", |b| {
        b.iter(|| {
            black_box(parse_vlan_tags(black_box(&single_vlan_data)));
        });
    });

    group.bench_function("double_vlan", |b| {
        b.iter(|| {
            black_box(parse_vlan_tags(black_box(&double_vlan_data)));
        });
    });

    group.finish();
}

/// 基准测试：TCP流重组性能
fn bench_tcp_stream_reassembly(c: &mut Criterion) {
    let mut group = c.benchmark_group("tcp_stream_reassembly");

    let base_packet = create_mock_ethernet_packet(false, false);
    let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    for stream_count in [1, 10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("stream_count", stream_count),
            stream_count,
            |b, &stream_count| {
                b.iter(|| {
                    let mut stream_buffers = HashMap::new();

                    for i in 0..stream_count {
                        let mut packet = base_packet.clone();
                        // 修改序列号和端口来创建不同的流
                        if packet.len() > 38 {
                            packet[38] = ((i + 0x1234) >> 8) as u8; // 修改序列号高字节
                            packet[39] = (i + 0x1234) as u8; // 修改序列号低字节
                            packet[34] = ((i + 0x1f90) >> 8) as u8; // 修改源端口高字节
                            packet[35] = (i + 0x1f90) as u8; // 修改源端口低字节
                        }

                        let timestamp = 0;
                        black_box(reassemble_tcp_stream(
                            black_box(&mut stream_buffers),
                            black_box(src_ip),
                            black_box(8080 + i as u16),
                            black_box(dst_ip),
                            black_box(20480),
                            black_box(0x12340000 + i as u32),
                            black_box(&packet[46..]),
                            black_box(timestamp),
                        ));
                    }
                });
            },
        );
    }

    group.finish();
}

/// 基准测试：数据包处理性能
fn bench_packet_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_processing");

    let tcp_packet = create_mock_ethernet_packet(false, false);
    let quic_packet = create_mock_quic_packet(false);

    for packet_count in [100, 500, 1000].iter() {
        // TCP数据包处理
        group.bench_with_input(
            BenchmarkId::new("tcp_packets", packet_count),
            packet_count,
            |b, &packet_count| {
                b.iter(|| {
                    let mut stream_buffers = HashMap::new();
                    for _ in 0..packet_count {
                        black_box(process_packet(
                            black_box(&tcp_packet),
                            black_box(&mut stream_buffers),
                        ));
                    }
                });
            },
        );

        // QUIC数据包处理
        group.bench_with_input(
            BenchmarkId::new("quic_packets", packet_count),
            packet_count,
            |b, &packet_count| {
                b.iter(|| {
                    let mut stream_buffers = HashMap::new();
                    for _ in 0..packet_count {
                        black_box(process_packet(
                            black_box(&quic_packet),
                            black_box(&mut stream_buffers),
                        ));
                    }
                });
            },
        );
    }

    group.finish();
}

/// 基准测试：会话键生成性能
fn bench_session_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_key_generation");

    let src_ip_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let dst_ip_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
    let src_ip_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let dst_ip_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

    group.bench_function("ipv4", |b| {
        b.iter(|| {
            black_box(generate_session_key(
                black_box(src_ip_v4),
                black_box(8080),
                black_box(dst_ip_v4),
                black_box(443),
                black_box(true),
            ));
        });
    });

    group.bench_function("ipv6", |b| {
        b.iter(|| {
            black_box(generate_session_key(
                black_box(src_ip_v6),
                black_box(8080),
                black_box(dst_ip_v6),
                black_box(443),
                black_box(true),
            ));
        });
    });

    group.bench_function("tcp_stream", |b| {
        b.iter(|| {
            black_box(generate_tcp_stream_key(
                black_box(src_ip_v4),
                black_box(8080),
                black_box(dst_ip_v4),
                black_box(443),
            ));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_packet_parsing,
    bench_vlan_parsing,
    bench_tcp_stream_reassembly,
    bench_packet_processing,
    bench_session_key_generation
);
criterion_main!(benches);