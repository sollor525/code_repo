//! PCAP解析库的性能测试
//!
//! 验证数据包处理和TCP流重组的性能

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
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

#[test]
fn test_packet_parsing_performance() {
    let ipv4_packet = create_mock_ethernet_packet(false, false);
    let ipv6_packet = create_mock_ethernet_packet(true, false);
    let vlan_packet = create_mock_ethernet_packet(false, true);

    let iterations = 1000;

    // 测试IPv4数据包解析
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = extract_tls_data_from_packet(&ipv4_packet);
    }
    let ipv4_time = start.elapsed();

    // 测试IPv6数据包解析
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = extract_tls_data_from_packet(&ipv6_packet);
    }
    let ipv6_time = start.elapsed();

    // 测试VLAN数据包解析
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = extract_tls_data_from_packet(&vlan_packet);
    }
    let vlan_time = start.elapsed();

    println!("Packet parsing performance ({} iterations):", iterations);
    println!("IPv4 packets: {:?} ({:.2} ns/packet)", ipv4_time, ipv4_time.as_nanos() as f64 / iterations as f64);
    println!("IPv6 packets: {:?} ({:.2} ns/packet)", ipv6_time, ipv6_time.as_nanos() as f64 / iterations as f64);
    println!("VLAN packets: {:?} ({:.2} ns/packet)", vlan_time, vlan_time.as_nanos() as f64 / iterations as f64);

    // 验证解析性能合理
    assert!(ipv4_time.as_nanos() < 100_000_000, "IPv4 parsing should be fast");
    assert!(ipv6_time.as_nanos() < 100_000_000, "IPv6 parsing should be fast");
    assert!(vlan_time.as_nanos() < 100_000_000, "VLAN parsing should be fast");
}

#[test]
fn test_tcp_stream_reassembly_performance() {
    let base_packet = create_mock_ethernet_packet(false, false);
    let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

    let stream_count = 100;
    let segments_per_stream = 10;

    let start = Instant::now();
    let mut stream_buffers = HashMap::new();

    for stream_id in 0..stream_count {
        for segment_id in 0..segments_per_stream {
            let mut packet = base_packet.clone();
            // 修改序列号和端口来创建不同的流和段
            if packet.len() > 38 {
                packet[38] = ((stream_id + segment_id) >> 8) as u8; // 修改序列号高字节
                packet[39] = (stream_id + segment_id) as u8; // 修改序列号低字节
                packet[34] = ((stream_id + 0x1f90) >> 8) as u8; // 修改源端口高字节
                packet[35] = (stream_id + 0x1f90) as u8; // 修改源端口低字节
            }

            let timestamp = 0;
            let _ = reassemble_tcp_stream(
                &mut stream_buffers,
                src_ip,
                8080 + stream_id as u16,
                dst_ip,
                20480,
                (stream_id * segments_per_stream + segment_id) as u32,
                &packet[46..],
                timestamp,
            );
        }
    }

    let total_time = start.elapsed();
    let total_operations = stream_count * segments_per_stream;

    println!("TCP stream reassembly performance:");
    println!("{} streams, {} segments each", stream_count, segments_per_stream);
    println!("Total time: {:?}", total_time);
    println!("Throughput: {:.2} ops/sec", total_operations as f64 / total_time.as_secs_f64());

    // 验证流重组性能合理
    assert!(total_time.as_nanos() < 1_000_000_000, "Stream reassembly should be reasonably fast");

    // 验证流缓冲区中包含数据
    assert!(!stream_buffers.is_empty(), "Stream buffers should contain data");
    println!("Active streams: {}", stream_buffers.len());
}

#[test]
fn test_session_key_generation_performance() {
    let src_ip_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let dst_ip_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
    let src_ip_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    let dst_ip_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

    let iterations = 10000;

    // 测试IPv4会话键生成
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = generate_session_key(src_ip_v4, 8080, dst_ip_v4, 443, true);
    }
    let ipv4_key_time = start.elapsed();

    // 测试IPv6会话键生成
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = generate_session_key(src_ip_v6, 8080, dst_ip_v6, 443, true);
    }
    let ipv6_key_time = start.elapsed();

    // 测试TCP流键生成
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = generate_tcp_stream_key(src_ip_v4, 8080, dst_ip_v4, 443);
    }
    let tcp_stream_key_time = start.elapsed();

    println!("Session key generation performance ({} iterations):", iterations);
    println!("IPv4 session keys: {:?} ({:.2} ns/key)", ipv4_key_time, ipv4_key_time.as_nanos() as f64 / iterations as f64);
    println!("IPv6 session keys: {:?} ({:.2} ns/key)", ipv6_key_time, ipv6_key_time.as_nanos() as f64 / iterations as f64);
    println!("TCP stream keys: {:?} ({:.2} ns/key)", tcp_stream_key_time, tcp_stream_key_time.as_nanos() as f64 / iterations as f64);

    // 验证键生成性能
    assert!(ipv4_key_time.as_nanos() < 10_000_000, "IPv4 key generation should be very fast");
    assert!(ipv6_key_time.as_nanos() < 10_000_000, "IPv6 key generation should be very fast");
    assert!(tcp_stream_key_time.as_nanos() < 10_000_000, "TCP stream key generation should be very fast");
}