use tls_ja4::*;

/// 测试分段TLS处理功能
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing segmented TLS processing...");
    println!("This example demonstrates how to handle TLS Client Hello that is split across multiple TCP segments.");

    // 创建上下文
    let context = tls_ja4_init();
    if context.is_null() {
        println!("❌ Failed to initialize context");
        return Ok(());
    }

    // 模拟分段TLS Client Hello
    // 第一个分段：IP头 + TCP头 + TLS记录头 + 部分Client Hello
    let segment1 = &[
        // IPv4 Header (20 bytes)
        0x45, 0x00, 0x00, 0x50,  // Version(4) + IHL(5) + TOS(0) + Total Length(80)
        0x00, 0x01, 0x40, 0x00,  // ID(1) + Flags(2) + Fragment Offset(0)
        0x40, 0x06, 0x00, 0x00,  // TTL(64) + Protocol(TCP=6) + Header Checksum(0)
        0xc0, 0xa8, 0x01, 0x64,  // Source IP: 192.168.1.100
        0x08, 0x08, 0x08, 0x08,  // Destination IP: 8.8.8.8
        
        // TCP Header (20 bytes)
        0x30, 0x39, 0x01, 0xbb,  // Source Port(12345) + Destination Port(443)
        0x00, 0x00, 0x03, 0xe8,  // Sequence Number(1000)
        0x00, 0x00, 0x00, 0x00,  // Acknowledgment Number(0)
        0x50, 0x18, 0x00, 0x00,  // Header Length(5) + Flags(PSH+ACK) + Window Size(0)
        0x00, 0x00, 0x00, 0x00,  // Checksum(0) + Urgent Pointer(0)
        
        // TLS Handshake - 第一个分段 (40 bytes)
        0x16, 0x03, 0x01, 0x00, 0x4a,  // TLS Handshake header
        0x01, 0x00, 0x00, 0x46,        // Client Hello header
        0x03, 0x03,                     // TLS 1.2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Random
        0x00,                           // Session ID length
        0x00, 0x04,                     // Cipher suites length
        0x00, 0x2f, 0x00, 0x35,         // Cipher suites
    ];

    // 第二个分段：剩余的TLS数据
    let segment2 = &[
        // IPv4 Header (20 bytes)
        0x45, 0x00, 0x00, 0x2c,  // Version(4) + IHL(5) + TOS(0) + Total Length(44)
        0x00, 0x02, 0x40, 0x00,  // ID(2) + Flags(2) + Fragment Offset(0)
        0x40, 0x06, 0x00, 0x00,  // TTL(64) + Protocol(TCP=6) + Header Checksum(0)
        0xc0, 0xa8, 0x01, 0x64,  // Source IP: 192.168.1.100
        0x08, 0x08, 0x08, 0x08,  // Destination IP: 8.8.8.8
        
        // TCP Header (20 bytes)
        0x30, 0x39, 0x01, 0xbb,  // Source Port(12345) + Destination Port(443)
        0x00, 0x00, 0x04, 0x10,  // Sequence Number(1040) - 继续第一个分段的序列号
        0x00, 0x00, 0x00, 0x00,  // Acknowledgment Number(0)
        0x50, 0x18, 0x00, 0x00,  // Header Length(5) + Flags(PSH+ACK) + Window Size(0)
        0x00, 0x00, 0x00, 0x00,  // Checksum(0) + Urgent Pointer(0)
        
        // TLS Handshake - 第二个分段 (4 bytes)
        0x01,                           // Compression methods length
        0x00,                           // Compression methods
        0x00, 0x1a,                     // Extensions length
    ];

    // 第三个分段：扩展数据
    let segment3 = &[
        // IPv4 Header (20 bytes)
        0x45, 0x00, 0x00, 0x3c,  // Version(4) + IHL(5) + TOS(0) + Total Length(60)
        0x00, 0x03, 0x40, 0x00,  // ID(3) + Flags(2) + Fragment Offset(0)
        0x40, 0x06, 0x00, 0x00,  // TTL(64) + Protocol(TCP=6) + Header Checksum(0)
        0xc0, 0xa8, 0x01, 0x64,  // Source IP: 192.168.1.100
        0x08, 0x08, 0x08, 0x08,  // Destination IP: 8.8.8.8
        
        // TCP Header (20 bytes)
        0x30, 0x39, 0x01, 0xbb,  // Source Port(12345) + Destination Port(443)
        0x00, 0x00, 0x04, 0x14,  // Sequence Number(1044) - 继续第二个分段的序列号
        0x00, 0x00, 0x00, 0x00,  // Acknowledgment Number(0)
        0x50, 0x18, 0x00, 0x00,  // Header Length(5) + Flags(PSH+ACK) + Window Size(0)
        0x00, 0x00, 0x00, 0x00,  // Checksum(0) + Urgent Pointer(0)
        
        // TLS Handshake - 第三个分段 (20 bytes)
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,  // Supported groups
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,  // EC point formats
        0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x00, 0x0a,  // Signature algorithms
    ];

    println!("\n📦 Processing Segment 1 ({} bytes)...", segment1.len());
    let mut result = TlsJa4Result {
        fingerprint: TlsJa4Fingerprint {
            ja4: [0; 64],
            ja4_len: 0,
            ja3: [0; 64],
            ja3_len: 0,
            tls_version: 0,
            cipher_count: 0,
            extension_count: 0,
        },
        is_client_hello: 0,
        is_complete: 0,
        status_code: 0,
        cached_bytes: 0,
        flow_id: 0,
        timestamp: 0,
    };

    let ret1 = tls_ja4_analyze_packet(
        context,
        segment1.as_ptr(),
        segment1.len() as u32,
        &mut result
    );

    println!("Segment 1 result: {}", ret1);
    if ret1 == TLS_JA4_SEGMENT_CACHED {
        println!("📦 Segment 1 cached, waiting for more data...");
    } else if ret1 == TLS_JA4_SUCCESS {
        println!("✅ Complete TLS Client Hello in segment 1!");
    } else {
        println!("❌ Segment 1 analysis failed: {}", ret1);
    }

    println!("\n📦 Processing Segment 2 ({} bytes)...", segment2.len());
    let ret2 = tls_ja4_analyze_packet(
        context,
        segment2.as_ptr(),
        segment2.len() as u32,
        &mut result
    );

    println!("Segment 2 result: {}", ret2);
    if ret2 == TLS_JA4_SEGMENT_CACHED {
        println!("📦 Segment 2 cached, waiting for more data...");
    } else if ret2 == TLS_JA4_SUCCESS {
        println!("✅ Complete TLS Client Hello in segment 2!");
    } else {
        println!("❌ Segment 2 analysis failed: {}", ret2);
    }

    println!("\n📦 Processing Segment 3 ({} bytes)...", segment3.len());
    let ret3 = tls_ja4_analyze_packet(
        context,
        segment3.as_ptr(),
        segment3.len() as u32,
        &mut result
    );

    println!("Segment 3 result: {}", ret3);
    if ret3 == TLS_JA4_SUCCESS {
        println!("✅ Complete TLS Client Hello assembled from segments!");
        println!("JA4: {}", std::str::from_utf8(&result.fingerprint.ja4[..result.fingerprint.ja4_len as usize]).unwrap_or("invalid"));
        println!("JA3: {}", std::str::from_utf8(&result.fingerprint.ja3[..result.fingerprint.ja3_len as usize]).unwrap_or("invalid"));
        println!("TLS Version: 0x{:04x}", result.fingerprint.tls_version);
        println!("Cipher Count: {}", result.fingerprint.cipher_count);
        println!("Extension Count: {}", result.fingerprint.extension_count);
    } else {
        println!("❌ Segment 3 analysis failed: {}", ret3);
    }

    // 清理上下文
    tls_ja4_cleanup(context);

    println!("\n🎯 Segmented TLS processing test completed!");
    println!("This demonstrates how the library handles TLS Client Hello split across multiple TCP segments.");
    println!("The implementation automatically reassembles segments and extracts fingerprints when complete.");

    Ok(())
}
