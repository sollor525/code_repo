use tls_ja4::*;

fn main() {
    println!("Testing C API functionality...");
    
    // 创建完整的IP数据包（包含IP头 + TCP头 + TLS载荷）
    let ip_packet = &[
        // IPv4 Header (20 bytes)
        0x45, 0x00, 0x00, 0x7c,  // Version(4) + IHL(5) + TOS(0) + Total Length(124)
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
        
        // TLS Handshake (74 bytes)
        0x16, 0x03, 0x01, 0x00, 0x4a,  // TLS Handshake header
        0x01, 0x00, 0x00, 0x46,        // Client Hello header
        0x03, 0x03,                     // TLS 1.2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Random
        0x00,                           // Session ID length
        0x00, 0x04,                     // Cipher suites length
        0x00, 0x2f, 0x00, 0x35,         // Cipher suites
        0x01,                           // Compression methods length
        0x00,                           // Compression methods
        0x00, 0x1a,                     // Extensions length
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,  // Supported groups
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,  // EC point formats
        0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x00, 0x0a,  // Signature algorithms
    ];
    
    // 测试TLS检测
    let is_tls = tls_ja4_is_tls_packet(ip_packet.as_ptr(), ip_packet.len() as u32);
    println!("Is TLS packet: {}", is_tls);
    
    let is_ch = tls_ja4_is_client_hello(ip_packet.as_ptr(), ip_packet.len() as u32);
    println!("Is Client Hello: {}", is_ch);
    
    // 测试分析函数
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
    
    // 创建上下文
    let context = tls_ja4_init();
    if context.is_null() {
        println!("❌ Failed to initialize context");
        return;
    }
    
    let ret = tls_ja4_analyze_packet(
        context,
        ip_packet.as_ptr(),
        ip_packet.len() as u32,
        &mut result
    );
    
    println!("Analysis return code: {}", ret);
    println!("Status code: {}", result.status_code);
    println!("Is complete: {}", result.is_complete);
    
    if ret == TLS_JA4_SUCCESS {
        println!("✅ Success!");
        println!("JA4: {}", std::str::from_utf8(&result.fingerprint.ja4[..result.fingerprint.ja4_len as usize]).unwrap_or("invalid"));
        println!("JA3: {}", std::str::from_utf8(&result.fingerprint.ja3[..result.fingerprint.ja3_len as usize]).unwrap_or("invalid"));
        println!("TLS Version: 0x{:04x}", result.fingerprint.tls_version);
        println!("Cipher Count: {}", result.fingerprint.cipher_count);
        println!("Extension Count: {}", result.fingerprint.extension_count);
    } else {
        println!("❌ Analysis failed with code: {}", ret);
    }
    
    // 清理上下文
    tls_ja4_cleanup(context);
    
    println!("C API test completed!");
}
