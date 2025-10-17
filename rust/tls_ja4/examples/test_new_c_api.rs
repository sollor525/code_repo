use tls_ja4::c_api::*;

fn main() {
    println!("Testing C API functionality...");

    // 创建TCP载荷（只包含TLS数据）
    let tls_payload = &[
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
    let is_tls = tls_is_tls_packet(tls_payload.as_ptr(), tls_payload.len() as u32);
    println!("Is TLS packet: {}", is_tls);

    let is_ch = tls_is_client_hello(tls_payload.as_ptr(), tls_payload.len() as u32);
    println!("Is Client Hello: {}", is_ch);

    // 测试JA3分析
    let mut ja3_result = TlsJa3Result {
        fingerprint: TlsJa4Fingerprint {
            fingerprint: [0; 64],
            fingerprint_len: 0,
            tls_version: 0,
            cipher_count: 0,
            extension_count: 0,
        },
        is_client_hello: 0,
        is_complete: 0,
        status_code: 0,
        timestamp: 0,
    };

    let ja3_ret = tls_calculate_ja3(
        tls_payload.as_ptr(),
        tls_payload.len() as u32,
        &mut ja3_result
    );

    println!("JA3 analysis return code: {}", ja3_ret);
    println!("JA3 Status code: {}", ja3_result.status_code);
    println!("JA3 Is complete: {}", ja3_result.is_complete);

    if ja3_ret == TLS_JA4_SUCCESS {
        println!("✅ JA3 Success!");
        println!("JA3: {}", std::str::from_utf8(&ja3_result.fingerprint.fingerprint[..ja3_result.fingerprint.fingerprint_len as usize]).unwrap_or("invalid"));
        println!("TLS Version: 0x{:04x}", ja3_result.fingerprint.tls_version);
        println!("Cipher Count: {}", ja3_result.fingerprint.cipher_count);
        println!("Extension Count: {}", ja3_result.fingerprint.extension_count);
    } else {
        println!("❌ JA3 Analysis failed with code: {}", ja3_ret);
    }

    // 测试JA4分析
    let mut ja4_result = TlsJa4Result {
        fingerprint: TlsJa4Fingerprint {
            fingerprint: [0; 64],
            fingerprint_len: 0,
            tls_version: 0,
            cipher_count: 0,
            extension_count: 0,
        },
        is_client_hello: 0,
        is_complete: 0,
        status_code: 0,
        timestamp: 0,
        is_match: 0,
    };

    let ja4_ret = tls_calculate_ja4(
        tls_payload.as_ptr(),
        tls_payload.len() as u32,
        &mut ja4_result
    );

    println!("JA4 analysis return code: {}", ja4_ret);
    println!("JA4 Status code: {}", ja4_result.status_code);
    println!("JA4 Is complete: {}", ja4_result.is_complete);

    if ja4_ret == TLS_JA4_SUCCESS {
        println!("✅ JA4 Success!");
        println!("JA4: {}", std::str::from_utf8(&ja4_result.fingerprint.fingerprint[..ja4_result.fingerprint.fingerprint_len as usize]).unwrap_or("invalid"));
        println!("TLS Version: 0x{:04x}", ja4_result.fingerprint.tls_version);
        println!("Cipher Count: {}", ja4_result.fingerprint.cipher_count);
        println!("Extension Count: {}", ja4_result.fingerprint.extension_count);
    } else {
        println!("❌ JA4 Analysis failed with code: {}", ja4_ret);
    }

    println!("C API test completed!");
}
