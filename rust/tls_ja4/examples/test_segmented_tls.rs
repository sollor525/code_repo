use tls_ja4::c_api::*;

/// 测试分段TLS处理功能
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing segmented TLS processing...");
    println!("This example demonstrates how to handle TLS Client Hello that is split across multiple TCP segments.");
    println!("Note: Current C API focuses on TCP payload processing. For IP packet processing, use Rust API instead.");

    // 创建上下文
    let context = tls_init();
    if context.is_null() {
        println!("❌ Failed to initialize context");
        return Ok(());
    }

    // 模拟分段TLS Client Hello (仅TCP载荷)
    // 第一个分段：部分TLS Client Hello
    let segment1 = &[
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
        // TLS Handshake - 第二个分段 (4 bytes)
        0x01,                           // Compression methods length
        0x00,                           // Compression methods
        0x00, 0x1a,                     // Extensions length
    ];

    // 第三个分段：扩展数据
    let segment3 = &[
        // TLS Handshake - 第三个分段 (20 bytes)
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,  // Supported groups
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,  // EC point formats
        0x00, 0x0d, 0x00, 0x04, 0x00, 0x02, 0x00, 0x0a,  // Signature algorithms
    ];

    println!("\n📦 Processing Segment 1 ({} bytes)...", segment1.len());

    // 测试第一个分段 - 检测是否为TLS和Client Hello
    let is_tls1 = tls_is_tls_packet(segment1.as_ptr(), segment1.len() as u32);
    let is_ch1 = tls_is_client_hello(segment1.as_ptr(), segment1.len() as u32);

    println!("Segment 1 - Is TLS: {}", is_tls1);
    println!("Segment 1 - Is Client Hello: {}", is_ch1);

    if is_tls1 == TLS_JA4_NOT_TLS {
        println!("❌ Segment 1 is not TLS data");
    } else if is_ch1 == TLS_JA4_NOT_CLIENT_HELLO {
        println!("📦 Segment 1 is TLS but incomplete Client Hello - needs more data");
    } else {
        println!("✅ Segment 1 contains valid TLS Client Hello data");

        // 尝试JA3分析
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

        let ja3_ret1 = tls_calculate_ja3(
            segment1.as_ptr(),
            segment1.len() as u32,
            &mut ja3_result
        );

        println!("Segment 1 JA3 analysis result: {}", ja3_ret1);
        if ja3_ret1 == TLS_JA4_SUCCESS {
            println!("✅ Complete TLS Client Hello in segment 1 for JA3!");
            println!("JA3: {}", std::str::from_utf8(&ja3_result.fingerprint.fingerprint[..ja3_result.fingerprint.fingerprint_len as usize]).unwrap_or("invalid"));
        } else {
            println!("📦 Segment 1 incomplete for JA3 - needs more data");
        }

        // 尝试JA4分析
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

        let ja4_ret1 = tls_calculate_ja4(
            segment1.as_ptr(),
            segment1.len() as u32,
            &mut ja4_result
        );

        println!("Segment 1 JA4 analysis result: {}", ja4_ret1);
        if ja4_ret1 == TLS_JA4_SUCCESS {
            println!("✅ Complete TLS Client Hello in segment 1 for JA4!");
            println!("JA4: {}", std::str::from_utf8(&ja4_result.fingerprint.fingerprint[..ja4_result.fingerprint.fingerprint_len as usize]).unwrap_or("invalid"));
        } else {
            println!("📦 Segment 1 incomplete for JA4 - needs more data");
        }
    }

    println!("\n📦 Processing Combined TLS data...");

    // 组合所有分段
    let mut combined = Vec::new();
    combined.extend_from_slice(segment1);
    combined.extend_from_slice(segment2);
    combined.extend_from_slice(segment3);

    // 测试组合后的完整数据
    let is_tls_combined = tls_is_tls_packet(combined.as_ptr(), combined.len() as u32);
    let is_ch_combined = tls_is_client_hello(combined.as_ptr(), combined.len() as u32);

    println!("Combined - Is TLS: {}", is_tls_combined);
    println!("Combined - Is Client Hello: {}", is_ch_combined);

    if is_tls_combined == TLS_JA4_SUCCESS && is_ch_combined == TLS_JA4_SUCCESS {
        // JA3分析
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

        let ja3_ret_combined = tls_calculate_ja3(
            combined.as_ptr(),
            combined.len() as u32,
            &mut ja3_result
        );

        // JA4分析
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

        let ja4_ret_combined = tls_calculate_ja4(
            combined.as_ptr(),
            combined.len() as u32,
            &mut ja4_result
        );

        println!("Combined JA3 analysis result: {}", ja3_ret_combined);
        println!("Combined JA4 analysis result: {}", ja4_ret_combined);

        if ja3_ret_combined == TLS_JA4_SUCCESS && ja4_ret_combined == TLS_JA4_SUCCESS {
            println!("✅ Complete TLS Client Hello assembled from segments!");
            println!("JA3: {}", std::str::from_utf8(&ja3_result.fingerprint.fingerprint[..ja3_result.fingerprint.fingerprint_len as usize]).unwrap_or("invalid"));
            println!("JA4: {}", std::str::from_utf8(&ja4_result.fingerprint.fingerprint[..ja4_result.fingerprint.fingerprint_len as usize]).unwrap_or("invalid"));
            println!("TLS Version: 0x{:04x}", ja4_result.fingerprint.tls_version);
            println!("Cipher Count: {}", ja4_result.fingerprint.cipher_count);
            println!("Extension Count: {}", ja4_result.fingerprint.extension_count);
        }
    }

    // 清理上下文
    tls_cleanup(context);

    println!("\n🎯 Segmented TLS processing test completed!");
    println!("Note: C API works with TCP payloads. For IP packet parsing and segment reassembly,");
    println!("use the Rust API or implement TCP reassembly before calling C API functions.");

    Ok(())
}
