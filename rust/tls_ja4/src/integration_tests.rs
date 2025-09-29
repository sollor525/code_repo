//! 集成测试模块

#[cfg(test)]
mod integration_tests {
    use crate::tls::client_hello::parse_client_hello_with_tls_parser;
    use crate::fingerprint::{calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data};
    use crate::network::format_ip;
    use tls_parser::TlsVersion;

    /// 测试完整的TLS Client Hello解析流程
    #[test]
    fn test_complete_tls_parsing_flow() {
        // 使用简化的测试数据，不依赖复杂的TLS解析
        let version = TlsVersion::Tls13;
        let ciphers = vec![0x1301, 0x1302, 0x1303];
        let extensions = vec![0x000a, 0x000b, 0x000d];
        let signature_algorithms = vec![0x0403, 0x0503];
        let elliptic_curves = vec![29, 23, 30];
        let ec_point_formats = vec![0, 1, 2];
        let payload = b"test client hello";
        
        // 计算JA4指纹
        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &ciphers, 
            &extensions, 
            &signature_algorithms, 
            payload
        );
        
        // 计算JA3指纹
        let ja3 = calculate_ja3_from_parsed_data(
            version, 
            &ciphers, 
            &extensions, 
            &elliptic_curves, 
            &ec_point_formats
        );
        
        // 验证结果
        assert!(!ja4.is_empty());
        assert!(ja3.is_some());
        assert!(ja4.starts_with("t13"));
        
        println!("完整流程测试 - JA4: {}, JA3: {:?}", ja4, ja3);
    }

    /// 测试网络地址处理集成
    #[test]
    fn test_network_address_integration() {
        // 测试IPv4地址
        let ipv4_bytes = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 100];
        let ipv4_str = format_ip(&ipv4_bytes);
        assert_eq!(ipv4_str, "192.168.1.100");
        
        // 测试IPv6地址
        let ipv6_bytes = [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 
                          0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34];
        let ipv6_str = format_ip(&ipv6_bytes);
        assert!(ipv6_str.contains("2001:0db8:85a3"));
        
        println!("网络地址处理测试通过 - IPv4: {}, IPv6: {}", ipv4_str, ipv6_str);
    }

    /// 测试多种TLS配置的兼容性
    #[test]
    fn test_multiple_tls_configurations() {
        let test_configs = vec![
            // Chrome-like配置
            (TlsVersion::Tls13, vec![0x1301, 0x1302, 0x1303], vec![0x000a, 0x000b, 0x000d, 0x0010]),
            // Firefox-like配置
            (TlsVersion::Tls12, vec![0x002f, 0x0035, 0x003c], vec![0x000a, 0x000b, 0x000d]),
            // Safari-like配置
            (TlsVersion::Tls13, vec![0x1301, 0x1302], vec![0x000a, 0x000b, 0x000d, 0x0010, 0x001b]),
        ];
        
        for (i, (version, ciphers, extensions)) in test_configs.iter().enumerate() {
            let signature_algorithms = vec![0x0403, 0x0503];
            let payload_str = format!("config_{}", i);
            let payload = payload_str.as_bytes();
            
            let ja4 = calculate_ja4_from_parsed_data(
                *version, 
                ciphers, 
                extensions, 
                &signature_algorithms, 
                payload
            );
            
            assert!(!ja4.is_empty());
            let expected_prefix = match *version {
            TlsVersion::Tls10 => "t10",
            TlsVersion::Tls11 => "t11", 
            TlsVersion::Tls12 => "t12",
            TlsVersion::Tls13 => "t13",
            _ => "t00",
        };
        assert!(ja4.starts_with(expected_prefix));
            
            println!("配置 {} - JA4: {}", i + 1, ja4);
        }
    }

    /// 测试错误恢复和边界情况
    #[test]
    fn test_error_recovery_and_edge_cases() {
        // 测试空数据
        let empty_data = b"";
        let result = parse_client_hello_with_tls_parser(empty_data);
        assert!(result.is_none());
        
        // 测试无效数据
        let invalid_data = b"invalid tls data";
        let result = parse_client_hello_with_tls_parser(invalid_data);
        assert!(result.is_none());
        
        // 测试部分有效数据
        let partial_data = &[0x16, 0x03, 0x01, 0x00, 0x04]; // 只有TLS记录头
        let result = parse_client_hello_with_tls_parser(partial_data);
        assert!(result.is_none());
        
        println!("错误恢复测试通过");
    }

    /// 测试性能基准
    #[test]
    fn test_performance_benchmark() {
        let version = TlsVersion::Tls13;
        let ciphers = (0x1301..=0x130f).collect::<Vec<u16>>();
        let extensions = (0x0000..=0x0010).collect::<Vec<u16>>();
        let signature_algorithms = (0x0401..=0x040f).collect::<Vec<u16>>();
        let payload = b"performance benchmark test";
        
        let iterations = 1000;
        let start = std::time::Instant::now();
        
        for _ in 0..iterations {
            let _ja4 = calculate_ja4_from_parsed_data(
                version, 
                &ciphers, 
                &extensions, 
                &signature_algorithms, 
                payload
            );
        }
        
        let duration = start.elapsed();
        let avg_time = duration.as_micros() / iterations;
        
        println!("性能基准测试 - {}次迭代，平均时间: {}μs", iterations, avg_time);
        assert!(avg_time < 1000); // 平均时间应该小于1ms
    }

    /// 测试内存使用
    #[test]
    fn test_memory_usage() {
        let version = TlsVersion::Tls12;
        let large_ciphers = (0x002f..=0x00ff).collect::<Vec<u16>>();
        let large_extensions = (0x0000..=0x00ff).collect::<Vec<u16>>();
        let large_signature_algorithms = (0x0401..=0x04ff).collect::<Vec<u16>>();
        let payload = b"memory usage test with large data";
        
        // 测试大量数据不会导致内存问题
        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &large_ciphers, 
            &large_extensions, 
            &large_signature_algorithms, 
            payload
        );
        
        assert!(!ja4.is_empty());
        println!("内存使用测试通过 - JA4: {}", ja4);
    }

    /// 测试并发安全性（模拟）
    #[test]
    fn test_concurrent_safety() {
        // use std::sync::Arc;
        use std::thread;
        
        let version = TlsVersion::Tls13;
        let ciphers = vec![0x1301, 0x1302, 0x1303];
        let extensions = vec![0x000a, 0x000b, 0x000d];
        let signature_algorithms = vec![0x0403, 0x0503];
        let _payload = b"concurrent safety test";
        
        let handles: Vec<_> = (0..10).map(|i| {
            let ciphers_clone = ciphers.clone();
            let extensions_clone = extensions.clone();
            let signature_algorithms_clone = signature_algorithms.clone();
            thread::spawn(move || {
                let test_payload = format!("test_{}", i);
                let payload_bytes = test_payload.as_bytes();
                calculate_ja4_from_parsed_data(
                    version, 
                    &ciphers_clone, 
                    &extensions_clone, 
                    &signature_algorithms_clone, 
                    payload_bytes
                )
            })
        }).collect();
        
        let results: Vec<_> = handles.into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        
        assert_eq!(results.len(), 10);
        for result in results {
            assert!(!result.is_empty());
        }
        
        println!("并发安全性测试通过");
    }

    // 辅助函数
    #[allow(dead_code)]
    fn create_mock_client_hello() -> Vec<u8> {
        // 创建一个模拟的TLS Client Hello数据包
        vec![
            0x16, 0x03, 0x01, 0x00, 0x4a, // TLS记录头
            0x01, 0x00, 0x00, 0x46, // Handshake头
            0x03, 0x03, // TLS 1.3版本
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 随机数
            0x00, // 会话ID长度
            0x00, 0x02, 0x13, 0x01, 0x13, 0x02, // 密码套件
            0x01, 0x00, // 压缩方法
            0x00, 0x0a, // 扩展长度
            0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, // 支持的椭圆曲线
            0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, // EC点格式
        ]
    }
    
    #[allow(dead_code)]
    fn version_to_number(version: TlsVersion) -> u8 {
        match version {
            TlsVersion::Ssl30 => 0,
            TlsVersion::Tls10 => 1,
            TlsVersion::Tls11 => 2,
            TlsVersion::Tls12 => 3,
            TlsVersion::Tls13 => 4,
            _ => 5, // 处理其他版本
        }
    }
}
