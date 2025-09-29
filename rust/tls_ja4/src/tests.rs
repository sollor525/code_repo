//! 单元测试模块

#[cfg(test)]
mod tests {
    // use crate::tls::client_hello::parse_client_hello_with_tls_parser;
    use crate::fingerprint::{calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data};
    use crate::network::format_ip;
    use tls_parser::TlsVersion;

    /// 测试IP地址格式化
    #[test]
    fn test_format_ip() {
        // 测试IPv4地址
        let ipv4 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1];
        assert_eq!(format_ip(&ipv4), "192.168.1.1");
        
        // 测试IPv6地址
        let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34];
        let result = format_ip(&ipv6);
        assert!(result.contains("2001:0db8:85a3"));
    }

    /// 测试JA4指纹计算
    #[test]
    fn test_ja4_calculation() {
        let version = TlsVersion::Tls13;
        let ciphers = vec![0x1301, 0x1302, 0x1303];
        let extensions = vec![0x000a, 0x000b, 0x000d];
        let signature_algorithms = vec![0x0403, 0x0503];
        let raw_payload = b"test payload";

        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &ciphers, 
            &extensions, 
            &signature_algorithms, 
            raw_payload
        );

        // JA4应该以t13开头（TLS 1.3）
        assert!(ja4.starts_with("t13"));
        // 应该包含密码套件和扩展的哈希
        assert!(ja4.contains("_"));
    }

    /// 测试JA3指纹计算
    #[test]
    fn test_ja3_calculation() {
        let version = TlsVersion::Tls12;
        let ciphers = vec![0x002f, 0x0035, 0x003c];
        let extensions = vec![0x000a, 0x000b, 0x000d];
        let elliptic_curves = vec![29, 23, 30];
        let ec_point_formats = vec![0, 1, 2];

        let ja3 = calculate_ja3_from_parsed_data(
            version, 
            &ciphers, 
            &extensions, 
            &elliptic_curves, 
            &ec_point_formats
        );

        assert!(ja3.is_some());
        let ja3_str = ja3.unwrap();
        // JA3应该是64字符的SHA256哈希（我们的实现使用SHA256）
        assert_eq!(ja3_str.len(), 64);
        // 应该只包含十六进制字符
        assert!(ja3_str.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// 测试TLS版本转换
    #[test]
    fn test_tls_version_conversion() {
        use crate::fingerprint::utils::tls_version_to_u16;
        
        assert_eq!(tls_version_to_u16(TlsVersion::Ssl30), 0x0300);
        assert_eq!(tls_version_to_u16(TlsVersion::Tls10), 0x0301);
        assert_eq!(tls_version_to_u16(TlsVersion::Tls11), 0x0302);
        assert_eq!(tls_version_to_u16(TlsVersion::Tls12), 0x0303);
        assert_eq!(tls_version_to_u16(TlsVersion::Tls13), 0x0304);
    }

    /// 测试GREASE检测
    #[test]
    fn test_grease_detection() {
        use crate::tls::extensions::{is_grease_extension, is_grease_cipher};
        
        // 测试GREASE扩展
        assert!(is_grease_extension(0x0a0a));
        assert!(is_grease_extension(0x1a1a));
        assert!(is_grease_extension(0x2a2a));
        assert!(!is_grease_extension(0x000a)); // 正常扩展
        assert!(!is_grease_extension(0x0010)); // ALPN扩展
        
        // 测试GREASE密码套件
        assert!(is_grease_cipher(0x0a0a));
        assert!(is_grease_cipher(0x1a1a));
        assert!(is_grease_cipher(0x2a2a));
        assert!(!is_grease_cipher(0x002f)); // 正常密码套件
        assert!(!is_grease_cipher(0x1301)); // TLS 1.3密码套件
    }

    /// 测试空输入处理
    #[test]
    fn test_empty_input_handling() {
        let version = TlsVersion::Tls12;
        let empty_ciphers = vec![];
        let empty_extensions = vec![];
        let empty_signature_algorithms = vec![];
        let empty_payload = b"";

        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &empty_ciphers, 
            &empty_extensions, 
            &empty_signature_algorithms, 
            empty_payload
        );

        // 即使输入为空，也应该生成有效的JA4
        assert!(!ja4.is_empty());
        assert!(ja4.starts_with("t12")); // TLS 1.2
    }

    /// 测试不同TLS版本的JA4计算
    #[test]
    fn test_different_tls_versions() {
        let ciphers = vec![0x002f, 0x0035];
        let extensions = vec![0x000a, 0x000b];
        let signature_algorithms = vec![0x0403];
        let payload = b"test";

        // TLS 1.0
        let ja4_tls10 = calculate_ja4_from_parsed_data(
            TlsVersion::Tls10, &ciphers, &extensions, &signature_algorithms, payload
        );
        println!("TLS 1.0 JA4: {}", ja4_tls10);
        assert!(ja4_tls10.starts_with("t10"));

        // TLS 1.1
        let ja4_tls11 = calculate_ja4_from_parsed_data(
            TlsVersion::Tls11, &ciphers, &extensions, &signature_algorithms, payload
        );
        assert!(ja4_tls11.starts_with("t11"));

        // TLS 1.2
        let ja4_tls12 = calculate_ja4_from_parsed_data(
            TlsVersion::Tls12, &ciphers, &extensions, &signature_algorithms, payload
        );
        assert!(ja4_tls12.starts_with("t12"));

        // TLS 1.3
        let ja4_tls13 = calculate_ja4_from_parsed_data(
            TlsVersion::Tls13, &ciphers, &extensions, &signature_algorithms, payload
        );
        assert!(ja4_tls13.starts_with("t13"));
    }

    /// 测试大量密码套件的处理
    #[test]
    fn test_large_cipher_list() {
        let version = TlsVersion::Tls12;
        let large_ciphers = (0x002f..=0x00ff).collect::<Vec<u16>>();
        let extensions = vec![0x000a, 0x000b, 0x000d];
        let signature_algorithms = vec![0x0403, 0x0503];
        let payload = b"large cipher test";

        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &large_ciphers, 
            &extensions, 
            &signature_algorithms, 
            payload
        );

        assert!(!ja4.is_empty());
        assert!(ja4.starts_with("t12"));
        // 应该包含密码套件的哈希
        assert!(ja4.contains("_"));
    }

    /// 测试大量扩展的处理
    #[test]
    fn test_large_extension_list() {
        let version = TlsVersion::Tls13;
        let ciphers = vec![0x1301, 0x1302];
        let large_extensions = (0x0000..=0x0010).collect::<Vec<u16>>();
        let signature_algorithms = vec![0x0403];
        let payload = b"large extension test";

        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &ciphers, 
            &large_extensions, 
            &signature_algorithms, 
            payload
        );

        assert!(!ja4.is_empty());
        assert!(ja4.starts_with("t13"));
        assert!(ja4.contains("_"));
    }

    /// 测试特殊字符和边界值
    #[test]
    fn test_special_values() {
        let version = TlsVersion::Tls12;
        
        // 测试最大u16值
        let max_ciphers = vec![0xFFFF];
        let max_extensions = vec![0xFFFF];
        let max_signature_algorithms = vec![0xFFFF];
        let payload = b"max values test";

        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &max_ciphers, 
            &max_extensions, 
            &max_signature_algorithms, 
            payload
        );

        assert!(!ja4.is_empty());
        assert!(ja4.starts_with("t12"));
    }

    /// 测试IPv6地址格式化
    #[test]
    fn test_ipv6_formatting() {
        // 测试标准IPv6地址
        let ipv6_standard = [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 
                             0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34];
        let result = format_ip(&ipv6_standard);
        assert!(result.contains("2001:0db8:85a3"));
        assert!(result.contains("8a2e:0370:7334"));

        // 测试IPv4映射的IPv6地址
        let ipv6_mapped = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0xff, 0xff, 192, 168, 1, 1];
        let result_mapped = format_ip(&ipv6_mapped);
        // IPv4映射的IPv6地址应该显示为IPv6格式，不是IPv4格式
        assert!(result_mapped.contains("c0a8:0101"));
    }

    /// 测试JA4格式验证
    #[test]
    fn test_ja4_format_validation() {
        let version = TlsVersion::Tls13;
        let ciphers = vec![0x1301, 0x1302, 0x1303];
        let extensions = vec![0x000a, 0x000b, 0x000d, 0x0010];
        let signature_algorithms = vec![0x0403, 0x0503, 0x0603];
        let payload = b"format validation test";

        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &ciphers, 
            &extensions, 
            &signature_algorithms, 
            payload
        );

        // 验证JA4格式：t13d[密码套件数量][扩展数量]h[签名算法数量]_[密码套件哈希]_[扩展哈希]
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 4); // 应该有4个部分用_分隔（包括ALPN哈希）
        
        // 第一部分应该以t13开头
        assert!(parts[0].starts_with("t13"));
        
        // 应该包含d和h标识符
        assert!(parts[0].contains("d"));
        assert!(parts[0].contains("h"));
    }

    /// 测试一致性：相同输入应产生相同输出
    #[test]
    fn test_consistency() {
        let version = TlsVersion::Tls12;
        let ciphers = vec![0x002f, 0x0035, 0x003c];
        let extensions = vec![0x000a, 0x000b, 0x000d];
        let signature_algorithms = vec![0x0403, 0x0503];
        let payload = b"consistency test";

        let ja4_1 = calculate_ja4_from_parsed_data(
            version, &ciphers, &extensions, &signature_algorithms, payload
        );
        
        let ja4_2 = calculate_ja4_from_parsed_data(
            version, &ciphers, &extensions, &signature_algorithms, payload
        );

        assert_eq!(ja4_1, ja4_2);
    }

    /// 测试性能：大量数据计算
    #[test]
    fn test_performance_large_data() {
        let version = TlsVersion::Tls13;
        let ciphers = (0x1301..=0x130f).collect::<Vec<u16>>();
        let extensions = (0x0000..=0x0020).collect::<Vec<u16>>();
        let signature_algorithms = (0x0401..=0x040f).collect::<Vec<u16>>();
        let payload = b"performance test with large data set";

        let start = std::time::Instant::now();
        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &ciphers, 
            &extensions, 
            &signature_algorithms, 
            payload
        );
        let duration = start.elapsed();

        assert!(!ja4.is_empty());
        assert!(duration.as_millis() < 100); // 应该在100ms内完成
    }

    /// 测试边界情况：单个元素
    #[test]
    fn test_single_elements() {
        let version = TlsVersion::Tls12;
        let single_cipher = vec![0x002f];
        let single_extension = vec![0x000a];
        let single_signature = vec![0x0403];
        let payload = b"single element test";

        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &single_cipher, 
            &single_extension, 
            &single_signature, 
            payload
        );

        assert!(!ja4.is_empty());
        assert!(ja4.starts_with("t12"));
    }

    /// 测试Unicode和特殊字符处理
    #[test]
    fn test_unicode_handling() {
        let version = TlsVersion::Tls13;
        let ciphers = vec![0x1301];
        let extensions = vec![0x000a];
        let signature_algorithms = vec![0x0403];
        
        // 测试包含Unicode字符的payload
        let unicode_payload = "测试中文🚀".as_bytes();
        
        let ja4 = calculate_ja4_from_parsed_data(
            version, 
            &ciphers, 
            &extensions, 
            &signature_algorithms, 
            unicode_payload
        );

        assert!(!ja4.is_empty());
        assert!(ja4.starts_with("t13"));
    }
}
