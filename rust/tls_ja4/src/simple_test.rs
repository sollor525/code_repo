//! 简单功能测试

#[cfg(test)]
mod tests {
    use crate::network::format_ip;
    use crate::fingerprint::calculate_ja4_from_parsed_data;
    use tls_parser::TlsVersion;

    #[test]
    fn test_basic_functionality() {
        // 测试IP地址格式化
        let ipv4 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1];
        assert_eq!(format_ip(&ipv4), "192.168.1.1");
        
        // 测试JA4计算
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
        
        println!("JA4 fingerprint: {}", ja4);
    }
}
