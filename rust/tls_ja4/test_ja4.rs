use tls_ja4::fingerprint::calculate_ja4_from_parsed_data;
use tls_ja4::network::format_ip;
use tls_parser::TlsVersion;

fn main() {
    println!("测试TLS JA4指纹计算功能");
    
    // 测试IP地址格式化
    let ipv4 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1];
    let ip_str = format_ip(&ipv4);
    println!("IPv4地址格式化: {}", ip_str);
    assert_eq!(ip_str, "192.168.1.1");
    
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

    println!("JA4指纹: {}", ja4);
    
    // 验证JA4格式
    assert!(ja4.starts_with("t13"));
    assert!(ja4.contains("_"));
    
    println!("✅ 所有测试通过！");
}
