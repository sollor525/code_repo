//! JA4指纹计算

use tls_parser::TlsVersion;
use crate::tls::extensions::{is_grease_extension, is_grease_cipher};

/// 计算JA4指纹
pub fn calculate_ja4_from_parsed_data(
    version: TlsVersion,
    cipher_suites: &[u16],
    extensions: &[u16],
    _signature_algorithms: &[u16],
    client_hello_data: &[u8],
) -> String {
    // 1. TLS版本 - 读取数据包中的最高版本（supported_versions扩展或协商版本）
    // 根据JA4标准，需要读取客户端支持的最高版本，不是协商版本
    let mut highest_version = version;
    if extensions.contains(&43) {
        // 如果有supported_versions扩展(43)，则客户端支持更高版本
        // 这里简化处理，假设有该扩展就表示支持TLS 1.3
        highest_version = TlsVersion::Tls13;
    }

    // 协议标识：t=TCP, q=QUIC
    let protocol = "t";

    let version_str = match highest_version {
        TlsVersion::Ssl30 => format!("{}s3", protocol),
        TlsVersion::Tls10 => format!("{}10", protocol),
        TlsVersion::Tls11 => format!("{}11", protocol),
        TlsVersion::Tls12 => format!("{}12", protocol),
        TlsVersion::Tls13 => format!("{}13", protocol),
        _ => format!("{}00", protocol),
    };

    // 2. SNI (Server Name Indication) - 检测扩展0 (SNI)
    // d = Domain (SNI存在，访问域名), i = IP (SNI不存在，访问IP)
    let sni_flag = if extensions.contains(&0) {
        "d" // SNI present -> 访问域名
    } else {
        "i" // SNI not present -> 访问IP
    };

    // 3. 密码套件计数 (排序后) - 根据正确格式，使用十进制
    let mut sorted_ciphers: Vec<u16> = cipher_suites.iter()
        .filter(|&&c| !is_grease_cipher(c))
        .copied()
        .collect();
    sorted_ciphers.sort();
    let cipher_count = format!("{:02}", sorted_ciphers.len().min(99));  // 使用十进制格式


    // 4. 扩展计数 (排序后) - 根据正确格式，使用十进制
    // 注意：JA4标准中可能包含所有扩展，不排除任何扩展
    let sorted_extensions: Vec<u16> = extensions.iter()
        .filter(|&&e| !is_grease_extension(e)) // 只排除GREASE值
        .copied()
        .collect();
    let extension_count = format!("{:02}", sorted_extensions.len().min(99));  // 使用十进制格式

    // 5. ALPN - 从扩展16中解析实际的ALPN值
    let alpn_flag = extract_alpn_from_client_hello(client_hello_data)
        .unwrap_or_else(|| "00".to_string());

    // 构建第一部分 - 根据正确格式，应该是t13i3111h1
    let part1 = format!("{}{}{}{}{}", version_str, sni_flag, cipher_count, extension_count, alpn_flag);

    // JA4_b = 密码套件排序哈希 (传递引用避免clone)
    let ja4_b = super::calculate_ja4b_from_parsed_data(cipher_suites);

    // JA4_c = 扩展和签名算法排序哈希 (传递引用避免clone)
    let ja4_c = super::calculate_ja4c_from_parsed_data(extensions, _signature_algorithms);

    // 构建完整的JA4指纹：JA4_a_JA4_b_JA4_c
    format!("{}_{}_{}",  part1, ja4_b, ja4_c)
}


/// 从原始TLS Client Hello数据中提取ALPN
pub fn extract_alpn_from_client_hello(client_hello_data: &[u8]) -> Option<String> {
    use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake};

    // 解析TLS包
    if let Ok((_, tls_plaintext)) = parse_tls_plaintext(client_hello_data) {
        for msg in &tls_plaintext.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = msg {
                if let Some(extensions_data) = &client_hello.ext {
                    if let Ok((_, parsed_extensions)) = tls_parser::parse_tls_extensions(extensions_data) {
                        for extension in parsed_extensions {
                            if let tls_parser::TlsExtension::ALPN(alpn_protocols) = extension {
                                if !alpn_protocols.is_empty() {
                                    // 根据JA4标准，只取ALPN扩展列表里的第一个协议
                                    let first_protocol = &alpn_protocols[0];
                                    let protocol_str = std::str::from_utf8(first_protocol).unwrap_or("");

                                    // 根据JA4标准映射ALPN协议
                                    return Some(match protocol_str.to_lowercase().as_str() {
                                        "http/1.1" => "h1".to_string(),
                                        "h2" | "http/2" => "h2".to_string(),
                                        "h3" | "http/3" => "h3".to_string(),
                                        "grpc" => "gr".to_string(),
                                        _ => {
                                            if protocol_str.len() >= 2 {
                                                protocol_str[..2].to_lowercase()
                                            } else {
                                                format!("{:0<2}", protocol_str).to_lowercase()
                                            }
                                        }
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Some("00".to_string())
}
