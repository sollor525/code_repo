//! JA4指纹计算

use tls_parser::TlsVersion;
use crate::tls::extensions::{is_grease_extension, is_grease_cipher};
use sha2::{Digest, Sha256};

/// 计算JA4指纹
pub fn calculate_ja4_from_parsed_data(
    version: TlsVersion,
    ciphers: &[u16],
    extensions: &[u16],
    _signature_algorithms: &[u16],
    _raw_payload: &[u8],
) -> String {
    // 过滤GREASE密码套件
    let filtered_ciphers: Vec<u16> = ciphers.iter()
        .filter(|&&c| !is_grease_cipher(c))
        .copied()
        .collect();
    
    // 过滤GREASE扩展
    let filtered_extensions: Vec<u16> = extensions.iter()
        .filter(|&&e| !is_grease_extension(e))
        .copied()
        .collect();
    
    // 构建JA4组件
    let tls_version = match version {
        TlsVersion::Ssl30 => "t00",
        TlsVersion::Tls10 => "t10", 
        TlsVersion::Tls11 => "t11",
        TlsVersion::Tls12 => "t12",
        TlsVersion::Tls13 => "t13",
        _ => "t00",
    };
    
    let cipher_count = filtered_ciphers.len();
    let extension_count = filtered_extensions.len();
    
    // 计算密码套件哈希
    let cipher_hash = if filtered_ciphers.is_empty() {
        "0".to_string()
    } else {
        let cipher_str = filtered_ciphers.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut hasher = Sha256::new();
        hasher.update(cipher_str.as_bytes());
        let hash = hasher.finalize();
        format!("{:x}", hash)[..12].to_string()
    };
    
    // 计算扩展哈希
    let extension_hash = if filtered_extensions.is_empty() {
        "0".to_string()
    } else {
        let ext_str = filtered_extensions.iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let mut hasher = Sha256::new();
        hasher.update(ext_str.as_bytes());
        let hash = hasher.finalize();
        format!("{:x}", hash)[..12].to_string()
    };
    
    // 计算ALPN哈希
    let alpn_hash = extract_alpn_hash(_raw_payload);
    
    // 构建JA4指纹
    format!("{}{}d{}{}h{}_{}_{}_{}", 
        tls_version,
        if cipher_count > 9 { "" } else { "0" },
        cipher_count,
        if extension_count > 9 { "" } else { "0" },
        extension_count,
        alpn_hash,
        cipher_hash,
        extension_hash,
    )
}

/// 提取ALPN哈希
fn extract_alpn_hash(payload: &[u8]) -> String {
    use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake};
    
    // 解析TLS包
    if let Ok((_, tls_plaintext)) = parse_tls_plaintext(payload) {
        if let Some(handshake) = tls_plaintext.msg.first() {
            if let TlsMessage::Handshake(handshake_msg) = handshake {
                if let TlsMessageHandshake::ClientHello(client_hello) = handshake_msg {
                    // 查找ALPN扩展
                    if let Some(extensions_data) = &client_hello.ext {
                        match tls_parser::parse_tls_extensions(extensions_data) {
                            Ok((_, parsed_extensions)) => {
                                for extension in parsed_extensions {
                                    if let tls_parser::TlsExtension::ALPN(alpn_protocols) = extension {
                                        if !alpn_protocols.is_empty() {
                                            // 计算ALPN哈希
                                            let alpn_str = alpn_protocols.iter()
                                                .map(|s| std::str::from_utf8(s).unwrap_or(""))
                                                .collect::<Vec<_>>()
                                                .join(",");
                                            
                                            let mut hasher = Sha256::new();
                                            hasher.update(alpn_str.as_bytes());
                                            let hash = hasher.finalize();
                                            return format!("{:x}", hash)[..12].to_string();
                                        }
                                    }
                                }
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }
    }
    
    "0".to_string()
}
