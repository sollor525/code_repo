//! JA3指纹计算

use tls_parser::TlsVersion;
use crate::tls::extensions::{is_grease_extension, is_grease_cipher};
use sha2::{Digest, Sha256};

/// 计算JA3指纹
pub fn calculate_ja3_from_parsed_data(
    version: TlsVersion,
    ciphers: &[u16],
    extensions: &[u16],
    elliptic_curves: &[u16],
    ec_point_formats: &[u8],
) -> Option<String> {
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
    
    // 构建JA3字符串
    let version_str = match version {
        TlsVersion::Ssl30 => "769",
        TlsVersion::Tls10 => "770",
        TlsVersion::Tls11 => "771",
        TlsVersion::Tls12 => "772",
        TlsVersion::Tls13 => "772",
        _ => "0",
    };
    
    let ciphers_str = if filtered_ciphers.is_empty() {
        "-".to_string()
    } else {
        filtered_ciphers.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    
    let extensions_str = if filtered_extensions.is_empty() {
        "-".to_string()
    } else {
        filtered_extensions.iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    
    let curves_str = if elliptic_curves.is_empty() {
        "-".to_string()
    } else {
        elliptic_curves.iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    
    let point_formats_str = if ec_point_formats.is_empty() {
        "-".to_string()
    } else {
        ec_point_formats.iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-")
    };
    
    let ja3_string = format!("{},{},{},{},{}", 
        version_str, ciphers_str, extensions_str, curves_str, point_formats_str);
    
    // 计算SHA256哈希
    let mut hasher = Sha256::new();
    hasher.update(ja3_string.as_bytes());
    let hash = hasher.finalize();
    
    Some(format!("{:x}", hash))
}
