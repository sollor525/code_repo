//! 高性能JA3/JA4指纹计算优化模块

use tls_parser::TlsVersion;
use crate::tls::extensions::{is_grease_extension, is_grease_cipher};
use sha2::{Digest, Sha256};
// use std::collections::hash_map::DefaultHasher;
// use std::hash::{Hash, Hasher};
use std::fmt::Write;

/// 高性能JA4指纹计算
pub fn calculate_ja4_optimized(
    version: TlsVersion,
    ciphers: &[u16],
    extensions: &[u16],
    _signature_algorithms: &[u16],
    raw_payload: &[u8],
) -> String {
    // 使用预分配的StringBuilder避免多次分配
    let mut result = String::with_capacity(64);
    
    // 快速版本映射
    let tls_version = match version {
        TlsVersion::Ssl30 => "t00",
        TlsVersion::Tls10 => "t10", 
        TlsVersion::Tls11 => "t11",
        TlsVersion::Tls12 => "t12",
        TlsVersion::Tls13 => "t13",
        _ => "t00",
    };
    
    // 使用单次遍历过滤GREASE
    let (filtered_ciphers, cipher_count) = filter_grease_single_pass(ciphers, is_grease_cipher);
    let (filtered_extensions, extension_count) = filter_grease_single_pass(extensions, is_grease_extension);
    
    // 构建JA4字符串
    write!(result, "{}", tls_version).unwrap();
    write!(result, "{}", if cipher_count > 9 { "" } else { "0" }).unwrap();
    write!(result, "{}", cipher_count).unwrap();
    write!(result, "{}", if extension_count > 9 { "" } else { "0" }).unwrap();
    write!(result, "{}", extension_count).unwrap();
    write!(result, "h{}_", extension_count).unwrap();
    
    // 快速哈希计算
    let alpn_hash = extract_alpn_hash_fast(raw_payload);
    let cipher_hash = calculate_hash_fast(&filtered_ciphers);
    let extension_hash = calculate_hash_fast(&filtered_extensions);
    
    write!(result, "{}_", alpn_hash).unwrap();
    write!(result, "{}_", cipher_hash).unwrap();
    write!(result, "{}", extension_hash).unwrap();
    
    result
}

/// 高性能JA3指纹计算
pub fn calculate_ja3_optimized(
    version: TlsVersion,
    ciphers: &[u16],
    extensions: &[u16],
    elliptic_curves: &[u16],
    ec_point_formats: &[u8],
) -> Option<String> {
    // 使用预分配的StringBuilder
    let mut ja3_string = String::with_capacity(512);
    
    // 快速版本映射
    let version_str = match version {
        TlsVersion::Ssl30 => "769",
        TlsVersion::Tls10 => "770",
        TlsVersion::Tls11 => "771",
        TlsVersion::Tls12 => "772",
        TlsVersion::Tls13 => "772",
        _ => "0",
    };
    
    // 单次遍历过滤GREASE
    let (filtered_ciphers, _) = filter_grease_single_pass(ciphers, is_grease_cipher);
    let (filtered_extensions, _) = filter_grease_single_pass(extensions, is_grease_extension);
    
    // 构建JA3字符串 - 使用更高效的连接方式
    write!(ja3_string, "{}", version_str).unwrap();
    
    // 密码套件
    if filtered_ciphers.is_empty() {
        write!(ja3_string, ",-").unwrap();
    } else {
        write!(ja3_string, ",").unwrap();
        for (i, &cipher) in filtered_ciphers.iter().enumerate() {
            if i > 0 { write!(ja3_string, "-").unwrap(); }
            write!(ja3_string, "{}", cipher).unwrap();
        }
    }
    
    // 扩展
    if filtered_extensions.is_empty() {
        write!(ja3_string, ",-").unwrap();
    } else {
        write!(ja3_string, ",").unwrap();
        for (i, &ext) in filtered_extensions.iter().enumerate() {
            if i > 0 { write!(ja3_string, "-").unwrap(); }
            write!(ja3_string, "{}", ext).unwrap();
        }
    }
    
    // 椭圆曲线
    if elliptic_curves.is_empty() {
        write!(ja3_string, ",-").unwrap();
    } else {
        write!(ja3_string, ",").unwrap();
        for (i, &curve) in elliptic_curves.iter().enumerate() {
            if i > 0 { write!(ja3_string, "-").unwrap(); }
            write!(ja3_string, "{}", curve).unwrap();
        }
    }
    
    // EC点格式
    if ec_point_formats.is_empty() {
        write!(ja3_string, ",-").unwrap();
    } else {
        write!(ja3_string, ",").unwrap();
        for (i, &format) in ec_point_formats.iter().enumerate() {
            if i > 0 { write!(ja3_string, "-").unwrap(); }
            write!(ja3_string, "{}", format).unwrap();
        }
    }
    
    // 计算SHA256哈希
    let mut hasher = Sha256::new();
    hasher.update(ja3_string.as_bytes());
    let hash = hasher.finalize();
    
    Some(format!("{:x}", hash))
}

/// 单次遍历过滤GREASE，返回过滤后的数据和计数
#[inline]
fn filter_grease_single_pass<T, F>(items: &[T], is_grease: F) -> (Vec<T>, usize)
where
    T: Copy,
    F: Fn(T) -> bool,
{
    let mut filtered = Vec::with_capacity(items.len());
    for &item in items {
        if !is_grease(item) {
            filtered.push(item);
        }
    }
    (filtered.clone(), filtered.len())
}

/// 快速哈希计算 - 使用更高效的字符串构建
#[inline]
fn calculate_hash_fast(items: &[u16]) -> String {
    if items.is_empty() {
        return "0".to_string();
    }
    
    // 使用预分配的StringBuilder
    let mut hash_input = String::with_capacity(items.len() * 6); // 估算容量
    for (i, &item) in items.iter().enumerate() {
        if i > 0 { hash_input.push(','); }
        write!(hash_input, "{}", item).unwrap();
    }
    
    let mut hasher = Sha256::new();
    hasher.update(hash_input.as_bytes());
    let hash = hasher.finalize();
    format!("{:x}", hash)[..12].to_string()
}

/// 快速ALPN哈希提取 - 优化版本
#[inline]
fn extract_alpn_hash_fast(payload: &[u8]) -> String {
    use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake};
    
    // 快速失败检查
    if payload.len() < 5 {
        return "0".to_string();
    }
    
    // 解析TLS包
    if let Ok((_, tls_plaintext)) = parse_tls_plaintext(payload)
        && let Some(handshake) = tls_plaintext.msg.first()
        && let TlsMessage::Handshake(handshake_msg) = handshake
        && let TlsMessageHandshake::ClientHello(client_hello) = handshake_msg
        && let Some(extensions_data) = &client_hello.ext
        && let Ok((_, parsed_extensions)) = tls_parser::parse_tls_extensions(extensions_data) {
        for extension in parsed_extensions {
            if let tls_parser::TlsExtension::ALPN(alpn_protocols) = extension
                && !alpn_protocols.is_empty() {
                // 使用预分配的StringBuilder
                let mut alpn_str = String::with_capacity(alpn_protocols.len() * 10);
                for (i, protocol) in alpn_protocols.iter().enumerate() {
                    if i > 0 { alpn_str.push(','); }
                    alpn_str.push_str(std::str::from_utf8(protocol).unwrap_or(""));
                }

                let mut hasher = Sha256::new();
                hasher.update(alpn_str.as_bytes());
                let hash = hasher.finalize();
                return format!("{:x}", hash)[..12].to_string();
            }
        }
    }
    
    "0".to_string()
}

/// 批量处理优化 - 处理多个指纹计算
pub fn calculate_fingerprints_batch(
    inputs: &[(TlsVersion, &[u16], &[u16], &[u16], &[u8])],
) -> Vec<(String, Option<String>)> {
    inputs.iter()
        .map(|(version, ciphers, extensions, elliptic_curves, raw_payload)| {
            let ja4 = calculate_ja4_optimized(*version, ciphers, extensions, &[], raw_payload);
            let ja3 = calculate_ja3_optimized(*version, ciphers, extensions, elliptic_curves, &[]);
            (ja4, ja3)
        })
        .collect()
}

/// 内存池优化的指纹计算器
pub struct OptimizedFingerprintCalculator {
    // 重用缓冲区避免分配
    cipher_buffer: Vec<u16>,
    extension_buffer: Vec<u16>,
    string_buffer: String,
}

impl OptimizedFingerprintCalculator {
    pub fn new() -> Self {
        Self {
            cipher_buffer: Vec::with_capacity(64),
            extension_buffer: Vec::with_capacity(32),
            string_buffer: String::with_capacity(512),
        }
    }
    
    /// 使用内存池计算JA4
    pub fn calculate_ja4_pooled(
        &mut self,
        version: TlsVersion,
        ciphers: &[u16],
        extensions: &[u16],
        raw_payload: &[u8],
    ) -> String {
        // 清空并重用缓冲区
        self.cipher_buffer.clear();
        self.extension_buffer.clear();
        self.string_buffer.clear();
        
        // 过滤GREASE到重用缓冲区
        for &cipher in ciphers {
            if !is_grease_cipher(cipher) {
                self.cipher_buffer.push(cipher);
            }
        }
        
        for &extension in extensions {
            if !is_grease_extension(extension) {
                self.extension_buffer.push(extension);
            }
        }
        
        // 使用重用缓冲区计算
        calculate_ja4_optimized(
            version,
            &self.cipher_buffer,
            &self.extension_buffer,
            &[],
            raw_payload,
        )
    }
    
    /// 使用内存池计算JA3
    pub fn calculate_ja3_pooled(
        &mut self,
        version: TlsVersion,
        ciphers: &[u16],
        extensions: &[u16],
        elliptic_curves: &[u16],
        ec_point_formats: &[u8],
    ) -> Option<String> {
        // 清空并重用缓冲区
        self.cipher_buffer.clear();
        self.extension_buffer.clear();
        
        // 过滤GREASE到重用缓冲区
        for &cipher in ciphers {
            if !is_grease_cipher(cipher) {
                self.cipher_buffer.push(cipher);
            }
        }
        
        for &extension in extensions {
            if !is_grease_extension(extension) {
                self.extension_buffer.push(extension);
            }
        }
        
        // 使用重用缓冲区计算
        calculate_ja3_optimized(
            version,
            &self.cipher_buffer,
            &self.extension_buffer,
            elliptic_curves,
            ec_point_formats,
        )
    }
}

impl Default for OptimizedFingerprintCalculator {
    fn default() -> Self {
        Self::new()
    }
}

/// 并行处理优化
pub fn calculate_fingerprints_parallel(
    inputs: &[(TlsVersion, &[u16], &[u16], &[u16], &[u8])],
) -> Vec<(String, Option<String>)> {
    use rayon::prelude::*;
    
    inputs.par_iter()
        .map(|(version, ciphers, extensions, elliptic_curves, raw_payload)| {
            let ja4 = calculate_ja4_optimized(*version, ciphers, extensions, &[], raw_payload);
            let ja3 = calculate_ja3_optimized(*version, ciphers, extensions, elliptic_curves, &[]);
            (ja4, ja3)
        })
        .collect()
}
