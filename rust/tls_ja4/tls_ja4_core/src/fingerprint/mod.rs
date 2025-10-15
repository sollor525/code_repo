//! 指纹计算模块
//!
//! 提供JA3和JA4指纹计算功能

pub mod ja3;
pub mod ja4;
pub mod utils;
pub mod optimized;
pub mod matcher;

pub use ja3::*;
pub use ja4::*;
pub use utils::*;
pub use optimized::*;
pub use matcher::*;

use crate::ClientHelloResult;

/// 从原始TLS数据解析Client Hello（用于核心库）
pub fn parse_client_hello_with_tls_parser(packet: &[u8]) -> ClientHelloResult {
    crate::tls::parse_client_hello_with_tls_parser(packet)
}

/// 计算JA4_b组件
pub fn calculate_ja4b_from_parsed_data(cipher_suites: &[u16]) -> String {
    // JA4_b算法：对Cipher Suite进行排序，然后计算SHA256哈希的前12位
    use crate::fingerprint::utils::is_grease_value;
    use sha2::{Digest, Sha256};
    use hex;

    // 1. 过滤并排序GREASE值（避免中间Vec分配）
    let mut sorted_ciphers: Vec<u16> = cipher_suites.iter()
        .filter(|&&c| !is_grease_value(c))
        .copied()
        .collect();

    // 2. 从小到大排序
    sorted_ciphers.sort();

    // 3. 转换为十六进制字符串，用逗号分隔
    let cipher_str = sorted_ciphers.iter()
        .map(|&c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");

    let mut hasher = Sha256::new();
    hasher.update(cipher_str.as_bytes());
    let hash = hasher.finalize();

    // Take first 6 bytes = 12 chars
    hex::encode(&hash[..6])
}

/// 计算JA4_c组件
pub fn calculate_ja4c_from_parsed_data(extensions: &[u16], signature_algorithms: &[u16]) -> String {
    // JA4_c算法：对Extensions进行排序并过滤，结合signature_algorithms
    use crate::fingerprint::utils::is_grease_value;
    use sha2::{Digest, Sha256};
    use hex;

    // 1. 过滤Extensions - 移除GREASE值、SNI扩展(0)和ALPN扩展(16)
    let mut filtered_extensions: Vec<u16> = extensions.iter()
        .filter(|&&ext| {
            !is_grease_value(ext) && // 过滤GREASE值
            ext != 0x0000 && // 过滤SNI扩展
            ext != 0x0010    // 过滤ALPN扩展
        })
        .copied()
        .collect();

    // 2. 从小到大排序
    filtered_extensions.sort();

    // 3. 转换为十六进制字符串，用逗号分隔
    let ext_str = filtered_extensions.iter()
        .map(|&e| format!("{:04x}", e))
        .collect::<Vec<_>>()
        .join(",");

    // 4. 处理signature_algorithms - 保持原始顺序（不排序），但过滤GREASE值
    let filtered_sig_algs: Vec<u16> = signature_algorithms.iter()
        .filter(|&&s| !is_grease_value(s))
        .copied()
        .collect();
    let sig_str = filtered_sig_algs.iter()
        .map(|&s| format!("{:04x}", s))
        .collect::<Vec<_>>()
        .join(",");

    // 5. 合并两个字符串，用下划线分隔
    let combined_str = if sig_str.is_empty() {
        ext_str.clone()
    } else {
        format!("{}_{}", ext_str, sig_str)
    };

    let mut hasher = Sha256::new();
    hasher.update(combined_str.as_bytes());
    let hash = hasher.finalize();

    // Take first 6 bytes = 12 chars
    hex::encode(&hash[..6])
}
