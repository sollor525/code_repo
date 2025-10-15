//! 网络包解析模块
//!
//! 提供IP、TCP包解析和流管理功能

pub mod ip;
pub mod tcp;
pub mod flow;

pub use ip::*;
pub use tcp::*;
pub use flow::*;

/// 格式化IP地址
pub fn format_ip(ip: &[u8]) -> String {
    if ip.len() == 4 {
        // IPv4
        format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15])
    } else if ip.len() == 16 {
        // IPv6 - 简化格式
        let mut result = String::new();
        for (i, chunk) in ip.chunks_exact(2).enumerate() {
            if i > 0 {
                result.push(':');
            }
            result.push_str(&format!("{:02x}{:02x}", chunk[0], chunk[1]));
        }
        result
    } else {
        "unknown".to_string()
    }
}
