//! 工具函数模块
//!
//! 提供常用的工具函数

/// 检查是否为GREASE值
pub fn is_grease_value(value: u16) -> bool {
    let high_byte = (value >> 8) & 0xFF;
    let low_byte = value & 0xFF;
    (high_byte & 0x0F) == 0x0A && (low_byte & 0x0F) == 0x0A && (high_byte >> 4) == (low_byte >> 4)
}

/// 将TlsVersion转换为u16
pub fn tls_version_to_u16(version: tls_parser::TlsVersion) -> u16 {
    match version {
        tls_parser::TlsVersion::Ssl30 => 0x0300,
        tls_parser::TlsVersion::Tls10 => 0x0301,
        tls_parser::TlsVersion::Tls11 => 0x0302,
        tls_parser::TlsVersion::Tls12 => 0x0303,
        tls_parser::TlsVersion::Tls13 => 0x0304,
        _ => 0x0303,
    }
}