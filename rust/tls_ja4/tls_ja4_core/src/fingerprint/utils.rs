//! 指纹计算工具函数

use tls_parser::TlsVersion;

/// TLS版本转换为u16
pub fn tls_version_to_u16(version: TlsVersion) -> u16 {
    match version {
        TlsVersion::Ssl30 => 0x0300,
        TlsVersion::Tls10 => 0x0301,
        TlsVersion::Tls11 => 0x0302,
        TlsVersion::Tls12 => 0x0303,
        TlsVersion::Tls13 => 0x0304,
        _ => 0x0000,
    }
}

/// 检查是否为GREASE值
pub fn is_grease_value(value: u16) -> bool {
    // GREASE值遵循模式：0x?a?a，其中?是相同的十六进制数字
    let high_byte = (value >> 8) & 0xFF;
    let low_byte = value & 0xFF;

    // 检查是否为GREASE模式：高字节和低字节都是?a的形式，且高低字节的高4位相同
    (high_byte & 0x0F) == 0x0A && (low_byte & 0x0F) == 0x0A && (high_byte >> 4) == (low_byte >> 4)
}
