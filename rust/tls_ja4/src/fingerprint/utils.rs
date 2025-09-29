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
