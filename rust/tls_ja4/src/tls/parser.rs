//! TLS包解析功能

use tls_parser::TlsVersion;

/// 检测是否为TLS包
pub fn is_tls_packet(payload: &[u8]) -> bool {
    if payload.len() < 5 {
        return false;
    }
    
    // 检查TLS记录头
    let content_type = payload[0];
    let version_major = payload[1];
    let version_minor = payload[2];
    
    // TLS内容类型：0x16 = Handshake, 0x14 = ChangeCipherSpec, 0x15 = Alert, 0x17 = Application
    let is_tls_content_type = matches!(content_type, 0x14 | 0x15 | 0x16 | 0x17);
    
    // TLS版本检查（3.x系列）
    let is_tls_version = version_major == 0x03 && version_minor <= 0x04;
    
    is_tls_content_type && is_tls_version
}

/// 检测是否为Client Hello
pub fn is_client_hello(payload: &[u8]) -> bool {
    if !is_tls_packet(payload) {
        return false;
    }
    
    if payload.len() < 6 {
        return false;
    }
    
    // 检查是否为Handshake消息
    if payload[0] != 0x16 {
        return false;
    }
    
    // 检查Handshake类型是否为Client Hello (0x01)
    if payload.len() < 6 || payload[5] != 0x01 {
        return false;
    }
    
    true
}

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
