//! C API函数实现 - 简化版本

use crate::tls::{is_tls_packet, is_client_hello, parse_client_hello_with_tls_parser};
use crate::fingerprint::{calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data};
use crate::fingerprint::utils::tls_version_to_u16;
use super::types::*;
use super::errors::*;

/// 初始化TLS JA4上下文
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_init() -> *mut TlsJa4Context {
    // 简化实现：返回空指针表示未实现
    std::ptr::null_mut()
}

/// 检测是否为TLS包
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_is_tls_packet(
    tcp_payload: *const u8,
    payload_len: u32,
) -> i32 {
    if tcp_payload.is_null() || payload_len == 0 {
        return TLS_JA4_INVALID_PARAMETER;
    }

    let payload_slice = unsafe {
        std::slice::from_raw_parts(tcp_payload, payload_len as usize)
    };

    if is_tls_packet(payload_slice) {
        TLS_JA4_SUCCESS
    } else {
        TLS_JA4_NOT_TLS
    }
}

/// 检测是否为Client Hello
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_is_client_hello(
    tcp_payload: *const u8,
    payload_len: u32,
) -> i32 {
    if tcp_payload.is_null() || payload_len == 0 {
        return TLS_JA4_INVALID_PARAMETER;
    }

    let payload_slice = unsafe {
        std::slice::from_raw_parts(tcp_payload, payload_len as usize)
    };

    if is_client_hello(payload_slice) {
        TLS_JA4_SUCCESS
    } else {
        TLS_JA4_NOT_CLIENT_HELLO
    }
}

/// 分析TLS Client Hello数据（仅TLS载荷）
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_analyze_client_hello(
    tls_payload: *const u8,
    payload_len: u32,
    result: *mut TlsJa4Result,
) -> i32 {
    if tls_payload.is_null() || result.is_null() || payload_len == 0 {
        return TLS_JA4_INVALID_PARAMETER;
    }

    let payload_slice = unsafe {
        std::slice::from_raw_parts(tls_payload, payload_len as usize)
    };

    // 获取当前时间戳
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    if is_tls_packet(payload_slice) && is_client_hello(payload_slice) {
        match parse_client_hello_with_tls_parser(payload_slice) {
            Some((version, ciphers, extensions, elliptic_curves, ec_point_formats, signature_algorithms)) => {
                let ja4 = calculate_ja4_from_parsed_data(version, &ciphers, &extensions, &signature_algorithms, payload_slice);
                let ja3 = calculate_ja3_from_parsed_data(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats)
                    .unwrap_or_else(|| "0".to_string());

                let result_ref = unsafe { &mut *result };

                // 填充指纹数据
                let ja4_bytes = ja4.as_bytes();
                let ja3_bytes = ja3.as_bytes();

                let ja4_len = ja4_bytes.len().min(256);
                let ja3_len = ja3_bytes.len().min(256);

                result_ref.fingerprint.ja4[..ja4_len].copy_from_slice(&ja4_bytes[..ja4_len]);
                result_ref.fingerprint.ja4_len = ja4_len as u32;

                result_ref.fingerprint.ja3[..ja3_len].copy_from_slice(&ja3_bytes[..ja3_len]);
                result_ref.fingerprint.ja3_len = ja3_len as u32;

                result_ref.fingerprint.tls_version = tls_version_to_u16(version);
                result_ref.fingerprint.cipher_count = ciphers.len() as u16;
                result_ref.fingerprint.extension_count = extensions.len() as u16;

                result_ref.is_client_hello = 1;
                result_ref.is_complete = 1;
                result_ref.status_code = TLS_JA4_SUCCESS;
                result_ref.cached_bytes = 0;
                result_ref.flow_id = 0;
                result_ref.timestamp = current_time;
                result_ref.is_match = 0; // 需要数据库支持

                TLS_JA4_SUCCESS
            },
            None => {
                let result_ref = unsafe { &mut *result };
                result_ref.is_client_hello = 0;
                result_ref.is_complete = 0;
                result_ref.status_code = TLS_JA4_NOT_CLIENT_HELLO;
                result_ref.cached_bytes = 0;
                result_ref.flow_id = 0;
                result_ref.timestamp = current_time;
                TLS_JA4_NOT_CLIENT_HELLO
            }
        }
    } else {
        let result_ref = unsafe { &mut *result };
        result_ref.is_client_hello = 0;
        result_ref.is_complete = 0;
        result_ref.status_code = TLS_JA4_NOT_CLIENT_HELLO;
        result_ref.cached_bytes = 0;
        result_ref.flow_id = 0;
        result_ref.timestamp = current_time;
        TLS_JA4_NOT_CLIENT_HELLO
    }
}

/// 清理TLS JA4上下文
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_cleanup(_ctx: *mut TlsJa4Context) {
    // 简化实现：空操作
}