//! C API函数实现 - 简化版本

use crate::tls::{is_tls_packet, is_client_hello, parse_client_hello_with_tls_parser};
use crate::fingerprint::{calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data};
use crate::fingerprint::utils::tls_version_to_u16;
use super::types::*;
use super::errors::*;

/// 初始化TLS上下文
#[unsafe(no_mangle)]
pub extern "C" fn tls_init() -> *mut TlsJa4Context {
    // 简化实现：创建一个空的上下文
    // 在实际实现中，这里需要分配内存并初始化内部状态
    let ctx = Box::new(TlsJa4Context {
        _internal: std::ptr::null_mut(),
    });
    Box::into_raw(ctx)
}

/// 检测是否为TLS包
#[unsafe(no_mangle)]
pub extern "C" fn tls_is_tls_packet(
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
pub extern "C" fn tls_is_client_hello(
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

/// 计算JA3指纹（仅TLS载荷）
#[unsafe(no_mangle)]
pub extern "C" fn tls_calculate_ja3(
    tls_payload: *const u8,
    payload_len: u32,
    result: *mut TlsJa3Result,
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
            Some((version, ciphers, extensions, elliptic_curves, ec_point_formats, _signature_algorithms)) => {
                let ja3 = calculate_ja3_from_parsed_data(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats)
                    .unwrap_or_else(|| "0".to_string());

                let result_ref = unsafe { &mut *result };

                // 填充JA3指纹数据
                let ja3_bytes = ja3.as_bytes();
                let ja3_len = ja3_bytes.len().min(64);

                result_ref.fingerprint.fingerprint[..ja3_len].copy_from_slice(&ja3_bytes[..ja3_len]);
                result_ref.fingerprint.fingerprint_len = ja3_len as u32;
                result_ref.fingerprint.tls_version = tls_version_to_u16(version);
                result_ref.fingerprint.cipher_count = ciphers.len() as u16;
                result_ref.fingerprint.extension_count = extensions.len() as u16;

                result_ref.is_client_hello = 1;
                result_ref.is_complete = 1;
                result_ref.status_code = TLS_JA4_SUCCESS;
                result_ref.timestamp = current_time;

                TLS_JA4_SUCCESS
            },
            None => {
                let result_ref = unsafe { &mut *result };
                result_ref.is_client_hello = 0;
                result_ref.is_complete = 0;
                result_ref.status_code = TLS_JA4_NOT_CLIENT_HELLO;
                result_ref.timestamp = current_time;
                TLS_JA4_NOT_CLIENT_HELLO
            }
        }
    } else {
        let result_ref = unsafe { &mut *result };
        result_ref.is_client_hello = 0;
        result_ref.is_complete = 0;
        result_ref.status_code = TLS_JA4_NOT_CLIENT_HELLO;
        result_ref.timestamp = current_time;
        TLS_JA4_NOT_CLIENT_HELLO
    }
}

/// 计算JA4指纹（仅TLS载荷）
#[unsafe(no_mangle)]
pub extern "C" fn tls_calculate_ja4(
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
            Some((version, ciphers, extensions, _elliptic_curves, _ec_point_formats, signature_algorithms)) => {
                let ja4 = calculate_ja4_from_parsed_data(version, &ciphers, &extensions, &signature_algorithms, payload_slice);

                let result_ref = unsafe { &mut *result };

                // 填充JA4指纹数据
                let ja4_bytes = ja4.as_bytes();
                let ja4_len = ja4_bytes.len().min(64);

                result_ref.fingerprint.fingerprint[..ja4_len].copy_from_slice(&ja4_bytes[..ja4_len]);
                result_ref.fingerprint.fingerprint_len = ja4_len as u32;
                result_ref.fingerprint.tls_version = tls_version_to_u16(version);
                result_ref.fingerprint.cipher_count = ciphers.len() as u16;
                result_ref.fingerprint.extension_count = extensions.len() as u16;

                result_ref.is_client_hello = 1;
                result_ref.is_complete = 1;
                result_ref.status_code = TLS_JA4_SUCCESS;
                result_ref.timestamp = current_time;
                result_ref.is_match = 0; // 需要数据库支持

                TLS_JA4_SUCCESS
            },
            None => {
                let result_ref = unsafe { &mut *result };
                result_ref.is_client_hello = 0;
                result_ref.is_complete = 0;
                result_ref.status_code = TLS_JA4_NOT_CLIENT_HELLO;
                result_ref.timestamp = current_time;
                TLS_JA4_NOT_CLIENT_HELLO
            }
        }
    } else {
        let result_ref = unsafe { &mut *result };
        result_ref.is_client_hello = 0;
        result_ref.is_complete = 0;
        result_ref.status_code = TLS_JA4_NOT_CLIENT_HELLO;
        result_ref.timestamp = current_time;
        TLS_JA4_NOT_CLIENT_HELLO
    }
}

/// 加载JA4指纹数据库
#[unsafe(no_mangle)]
pub extern "C" fn tls_load_database(
    ctx: *mut TlsJa4Context,
    db_path: *const std::ffi::c_char,
) -> i32 {
    if ctx.is_null() || db_path.is_null() {
        return TLS_JA4_INVALID_PARAMETER;
    }

    // 简化实现：返回成功，但不实际加载数据库
    // 在实际实现中，这里需要：
    // 1. 读取JSON数据库文件
    // 2. 解析JA4指纹条目
    // 3. 存储到上下文中供后续查询
    TLS_JA4_SUCCESS
}

/// 匹配JA4指纹
#[unsafe(no_mangle)]
pub extern "C" fn tls_match_fingerprint(
    ctx: *mut TlsJa4Context,
    fingerprint: *const std::ffi::c_char,
) -> i32 {
    if ctx.is_null() || fingerprint.is_null() {
        return 0; // 不匹配
    }

    // 将C字符串转换为Rust字符串
    let fp_str = unsafe {
        std::ffi::CStr::from_ptr(fingerprint)
    }.to_str().unwrap_or("");

    // 简化实现：检查一些已知的指纹
    let known_fingerprints = [
        "t13d1517h2_8daaf6152771_b0da82dd1658",
        "t13i181000_85036bcba153_d41ae481755e",
        "t13d1516h2_8daaf6152771_02713d6af862",
        "q13d0312h3_55b375c5d22e_06cda9e17597",
        "t13d1517h2_8daaf6152771_b1ff8ab2d16f",
        "t13d190900_9dc949149365_97f8aa674fd9",
    ];

    if known_fingerprints.contains(&fp_str) {
        1 // 匹配
    } else {
        0 // 不匹配
    }
}



/// 清理TLS上下文
#[unsafe(no_mangle)]
pub extern "C" fn tls_cleanup(ctx: *mut TlsJa4Context) {
    if ctx.is_null() {
        return;
    }

    // 将指针转换回Box并释放内存
    unsafe {
        let _ctx = Box::from_raw(ctx);
    }
}