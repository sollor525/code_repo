//! C API函数实现

use std::ffi::c_void;
use crate::network::{parse_ip_header, parse_tcp_header, generate_flow_key};
use crate::tls::{is_tls_packet, is_client_hello, parse_client_hello_with_tls_parser, tls_version_to_u16};
use crate::fingerprint::{calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data};
use crate::cache::{InternalContext, SegmentCache};
use super::types::*;
use super::errors::*;

/// 初始化TLS JA4上下文
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_init() -> *mut TlsJa4Context {
    let internal_ctx = Box::new(InternalContext::new());
    
    let ctx = Box::new(TlsJa4Context {
        _internal: Box::into_raw(internal_ctx) as *mut c_void,
    });
    
    Box::into_raw(ctx)
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

/// 统一报文分析接口 - 处理从IP头开始的完整报文
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_analyze_packet(
    ctx: *mut TlsJa4Context,
    packet_data: *const u8,
    packet_len: u32,
    result: *mut TlsJa4Result,
) -> i32 {
    if packet_data.is_null() || result.is_null() || packet_len == 0 {
        return TLS_JA4_INVALID_PARAMETER;
    }

    let packet_slice = unsafe {
        std::slice::from_raw_parts(packet_data, packet_len as usize)
    };

    // 解析IP头
    let ip_header = match parse_ip_header(packet_slice) {
        Ok(header) => header,
        Err(e) => {
            let result_ref = unsafe { &mut *result };
            result_ref.is_client_hello = 0;
            result_ref.is_complete = 0;
            result_ref.status_code = e;
            result_ref.cached_bytes = 0;
            result_ref.flow_id = 0;
            result_ref.timestamp = 0;
            return e;
        }
    };

    // 只处理TCP协议
    if ip_header.protocol != 6 {
        let result_ref = unsafe { &mut *result };
        result_ref.is_client_hello = 0;
        result_ref.is_complete = 0;
        result_ref.status_code = TLS_JA4_NOT_TLS;
        result_ref.cached_bytes = 0;
        result_ref.flow_id = 0;
        result_ref.timestamp = 0;
        return TLS_JA4_NOT_TLS;
    }

    // 解析TCP头
    let tcp_header = match parse_tcp_header(packet_slice, ip_header.header_len) {
        Ok(header) => header,
        Err(e) => {
            let result_ref = unsafe { &mut *result };
            result_ref.is_client_hello = 0;
            result_ref.is_complete = 0;
            result_ref.status_code = e;
            result_ref.cached_bytes = 0;
            result_ref.flow_id = 0;
            result_ref.timestamp = 0;
            return e;
        }
    };

    // 获取TCP载荷
    if packet_slice.len() <= tcp_header.payload_offset {
        let result_ref = unsafe { &mut *result };
        result_ref.is_client_hello = 0;
        result_ref.is_complete = 0;
        result_ref.status_code = TLS_JA4_INSUFFICIENT_DATA;
        result_ref.cached_bytes = 0;
        result_ref.flow_id = 0;
        result_ref.timestamp = 0;
        return TLS_JA4_INSUFFICIENT_DATA;
    }

    let tcp_payload = &packet_slice[tcp_header.payload_offset..];

    // 如果ctx为NULL，内部自动管理
    let mut internal_ctx_owned = Some(InternalContext::new());
    let internal_ctx = if ctx.is_null() {
        &mut internal_ctx_owned.as_mut().unwrap()
    } else {
        unsafe { &mut *((ctx as *mut TlsJa4Context).as_ref().unwrap()._internal as *mut InternalContext) }
    };

    // 生成流键
    let flow_key = generate_flow_key(&ip_header.src_ip, &ip_header.dst_ip, tcp_header.src_port, tcp_header.dst_port);
    
    // 获取当前时间戳
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // 检查缓存限制
    if internal_ctx.segment_cache.len() >= internal_ctx.config.max_flows as usize {
        // 清理最旧的流
        let oldest_key = internal_ctx.segment_cache.iter()
            .min_by_key(|(_, cache)| cache.last_activity)
            .map(|(k, _)| k.clone());
        
        if let Some(key) = oldest_key {
            internal_ctx.segment_cache.remove(&key);
        }
    }

    // 检查缓存大小限制
    let current_cache_size = internal_ctx.segment_cache.get(&flow_key)
        .map(|cache| cache.data.len())
        .unwrap_or(0);
    
    if current_cache_size + tcp_payload.len() > internal_ctx.config.max_bytes_per_flow as usize {
        // 缓存溢出，清理并返回
        internal_ctx.segment_cache.remove(&flow_key);
        let result_ref = unsafe { &mut *result };
        result_ref.is_client_hello = 0;
        result_ref.is_complete = 0;
        result_ref.status_code = TLS_JA4_CACHE_OVERFLOW;
        result_ref.cached_bytes = 0;
        result_ref.flow_id = 0;
        result_ref.timestamp = current_time;
        return TLS_JA4_CACHE_OVERFLOW;
    }

    // 获取或创建分段缓存
    let cache = internal_ctx.segment_cache.entry(flow_key.clone()).or_insert_with(|| {
        SegmentCache {
            data: Vec::new(),
            expected_len: 0,
            is_complete: false,
            last_activity: current_time,
            flow_id: internal_ctx.next_flow_id,
        }
    });

    // 更新活动时间
    cache.last_activity = current_time;

    // 添加数据到缓存
    cache.data.extend_from_slice(tcp_payload);

    // 尝试解析TLS记录长度
    if cache.expected_len == 0 && cache.data.len() >= 5 {
        let record_len = ((cache.data[3] as u16) << 8 | cache.data[4] as u16) as usize;
        cache.expected_len = 5 + record_len;
    }

    // 检查是否有足够的数据
    let should_parse = cache.expected_len > 0 && cache.data.len() >= cache.expected_len;
    
    if should_parse {
        // 有完整的数据，尝试解析
        let complete_data = cache.data[..cache.expected_len].to_vec();
        let flow_id = cache.flow_id;
        
        // 清理缓存
        internal_ctx.segment_cache.remove(&flow_key);
        
        if is_tls_packet(&complete_data) && is_client_hello(&complete_data) {
            match parse_client_hello_with_tls_parser(&complete_data) {
                Some((version, ciphers, extensions, elliptic_curves, ec_point_formats, signature_algorithms)) => {
                    let ja4 = calculate_ja4_from_parsed_data(version, &ciphers, &extensions, &signature_algorithms, &complete_data);
                    let ja3 = calculate_ja3_from_parsed_data(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats)
                        .unwrap_or_else(|| "0".to_string());

                    let result_ref = unsafe { &mut *result };
                    
                    // 填充指纹数据
                    let ja4_bytes = ja4.as_bytes();
                    let ja3_bytes = ja3.as_bytes();
                    
                    result_ref.fingerprint.ja4[..ja4_bytes.len()].copy_from_slice(ja4_bytes);
                    result_ref.fingerprint.ja4_len = ja4_bytes.len() as u32;
                    
                    result_ref.fingerprint.ja3[..ja3_bytes.len()].copy_from_slice(ja3_bytes);
                    result_ref.fingerprint.ja3_len = ja3_bytes.len() as u32;
                    
                    result_ref.fingerprint.tls_version = tls_version_to_u16(version);
                    result_ref.fingerprint.cipher_count = ciphers.len() as u16;
                    result_ref.fingerprint.extension_count = extensions.len() as u16;
                    
                    result_ref.is_client_hello = 1;
                    result_ref.is_complete = 1;
                    result_ref.status_code = TLS_JA4_SUCCESS;
                    result_ref.cached_bytes = 0;
                    result_ref.flow_id = flow_id;
                    result_ref.timestamp = current_time;
                    
                    return TLS_JA4_SUCCESS;
                },
                None => {
                    // 解析失败
                    let result_ref = unsafe { &mut *result };
                    result_ref.is_client_hello = 0;
                    result_ref.is_complete = 0;
                    result_ref.status_code = TLS_JA4_NOT_CLIENT_HELLO;
                    result_ref.cached_bytes = 0;
                    result_ref.flow_id = flow_id;
                    result_ref.timestamp = current_time;
                    return TLS_JA4_NOT_CLIENT_HELLO;
                }
            }
        } else {
            // 不是TLS Client Hello
            let result_ref = unsafe { &mut *result };
            result_ref.is_client_hello = 0;
            result_ref.is_complete = 0;
            result_ref.status_code = TLS_JA4_NOT_CLIENT_HELLO;
            result_ref.cached_bytes = 0;
            result_ref.flow_id = flow_id;
            result_ref.timestamp = current_time;
            return TLS_JA4_NOT_CLIENT_HELLO;
        }
    } else {
        // 数据不足，继续缓存
        let result_ref = unsafe { &mut *result };
        result_ref.is_client_hello = 0;
        result_ref.is_complete = 0;
        result_ref.status_code = TLS_JA4_SEGMENT_CACHED;
        result_ref.cached_bytes = cache.data.len() as u32;
        result_ref.flow_id = cache.flow_id;
        result_ref.timestamp = current_time;
        return TLS_JA4_SEGMENT_CACHED;
    }
}

/// 设置缓存限制
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_set_cache_limits(
    ctx: *mut TlsJa4Context,
    max_flows: u32,
    max_bytes_per_flow: u32,
    timeout_ms: u64,
) -> i32 {
    if ctx.is_null() {
        return TLS_JA4_INVALID_PARAMETER;
    }

    let internal_ctx = unsafe { &mut *((ctx as *mut TlsJa4Context).as_ref().unwrap()._internal as *mut InternalContext) };
    
    internal_ctx.set_cache_limits(max_flows, max_bytes_per_flow, timeout_ms);
    
    TLS_JA4_SUCCESS
}

/// 清理超时的缓存
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_cleanup_timeout_cache(
    ctx: *mut TlsJa4Context,
) -> i32 {
    if ctx.is_null() {
        return TLS_JA4_INVALID_PARAMETER;
    }

    let internal_ctx = unsafe { &mut *((ctx as *mut TlsJa4Context).as_ref().unwrap()._internal as *mut InternalContext) };
    
    internal_ctx.cleanup_timeout_cache();
    
    TLS_JA4_SUCCESS
}

/// 获取缓存统计信息
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_get_cache_stats(
    ctx: *mut TlsJa4Context,
    active_flows: *mut u32,
    total_cached_bytes: *mut u32,
) -> i32 {
    if ctx.is_null() || active_flows.is_null() || total_cached_bytes.is_null() {
        return TLS_JA4_INVALID_PARAMETER;
    }

    let internal_ctx = unsafe { &mut *((ctx as *mut TlsJa4Context).as_ref().unwrap()._internal as *mut InternalContext) };
    
    let (flows, total_bytes) = internal_ctx.get_cache_stats();
    
    unsafe {
        *active_flows = flows;
        *total_cached_bytes = total_bytes;
    }
    
    TLS_JA4_SUCCESS
}

/// 清理TLS JA4上下文
#[unsafe(no_mangle)]
pub extern "C" fn tls_ja4_cleanup(ctx: *mut TlsJa4Context) {
    if !ctx.is_null() {
        unsafe {
            let internal_ctx = Box::from_raw((ctx as *mut TlsJa4Context).as_ref().unwrap()._internal as *mut InternalContext);
            drop(internal_ctx);
            let _ = Box::from_raw(ctx);
        }
    }
}
