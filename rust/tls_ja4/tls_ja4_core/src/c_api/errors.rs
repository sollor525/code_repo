//! C API错误码定义

/// 成功
pub const TLS_JA4_SUCCESS: i32 = 0;

/// 无效参数
pub const TLS_JA4_INVALID_PARAMETER: i32 = -1;
pub const TLS_JA4_INVALID_PACKET: i32 = -2;

/// 非TLS报文
pub const TLS_JA4_NOT_TLS: i32 = -2;

/// 非Client Hello
pub const TLS_JA4_NOT_CLIENT_HELLO: i32 = -3;

/// 数据不足
pub const TLS_JA4_INSUFFICIENT_DATA: i32 = -4;

/// 分段缓存中
pub const TLS_JA4_SEGMENT_CACHED: i32 = -5;

/// 缓存溢出
pub const TLS_JA4_CACHE_OVERFLOW: i32 = -9;

/// 缓存超时
pub const TLS_JA4_CACHE_TIMEOUT: i32 = -10;

/// IPv6暂不支持
pub const TLS_JA4_IPV6_NOT_SUPPORTED: i32 = -11;

/// TCP重组失败
pub const TLS_JA4_TCP_REASSEMBLY_FAILED: i32 = -12;
