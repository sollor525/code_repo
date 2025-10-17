//! C兼容的类型定义

/// JA4指纹结果结构体
#[repr(C)]
pub struct TlsJa4Fingerprint {
    pub fingerprint: [u8; 64],  /* 指纹，固定长度缓冲区 */
    pub fingerprint_len: u32,   /* 指纹实际长度 */
    pub tls_version: u16,       /* TLS版本 */
    pub cipher_count: u16,      /* 密码套件数量 */
    pub extension_count: u16,   /* 扩展数量 */
}

/// JA3分析结果结构体
#[repr(C)]
pub struct TlsJa3Result {
    pub fingerprint: TlsJa4Fingerprint, /* JA3指纹数据 */
    pub is_client_hello: u8,            /* 是否为Client Hello */
    pub is_complete: u8,                 /* 分析是否完成 */
    pub status_code: i32,               /* 返回状态码 */
    pub timestamp: u64,                 /* 时间戳（毫秒） */
}

/// JA4分析结果结构体
#[repr(C)]
pub struct TlsJa4Result {
    pub fingerprint: TlsJa4Fingerprint, /* JA4指纹数据 */
    pub is_client_hello: u8,            /* 是否为Client Hello */
    pub is_complete: u8,                 /* 分析是否完成 */
    pub status_code: i32,               /* 返回状态码 */
    pub timestamp: u64,                 /* 时间戳（毫秒） */
    pub is_match: u8,                   /* JA4指纹是否匹配数据库中的条目（1=匹配，0=不匹配） */
}

/// C兼容的上下文结构体（线程私有设计，支持分段TLS处理）
#[repr(C)]
pub struct TlsJa4Context {
    pub _internal: *mut std::ffi::c_void, /* 内部上下文指针 */
}
