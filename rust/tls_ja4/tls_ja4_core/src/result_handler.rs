//! 结果处理模块
//!
//! 提供统一的错误处理和结果填充功能

use crate::c_api::types::*;
use crate::errors::TlsJa4Error;

// 类型别名，避免命名冲突
pub type TlsJa4ResultType = TlsJa4Result;

/// C API结果处理器
pub struct CResultHandler;

impl CResultHandler {
    /// 创建失败结果
    pub fn create_error_result(
        result: *mut TlsJa4Result,
        error: TlsJa4Error,
        timestamp: u64,
    ) -> i32 {
        if result.is_null() {
            return error.to_c_error_code();
        }

        unsafe {
            let result_ref = &mut *result;
            Self::reset_result(result_ref);
            result_ref.status_code = error.to_c_error_code();
            result_ref.timestamp = timestamp;
        }

        error.to_c_error_code()
    }

    /// 创建成功结果
    pub fn create_success_result(
        result: *mut TlsJa4Result,
        fingerprint_data: &FingerprintData,
        timestamp: u64,
        is_match: bool,
    ) -> i32 {
        if result.is_null() {
            return TlsJa4Error::InvalidParameter.to_c_error_code();
        }

        unsafe {
            let result_ref = &mut *result;
            Self::fill_fingerprint_data(result_ref, fingerprint_data);
            result_ref.is_client_hello = 1;
            result_ref.is_complete = 1;
            result_ref.status_code = 0; // TLS_JA4_SUCCESS
            result_ref.timestamp = timestamp;
            result_ref.is_match = if is_match { 1 } else { 0 };
        }

        0 // TLS_JA4_SUCCESS
    }

    /// 重置结果结构体
    fn reset_result(result_ref: &mut TlsJa4ResultType) {
        result_ref.fingerprint = TlsJa4Fingerprint {
            fingerprint: [0; 64],
            fingerprint_len: 0,
            tls_version: 0,
            cipher_count: 0,
            extension_count: 0,
        };
        result_ref.is_client_hello = 0;
        result_ref.is_complete = 0;
        result_ref.status_code = 0;
        result_ref.timestamp = 0;
        result_ref.is_match = 0;
    }

    /// 填充指纹数据
    fn fill_fingerprint_data(result_ref: &mut TlsJa4ResultType, data: &FingerprintData) {
        if let Some(ref fingerprint) = data.fingerprint {
            let fingerprint_bytes = fingerprint.as_bytes();
            let copy_len = std::cmp::min(fingerprint_bytes.len(), result_ref.fingerprint.fingerprint.len());
            result_ref.fingerprint.fingerprint[..copy_len].copy_from_slice(&fingerprint_bytes[..copy_len]);
            result_ref.fingerprint.fingerprint_len = copy_len as u32;
        }

        if let Some(tls_version) = data.tls_version {
            result_ref.fingerprint.tls_version = tls_version;
        }

        if let Some(cipher_count) = data.cipher_count {
            result_ref.fingerprint.cipher_count = cipher_count;
        }

        if let Some(extension_count) = data.extension_count {
            result_ref.fingerprint.extension_count = extension_count;
        }
    }
}

/// 指纹数据结构
#[derive(Debug, Clone)]
pub struct FingerprintData {
    pub fingerprint: Option<String>,
    pub tls_version: Option<u16>,
    pub cipher_count: Option<u16>,
    pub extension_count: Option<u16>,
}

impl FingerprintData {
    /// 创建新的指纹数据
    pub fn new() -> Self {
        Self {
            fingerprint: None,
            tls_version: None,
            cipher_count: None,
            extension_count: None,
        }
    }

    /// 设置指纹
    pub fn with_fingerprint(mut self, fingerprint: String) -> Self {
        self.fingerprint = Some(fingerprint);
        self
    }

    /// 设置TLS版本
    pub fn with_tls_version(mut self, version: u16) -> Self {
        self.tls_version = Some(version);
        self
    }

    /// 设置密码套件数量
    pub fn with_cipher_count(mut self, count: u16) -> Self {
        self.cipher_count = Some(count);
        self
    }

    /// 设置扩展数量
    pub fn with_extension_count(mut self, count: u16) -> Self {
        self.extension_count = Some(count);
        self
    }
}

impl Default for FingerprintData {
    fn default() -> Self {
        Self::new()
    }
}