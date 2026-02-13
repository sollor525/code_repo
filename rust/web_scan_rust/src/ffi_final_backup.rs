//! FFI类型定义模块
//!
//! 定义C语言兼容的数据结构，供FFI接口使用

use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_uint, c_ulong};

/// C兼容的结果结构体
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WebScanResultFFI {
    pub is_matched: bool,
    pub rule_id: u32,
    pub action: WebScanActionFFI,
    pub content_length: u32,
    pub protocol: WebScanProtocolFFI,
    pub confidence: u8,
}

/// C兼容的动作枚举
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WebScanActionFFI {
    Alert = 0,
    Drop = 1,
    Pass = 2,
    Log = 3,
}

/// C兼容的协议枚举
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WebScanProtocolFFI {
    Unknown = 0,
    HTTP = 1,
    HTTPS = 2,
    HTTP2 = 3,
}

/// C兼容的统计结构体
#[repr(C)]
#[derive(Debug, Clone)]
pub struct WebScanStatsFFI {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub total_sessions: u64,
    pub active_sessions: u64,
    pub total_matches: u64,
    pub processing_time_ms: u64,
}

/// C兼容的输入验证结果枚举
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputValidationResult {
    Success = 0,
    NullPointer = -1,
    EmptyInput = -2,
    InvalidLength = -3,
    InvalidSession = -4,
    TooLarge = -5,
    DangerousPattern = -6,
}

/// 输入验证器结构体
#[derive(Debug)]
pub struct InputValidator {
    pub max_payload_size: usize,
    pub max_sessions: u64,
    pub allowed_chars: String,
}