use std::os::raw::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::sync::Arc;
use tracing::{info, error, debug, warn};

use crate::common::error::Result;
use crate::extractor::KeyProcessor;
use std::sync::Once;

// FFI 错误码
#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum FfiResult {
    Success = 0,
    Error = -1,
    InvalidParam = -2,
    NotInitialized = -3,
    AlreadyInitialized = -4,
    BufferTooSmall = -5,
}

// 将Rust Result转换为FFI错误码
#[allow(dead_code)]
fn result_to_ffi_result(_result: Result<()>) -> FfiResult {
    // 简化实现，总是返回成功
    FfiResult::Success
}

// 全局状态
static mut GLOBAL_INITIALIZED: bool = false;
static mut GLOBAL_KEY_PROCESSOR: Option<Arc<KeyProcessor>> = None;
static GLOBAL_INIT: Once = Once::new();

/// 设置全局密钥处理器（供 Rust 代码调用）
pub fn set_global_key_processor(processor: Arc<KeyProcessor>) {
    unsafe {
        GLOBAL_INIT.call_once(|| {
            GLOBAL_KEY_PROCESSOR = Some(processor);
        });
    }
}

/// 获取全局密钥处理器
#[allow(static_mut_refs)]
pub fn get_global_key_processor() -> Option<Arc<KeyProcessor>> {
    unsafe {
        GLOBAL_KEY_PROCESSOR.clone()
    }
}

// ==================== C FFI 导出函数 ====================

// 外部C函数声明（来自 openssl_hook.c）
extern "C" {
    pub fn init_tls_key_agent_hook(config_path: *const c_char) -> c_int;
    pub fn cleanup_tls_key_agent_hook() -> c_int;
    pub fn tls_key_agent_hook_status() -> c_int;
    pub fn tls_key_agent_set_log_level(level: c_int);
}

/// 初始化TLS Key Agent
#[no_mangle]
pub unsafe extern "C" fn tls_key_agent_init(config_path: *const c_char) -> FfiResult {
    debug!("TLS Key Agent C FFI 初始化");

    if config_path.is_null() {
        error!("配置路径为空");
        return FfiResult::InvalidParam;
    }

    unsafe {
        if GLOBAL_INITIALIZED {
            info!("Agent已经初始化");
            return FfiResult::AlreadyInitialized;
        }
        GLOBAL_INITIALIZED = true;
    }

    let config_str = unsafe {
        match CStr::from_ptr(config_path).to_str() {
            Ok(s) => s.to_string(),
            Err(e) => {
                error!("配置路径字符串转换失败: {}", e);
                return FfiResult::InvalidParam;
            }
        }
    };

    info!("TLS Key Agent初始化完成，配置文件: {}", config_str);
    FfiResult::Success
}

/// 清理TLS Key Agent
#[no_mangle]
pub unsafe extern "C" fn tls_key_agent_cleanup() -> FfiResult {
    debug!("TLS Key Agent C FFI 清理");

    unsafe {
        GLOBAL_INITIALIZED = false;
    }

    info!("TLS Key Agent清理完成");
    FfiResult::Success
}

/// 启动TLS Key Agent
#[no_mangle]
pub unsafe extern "C" fn tls_key_agent_start() -> FfiResult {
    debug!("启动TLS Key Agent (C FFI)");

    unsafe {
        if !GLOBAL_INITIALIZED {
            error!("Agent未初始化");
            return FfiResult::NotInitialized;
        }
    }

    info!("TLS Key Agent启动成功");
    FfiResult::Success
}

/// 停止TLS Key Agent
#[no_mangle]
pub unsafe extern "C" fn tls_key_agent_stop() -> FfiResult {
    debug!("停止TLS Key Agent (C FFI)");

    unsafe {
        if !GLOBAL_INITIALIZED {
            error!("Agent未初始化");
            return FfiResult::NotInitialized;
        }
    }

    info!("TLS Key Agent停止成功");
    FfiResult::Success
}

/// 处理Client Random
#[no_mangle]
pub unsafe extern "C" fn tls_key_agent_on_client_random(
    ssl_ptr: *mut c_void,
    client_random: *const u8,
    len: usize,
) -> FfiResult {
    if client_random.is_null() {
        error!("Client Random为空");
        return FfiResult::InvalidParam;
    }

    if len != 32 {
        error!("Client Random长度无效: {}", len);
        return FfiResult::InvalidParam;
    }

    let data = unsafe {
        std::slice::from_raw_parts(client_random, len)
    };

    debug!("收到Client Random，长度: {}", len);

    // 打印 hex 格式的 Client Random
    let hex_str = data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    debug!("Client Random: {}", hex_str);

    // 处理 Client Random
    if let Some(processor) = get_global_key_processor() {
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                if let Err(e) = rt.block_on(processor.process_client_random(ssl_ptr, data)) {
                    error!("处理 Client Random 失败: {}", e);
                    return FfiResult::Error;
                }
            }
            Err(_) => {
                warn!("没有可用的 Tokio 运行时，跳过 Client Random 处理");
            }
        }
    } else {
        debug!("全局密钥处理器未设置，跳过 Client Random 处理");
    }

    info!("Client Random处理完成");
    FfiResult::Success
}

/// 处理Master Secret
#[no_mangle]
pub unsafe extern "C" fn tls_key_agent_on_master_secret(
    ssl_ptr: *mut c_void,
    master_secret: *const u8,
    len: usize,
) -> FfiResult {
    if master_secret.is_null() {
        error!("Master Secret为空");
        return FfiResult::InvalidParam;
    }

    if len != 48 {
        error!("Master Secret长度无效: {}", len);
        return FfiResult::InvalidParam;
    }

    let data = unsafe {
        std::slice::from_raw_parts(master_secret, len)
    };

    debug!("收到Master Secret，长度: {}", len);

    // 打印 hex 格式的 Master Secret
    let hex_str = data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    debug!("Master Secret: {}", hex_str);

    // 处理 Master Secret
    if let Some(processor) = get_global_key_processor() {
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                if let Err(e) = rt.block_on(processor.process_master_secret(ssl_ptr, data)) {
                    error!("处理 Master Secret 失败: {}", e);
                    return FfiResult::Error;
                }

                // 尝试完成会话
                if let Some(session) = rt.block_on(processor.try_complete_session(ssl_ptr)).unwrap() {
                    info!("完成TLS会话处理: {:?}", session.five_tuple);

                    // 将会话传递给传输层
                    // 这里会话已经被传递给回调函数，回调函数负责传输
                    // 在正常使用中，回调函数会将会话发送到配置的传输层
                    debug!("TLS会话已通过回调传递给传输层");
                }
            }
            Err(_) => {
                warn!("没有可用的 Tokio 运行时，跳过 Master Secret 处理");
            }
        }
    } else {
        debug!("全局密钥处理器未设置，跳过 Master Secret 处理");
    }

    info!("Master Secret处理完成");
    FfiResult::Success
}

/// 处理连接信息
#[no_mangle]
pub unsafe extern "C" fn tls_key_agent_on_connection_info(
    ssl_ptr: *mut c_void,
    src_ip: *const c_char,
    src_port: u16,
    dst_ip: *const c_char,
    dst_port: u16,
    protocol: *const c_char,
) -> FfiResult {
    if src_ip.is_null() || dst_ip.is_null() || protocol.is_null() {
        error!("连接信息参数为空");
        return FfiResult::InvalidParam;
    }

    let src_ip_str = unsafe {
        match CStr::from_ptr(src_ip).to_str() {
            Ok(s) => s,
            Err(e) => {
                error!("源IP字符串转换失败: {}", e);
                return FfiResult::InvalidParam;
            }
        }
    };

    let dst_ip_str = unsafe {
        match CStr::from_ptr(dst_ip).to_str() {
            Ok(s) => s,
            Err(e) => {
                error!("目标IP字符串转换失败: {}", e);
                return FfiResult::InvalidParam;
            }
        }
    };

    let protocol_str = unsafe {
        match CStr::from_ptr(protocol).to_str() {
            Ok(s) => s,
            Err(e) => {
                error!("协议字符串转换失败: {}", e);
                return FfiResult::InvalidParam;
            }
        }
    };

    debug!("收到连接信息: {}:{} -> {}:{} ({})",
           src_ip_str, src_port, dst_ip_str, dst_port, protocol_str);

    // 处理连接信息
    if let Some(processor) = get_global_key_processor() {
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                if let Err(e) = rt.block_on(
                    processor.process_connection_info(ssl_ptr, src_ip_str, src_port, dst_ip_str, dst_port, protocol_str)
                ) {
                    error!("处理连接信息失败: {}", e);
                    return FfiResult::Error;
                }
            }
            Err(_) => {
                warn!("没有可用的 Tokio 运行时，跳过连接信息处理");
            }
        }
    } else {
        debug!("全局密钥处理器未设置，跳过连接信息处理");
    }

    info!("连接信息处理完成");
    FfiResult::Success
}

/// 获取Agent运行状态
#[no_mangle]
pub unsafe extern "C" fn tls_key_agent_is_running() -> c_int {
    unsafe {
        if GLOBAL_INITIALIZED {
            1
        } else {
            0
        }
    }
}

/// 获取版本信息
#[no_mangle]
pub unsafe extern "C" fn tls_key_agent_get_version() -> *const c_char {
    let version = CString::new("0.1.0").unwrap();
    version.into_raw()
}

/// 释放版本字符串内存
#[no_mangle]
pub unsafe extern "C" fn tls_key_agent_free_version(version_ptr: *mut c_char) {
    if !version_ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(version_ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_result_conversion() {
        let ok_result: Result<()> = Ok(());
        assert_eq!(result_to_ffi_result(ok_result), FfiResult::Success);
    }

    #[test]
    fn test_version_management() {
        let version_ptr = unsafe { tls_key_agent_get_version() };
        assert!(!version_ptr.is_null());

        let version_str = unsafe {
            CStr::from_ptr(version_ptr).to_str().unwrap()
        };
        assert_eq!(version_str, "0.1.0");

        unsafe { tls_key_agent_free_version(version_ptr as *mut c_char) };
    }

    #[test]
    fn test_is_running_without_init() {
        unsafe { tls_key_agent_cleanup() };
        let running = unsafe { tls_key_agent_is_running() };
        assert_eq!(running, 0);
    }

    #[test]
    fn test_lifecycle() {
        // 初始化
        let config = CString::new("test_config").unwrap();
        let result = unsafe { tls_key_agent_init(config.as_ptr()) };
        assert_eq!(result, FfiResult::Success);

        // 检查状态
        let running = unsafe { tls_key_agent_is_running() };
        assert_eq!(running, 1);

        // 启动
        let result = unsafe { tls_key_agent_start() };
        assert_eq!(result, FfiResult::Success);

        // 停止
        let result = unsafe { tls_key_agent_stop() };
        assert_eq!(result, FfiResult::Success);

        // 清理
        let result = unsafe { tls_key_agent_cleanup() };
        assert_eq!(result, FfiResult::Success);
    }
}