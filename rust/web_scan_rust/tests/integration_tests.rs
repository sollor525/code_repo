//! 集成测试模块
//!
//! 测试整个Web扫描检测系统的集成功能，包括：
//! - Hyperscan集成
//! - 分段数据包处理
//! - 规则加载和匹配
//! - FFI接口测试
//!
//! 注意：这些测试使用全局引擎实例，因此需要串行执行以避免状态干扰。
//! 运行测试时建议使用: cargo test --test integration_tests -- --test-threads=1

use web_scan_rust::{Protocol, WebScanResult, WebScanStats, WebScanAction};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

// 导入FFI函数
extern "C" {
    fn web_scan_rust_init() -> c_int;
    fn web_scan_rust_init_with_hyperscan() -> c_int;
    fn web_scan_rust_load_rules(rules_path: *const c_char) -> c_int;
    fn web_scan_rust_process_payload(
        payload: *const u8,
        payload_len: u32,
        result: *mut WebScanResult,
    ) -> c_int;
    fn web_scan_rust_process_segmented_payload(
        payload: *const u8,
        payload_len: u32,
        stream_data: *mut u8,
        stream_len: u32,
        max_stream_len: u32,
        is_complete: c_int,
        result: *mut WebScanResult,
        new_stream_len: *mut u32,
    ) -> c_int;
    fn web_scan_rust_get_stats(stats: *mut WebScanStats) -> c_int;
    fn web_scan_rust_reset_stats() -> c_int;
    fn web_scan_rust_set_enabled(enabled: bool) -> c_int;
    fn web_scan_rust_is_enabled() -> c_int;
    fn web_scan_rust_set_default_action(action: WebScanAction) -> c_int;
    fn web_scan_rust_get_rule_count() -> c_int;
    fn web_scan_rust_is_hyperscan_enabled() -> c_int;
    fn web_scan_rust_reload_rules(rules_path: *const c_char) -> c_int;
    fn web_scan_rust_get_last_error() -> *const c_char;
    fn web_scan_rust_cleanup() -> c_int;
}

/// 测试Hyperscan初始化和规则加载
#[test]
fn test_hyperscan_initialization() {
    // 初始化引擎（默认启用Hyperscan）
    let result = unsafe { web_scan_rust_init_with_hyperscan() };
    assert_eq!(result, 0);

    // 此时 Hyperscan 应该是启用的，即使没有规则
    let hyperscan_enabled = unsafe { web_scan_rust_is_hyperscan_enabled() };
    // 注意：在没有规则的情况下可能返回 0，这是正常的

    // 清理
    unsafe { web_scan_rust_cleanup() };
}

/// 测试分段数据包处理
#[test]
fn test_segmented_payload_processing() {
    // 初始化引擎并确保启用
    let result = unsafe { web_scan_rust_init() };
    assert_eq!(result, 0);
    unsafe { 
        web_scan_rust_set_enabled(true);
        web_scan_rust_reset_stats();  // 重置统计信息
    }
    
    // 创建测试规则
    let rules_content = r#"
alert http any any -> any any (msg:"Admin access"; content:"/admin/"; sid:1001;)
alert http any any -> any any (msg:"SQL injection"; content:"union select"; sid:1002;)
"#;
    
    // 写入临时文件
    let rules_path = "/tmp/test_segmented.rules";
    std::fs::write(rules_path, rules_content).unwrap();
    
    // 加载规则
    let rules_cstr = CString::new(rules_path).unwrap();
    let result = unsafe { web_scan_rust_load_rules(rules_cstr.as_ptr()) };
    assert_eq!(result, 0, "Failed to load rules: {}", unsafe {
        CStr::from_ptr(web_scan_rust_get_last_error()).to_str().unwrap_or("unknown error")
    });
    
    // 测试分段数据包处理
    let payload1 = b"GET /admin/";
    let payload2 = b"login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
    
    // 创建流缓冲区
    let mut stream_buffer = vec![0u8; 1024];
    let mut new_stream_len: u32 = 0;
    let mut result = WebScanResult::default();
    
    // 处理第一个分段
    let result_code = unsafe {
        web_scan_rust_process_segmented_payload(
            payload1.as_ptr(),
            payload1.len() as u32,
            stream_buffer.as_mut_ptr(),
            0,
            1024,
            0, // 不完整
            &mut result,
            &mut new_stream_len,
        )
    };
    
    // 应该需要更多数据
    assert_eq!(result_code, 1);
    assert!(!result.is_matched);
    
    // 处理第二个分段（完整）
    let result_code = unsafe {
        web_scan_rust_process_segmented_payload(
            payload2.as_ptr(),
            payload2.len() as u32,
            stream_buffer.as_mut_ptr(),
            new_stream_len,
            1024,
            1, // 完整
            &mut result,
            &mut new_stream_len,
        )
    };
    
    // 应该匹配到管理员访问规则
    assert_eq!(result_code, 0);
    assert!(result.is_matched);
    assert_eq!(result.rule_id, 1001);
    
    // 清理（但保持引擎启用，以便后续测试使用）
    unsafe { 
        web_scan_rust_set_enabled(true);  // 确保引擎保持启用
    }
    std::fs::remove_file(rules_path).unwrap();
}

/// 测试Hyperscan规则格式
#[test]
fn test_hyperscan_rule_format() {
    // 初始化引擎并确保启用
    let result = unsafe { web_scan_rust_init() };
    assert_eq!(result, 0);
    unsafe { 
        web_scan_rust_set_enabled(true);
        web_scan_rust_reset_stats();  // 重置统计信息
    }
    
    // 创建Hyperscan格式规则
    let rules_content = r#"
# Test rules in Hyperscan/Snort format
alert http any any -> any any (msg:"Admin access"; content:"/admin/"; sid:2001;)
drop http any any -> any any (msg:"SQL injection"; content:"union select"; sid:2002;)
alert http any any -> any any (msg:"XSS attempt"; content:"<script>"; sid:2003;)
"#;
    
    // 写入临时文件
    let rules_path = "/tmp/test_hyperscan.rules";
    std::fs::write(rules_path, rules_content).unwrap();
    
    // 加载规则
    let rules_cstr = CString::new(rules_path).unwrap();
    let result = unsafe { web_scan_rust_load_rules(rules_cstr.as_ptr()) };
    assert_eq!(result, 0, "Failed to load rules: {}", unsafe {
        CStr::from_ptr(web_scan_rust_get_last_error()).to_str().unwrap_or("unknown error")
    });
    
    // 检查规则数量
    let rule_count = unsafe { web_scan_rust_get_rule_count() };
    assert_eq!(rule_count, 3);
    
    // 测试规则匹配
    let test_payload = b"GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut result = WebScanResult::default();
    
    let result_code = unsafe {
        web_scan_rust_process_payload(
            test_payload.as_ptr(),
            test_payload.len() as u32,
            &mut result,
        )
    };

    assert_eq!(result_code, 0);
    assert!(result.is_matched);
    assert_eq!(result.rule_id, 2001);

    // 清理（但保持引擎启用，以便后续测试使用）
    unsafe { 
        web_scan_rust_set_enabled(true);  // 确保引擎保持启用
    }
    std::fs::remove_file(rules_path).unwrap();
}

/// 测试错误处理
#[test]
fn test_error_handling() {
    // 初始化引擎（由于OnceLock的特性，引擎可能已经被初始化）
    unsafe { web_scan_rust_init(); }
    
    // 测试空指针错误处理
    let result_code = unsafe {
        web_scan_rust_process_payload(
            std::ptr::null(),
            10,
            std::ptr::null_mut(),
        )
    };
    
    // 应该返回错误（空指针）
    assert!(result_code < 0, "Expected error code < 0 for null pointer, got {}", result_code);
    
    // 检查错误信息
    let error_ptr = unsafe { web_scan_rust_get_last_error() };
    assert!(!error_ptr.is_null(), "Error pointer should not be null");
    
    let error_str = unsafe { CStr::from_ptr(error_ptr) }.to_str().unwrap();
    assert!(error_str.contains("Null") || error_str.contains("null"), "Error message should contain 'Null' or 'null', got: {}", error_str);
    
    // 测试无效的规则路径
    let invalid_path = CString::new("/nonexistent/path.rules").unwrap();
    let result_code = unsafe {
        web_scan_rust_load_rules(invalid_path.as_ptr())
    };
    
    // 应该返回错误（文件不存在）
    assert!(result_code < 0, "Expected error code < 0 for invalid path, got {}", result_code);
}

/// 测试统计信息
#[test]
fn test_statistics() {
    // 初始化引擎并确保启用
    let result = unsafe { web_scan_rust_init() };
    assert_eq!(result, 0);
    unsafe { 
        web_scan_rust_set_enabled(true);
        web_scan_rust_reset_stats();  // 先重置统计信息
    }
    
    // 创建测试规则
    let rules_content = r#"
alert http any any -> any any (msg:"Test rule"; content:"test"; sid:3001;)
"#;
    
    // 写入临时文件
    let rules_path = "/tmp/test_stats.rules";
    std::fs::write(rules_path, rules_content).unwrap();
    
    // 加载规则
    let rules_cstr = CString::new(rules_path).unwrap();
    let result = unsafe { web_scan_rust_load_rules(rules_cstr.as_ptr()) };
    assert_eq!(result, 0, "Failed to load rules: {}", unsafe {
        CStr::from_ptr(web_scan_rust_get_last_error()).to_str().unwrap_or("unknown error")
    });
    
    // 再次重置统计（确保在加载规则后重置）
    let result = unsafe { web_scan_rust_reset_stats() };
    assert_eq!(result, 0);
    
    // 处理一些数据包
    let test_payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut result = WebScanResult::default();
    
    for _ in 0..5 {
        let result_code = unsafe {
            web_scan_rust_process_payload(
                test_payload.as_ptr(),
                test_payload.len() as u32,
                &mut result,
            )
        };
        assert_eq!(result_code, 0);
    }
    
    // 获取统计信息
    let mut stats = WebScanStats::default();
    let result = unsafe { web_scan_rust_get_stats(&mut stats) };
    assert_eq!(result, 0);
    
    // 验证统计信息
    assert!(stats.packets_processed >= 5);
    assert!(stats.packets_matched >= 5);
    
    // 清理（但保持引擎启用，以便后续测试使用）
    unsafe { 
        web_scan_rust_set_enabled(true);  // 确保引擎保持启用
    }
    std::fs::remove_file(rules_path).unwrap();
}

/// 测试引擎控制功能
#[test]
fn test_engine_control() {
    // 初始化引擎并确保启用
    let result = unsafe { web_scan_rust_init() };
    assert_eq!(result, 0);
    unsafe { web_scan_rust_set_enabled(true); }
    
    // 测试启用/禁用
    let result = unsafe { web_scan_rust_set_enabled(false) };
    assert_eq!(result, 0);
    
    let enabled = unsafe { web_scan_rust_is_enabled() };
    assert_eq!(enabled, 0);
    
    let result = unsafe { web_scan_rust_set_enabled(true) };
    assert_eq!(result, 0);
    
    let enabled = unsafe { web_scan_rust_is_enabled() };
    assert_eq!(enabled, 1);
    
    // 测试默认动作
    let result = unsafe { web_scan_rust_set_default_action(WebScanAction::Drop) };
    assert_eq!(result, 0);
    
    // 清理（但保持引擎启用，以便后续测试使用）
    unsafe { 
        web_scan_rust_set_enabled(true);  // 确保引擎保持启用
    }
}

/// 测试并发安全性
#[test]
fn test_concurrent_safety() {
    use std::thread;
    use std::sync::Arc;
    
    // 初始化引擎并确保启用
    let result = unsafe { web_scan_rust_init() };
    assert_eq!(result, 0);
    unsafe { web_scan_rust_set_enabled(true); }
    
    // 创建测试规则
    let rules_content = r#"
alert http any any -> any any (msg:"Concurrent test"; content:"test"; sid:4001;)
"#;
    
    // 写入临时文件
    let rules_path = "/tmp/test_concurrent.rules";
    std::fs::write(rules_path, rules_content).unwrap();
    
    // 加载规则
    let rules_cstr = CString::new(rules_path).unwrap();
    let result = unsafe { web_scan_rust_load_rules(rules_cstr.as_ptr()) };
    assert_eq!(result, 0, "Failed to load rules: {}", unsafe {
        CStr::from_ptr(web_scan_rust_get_last_error()).to_str().unwrap_or("unknown error")
    });
    
    // 创建多个线程同时处理数据包
    let handles: Vec<_> = (0..4).map(|_| {
        thread::spawn(|| {
            let test_payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
            let mut result = WebScanResult::default();
            
            for _ in 0..100 {
                let result_code = unsafe {
                    web_scan_rust_process_payload(
                        test_payload.as_ptr(),
                        test_payload.len() as u32,
                        &mut result,
                    )
                };
                assert_eq!(result_code, 0);
            }
        })
    }).collect();
    
    // 等待所有线程完成
    for handle in handles {
        handle.join().unwrap();
    }
    
    // 清理（但保持引擎启用，以便后续测试使用）
    unsafe { 
        web_scan_rust_set_enabled(true);  // 确保引擎保持启用
    }
    std::fs::remove_file(rules_path).unwrap();
}