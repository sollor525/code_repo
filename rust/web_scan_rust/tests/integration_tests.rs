use web_scan_rust::ffi::*;
use std::ffi::CString;

#[test]
fn test_ffi_safety_features() {
    // 测试1: 初始化引擎
    let init_result = web_scan_rust_init();
    assert_eq!(init_result, 0, "Failed to initialize engine");

    // 测试2: 空指针安全检查
    let null_result = web_scan_rust_load_rules_from_json(std::ptr::null());
    assert_eq!(null_result, -2, "Should reject null pointer");

    // 测试3: 载荷长度限制检查
    let mut result = WebScanResultFFI {
        is_matched: false,
        rule_id: 0,
        action: WebScanActionFFI::Alert,
        content_length: 0,
        protocol: WebScanProtocolFFI::Unknown,
        confidence: 0,
    };

    // 空载荷应该被拒绝
    let empty_result = web_scan_rust_process_payload_with_session(
        0, // 无效的会话ID
        0, // direction
        b"test".as_ptr() as *const i8,
        0, // length
        0, // is_final
        0, // reset_on_request_end
        &mut result as *mut _
    );
    assert_eq!(empty_result, -4, "Should reject invalid session ID");

    // 测试4: 会话ID验证
    let session_result = web_scan_rust_process_payload_with_session(
        0, // 无效的会话ID
        0, // direction
        b"test".as_ptr() as *const i8,
        4, // length
        0, // is_final
        0, // reset_on_request_end
        &mut result as *mut _
    );
    assert_eq!(session_result, -4, "Should reject invalid session ID");

    // 测试5: 路径遍历攻击防护
    let malicious_path = CString::new("../../../etc/passwd").unwrap();
    let path_result = web_scan_rust_load_rules_from_json(malicious_path.as_ptr());
    assert_eq!(path_result, -4, "Should reject path traversal attempts");

    // 测试6: 统计功能
    let mut stats = WebScanStatsFFI {
        total_packets: 0,
        total_bytes: 0,
        total_sessions: 0,
        active_sessions: 0,
        total_matches: 0,
        processing_time_ms: 0,
    };
    let stats_result = web_scan_rust_get_stats(&mut stats);
    assert_eq!(stats_result, 0, "Should get statistics successfully");

    println!("All FFI safety tests passed!");
}