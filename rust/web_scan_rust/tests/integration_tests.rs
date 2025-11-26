use web_scan_rust::ffi::*;
use std::ffi::CString;

#[test]
fn test_ffi_safety_features() {
    unsafe {
        // 测试1: 初始化引擎
        let init_result = web_scan_rust_init();
        assert_eq!(init_result, 0, "Failed to initialize engine");

        // 测试2: 空指针安全检查
        let null_result = web_scan_rust_load_rules(std::ptr::null());
        assert_eq!(null_result, -1, "Should reject null pointer");

        // 测试3: 载荷长度限制检查
        let mut result = web_scan_result_t {
            is_matched: false,
            rule_id: 0,
            action: web_scan_action_t::Alert,
            content_length: 0,
            protocol: web_scan_protocol_t::Unknown,
            confidence: 0,
        };

        // 空载荷应该被拒绝
        let empty_result = web_scan_rust_process_payload(
            b"".as_ptr(),
            0,
            &mut result as *mut _
        );
        assert_eq!(empty_result, -2, "Should reject empty payload");

        // 测试4: 会话ID验证
        let session_result = web_scan_rust_process_payload_with_session(
            0, // 无效的会话ID
            b"test".as_ptr(),
            4,
            0,
            0,
            &mut result as *mut _
        );
        assert_eq!(session_result, -4, "Should reject invalid session ID");

        // 测试5: 路径遍历攻击防护
        let malicious_path = CString::new("../../../etc/passwd").unwrap();
        let path_result = web_scan_rust_load_rules(malicious_path.as_ptr());
        assert_eq!(path_result, -4, "Should reject path traversal attempts");

        println!("All FFI safety tests passed!");
    }
}