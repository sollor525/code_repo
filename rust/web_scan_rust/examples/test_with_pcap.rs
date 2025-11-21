use web_scan_rust::engine::WebScanEngine;

fn main() {
    println!("🔍 直接测试引擎功能");

    // 1. 创建规则
    let rule_content = r#"alert http any any -> $HOME_NET any (msg:"ET EXPLOIT Netgear R7000 Command Injection Exploit"; flow:established,to_server; http.uri; content:"/cgi-bin/"; startswith; content:"$IFS"; fast_pattern; distance:0; content:"|3b|"; reference:url,www.kb.cert.org/vuls/id/582384; classtype:attempted-user; sid:2023628; rev:1;)"#;

    std::fs::write("/tmp/test_2023628.rules", rule_content).expect("Failed to write rules");

    // 2. 测试请求
    let test_requests = vec![
        // 正常的srm备份请求 - 不应该匹配
        b"GET /srm-dump.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        // 明确的攻击请求 - 应该匹配
        b"GET /cgi-bin/setup.cgi$IFS;reboot HTTP/1.1\r\nHost: router.local\r\n\r\n".as_slice(),
        // 边界情况 - 可能误报
        b"GET /path/cgi-bin/srm-dump.7z HTTP/1.1\r\nHost: router.local\r\n\r\n".as_slice(),
    ];

    let mut engine = WebScanEngine::new();
    match engine.init_with_rules("/tmp/test_2023628.rules") {
        Ok(()) => {
            println!("✅ 引擎初始化成功");
        }
        Err(e) => {
            println!("❌ 引擎初始化失败: {:?}", e);
            return;
        }
    }

    println!("\n🔍 测试请求:");

    for (i, request) in test_requests.iter().enumerate() {
        let request_str = std::str::from_utf8(request).unwrap();
        println!("\n请求 {}: {}", i + 1, request_str.lines().next().unwrap_or(""));

        // 解析URI
        let uri = if let Some(space_pos) = request_str.find(' ') {
            if let Some(http_pos) = request_str[space_pos + 1..].find(" HTTP/") {
                &request_str[space_pos + 1..space_pos + 1 + http_pos]
            } else {
                "Invalid"
            }
        } else {
            "Invalid"
        };

        println!("URI: '{}'", uri);
        println!("以/cgi-bin/开头: {}", uri.starts_with("/cgi-bin/"));
        println!("包含$IFS: {}", uri.contains("$IFS"));
        println!("包含分号: {}", uri.contains(";"));

        // 测试多个会话
        for session_id in 1..=3 {
            match engine.process_payload_with_session(session_id, request, true, true) {
                Ok(result) => {
                    println!("  会话{}: matched={}, rule_id={}", session_id, result.is_matched, result.rule_id);
                    if result.is_matched && result.rule_id == 2023628 {
                        if i == 0 {  // srm备份请求
                            println!("    ❌ 严重误报！srm备份请求不应该匹配规则2023628");
                        } else {
                            println!("    ✅ 正确检测到攻击");
                        }
                    } else if !result.is_matched && i == 1 {  // 攻击请求
                        println!("    ❌ 漏报！攻击请求应该匹配规则2023628");
                    }
                }
                Err(e) => {
                    println!("  会话{}: 检测失败: {:?}", session_id, e);
                }
            }
        }
    }

    println!("\n🎯 结论:");
    println!("- 如果srm备份请求匹配了规则，说明存在误报问题");
    println!("- 如果攻击请求没有匹配，说明存在漏报问题");
    println!("- 理想情况：只有攻击请求匹配，正常请求不匹配");
}