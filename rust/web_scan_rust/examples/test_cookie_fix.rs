use web_scan_rust::engine::WebScanEngine;

fn main() {
    println!("🔍 测试Cookie匹配修复效果");

    // 创建规则2019239
    let rule_line = r#"alert http any any -> $HTTP_SERVERS any (msg:"ET WEB_SERVER Possible CVE-2014-6271 Attempt in HTTP Cookie"; flow:established,to_server; http.cookie; content:"|28 29 20 7b|"; reference:url,blogs.akamai.com/2014/09/environment-bashing.html; classtype:attempted-admin; sid:2019239; rev:1;)"#;

    std::fs::write("/tmp/test_cookie_fix.rules", rule_line).expect("Failed to write test rule");

    // 创建引擎并加载规则
    let mut engine = WebScanEngine::new();

    match engine.init_with_rules("/tmp/test_cookie_fix.rules") {
        Ok(()) => {
            println!("✅ 规则2019239加载成功");
        }
        Err(e) => {
            println!("❌ 规则加载失败: {:?}", e);
            return;
        }
    }

    // 测试1: 不含Cookie的HTTP请求（应该不匹配）
    let test_request1 = b"GET /cgi-mod/index.cgi HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\nUser-Agent: Mozilla/5.0\r\n\r\n";

    println!("\n🔍 测试1: HTTP请求无Cookie (期望: 不匹配)");
    match engine.process_payload(test_request1) {
        Ok(result) => {
            println!("  检测结果: is_matched={}", result.is_matched);
            if result.is_matched {
                println!("  ❌ 误报！不应该匹配规则{}", result.rule_id);
                println!("  ❌ 这表明Cookie位置验证仍然有问题");
            } else {
                println!("  ✅ 正确！没有匹配任何规则");
            }
        }
        Err(e) => {
            println!("  检测失败: {:?}", e);
        }
    }

    // 测试2: 另一个不含Cookie的HTTP请求（应该不匹配）
    let test_request2 = b"GET /cgi-bin/test.cgi HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\nAccept: text/html\r\n\r\n";

    println!("\n🔍 测试2: HTTP请求无Cookie (期望: 不匹配)");
    match engine.process_payload(test_request2) {
        Ok(result) => {
            println!("  检测结果: is_matched={}", result.is_matched);
            if result.is_matched {
                println!("  ❌ 误报！不应该匹配规则{}", result.rule_id);
                println!("  ❌ 这表明Cookie位置验证仍然有问题");
            } else {
                println!("  ✅ 正确！没有匹配任何规则");
            }
        }
        Err(e) => {
            println!("  检测失败: {:?}", e);
        }
    }

    // 测试3: 包含攻击模式的Cookie请求（应该匹配）
    // 使用实际的字节值：0x28='(', 0x29=')', 0x20=' ', 0x7B='{'
    let test_request3 = b"GET /test HTTP/1.1\r\nHost: example.com\r\nCookie: test() {more\r\nUser-Agent: Mozilla/5.0\r\n\r\n";

    println!("\n🔍 测试3: HTTP请求含攻击Cookie (期望: 匹配规则2019239)");
    match engine.process_payload(test_request3) {
        Ok(result) => {
            println!("  检测结果: is_matched={}", result.is_matched);
            if result.is_matched {
                if result.rule_id == 2019239 {
                    println!("  ✅ 正确！成功匹配规则{}", result.rule_id);
                    println!("  ✅ Cookie攻击检测正常工作");
                } else {
                    println!("  ⚠️  匹配了错误的规则{}，期望2019239", result.rule_id);
                }
            } else {
                println!("  ❌ 失败！应该匹配规则2019239但没有匹配");
            }
        }
        Err(e) => {
            println!("  检测失败: {:?}", e);
        }
    }

    // 测试4: 包含攻击模式但不在Cookie中（应该不匹配）
    let test_request4 = b"GET /search?q=\x28\x29\x20\x7B HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";

    println!("\n🔍 测试4: 攻击模式在URI中，不在Cookie (期望: 不匹配)");
    println!("  请求数据: {:?}", std::str::from_utf8(test_request4).unwrap_or("Invalid UTF-8"));
    match engine.process_payload(test_request4) {
        Ok(result) => {
            println!("  检测结果: is_matched={}", result.is_matched);
            if result.is_matched {
                println!("  ❌ 误报！攻击模式不在Cookie中，不应该匹配规则{}", result.rule_id);
                println!("  ❌ 这表明Hyperscan找到了匹配但位置验证有问题");
            } else {
                println!("  ✅ 正确！没有匹配任何规则（攻击模式位置不正确）");
            }
        }
        Err(e) => {
            println!("  检测失败: {:?}", e);
        }
    }

    println!("\n🎉 测试完成！");
    println!("如果所有测试都通过，说明Cookie位置验证修复成功。");
}