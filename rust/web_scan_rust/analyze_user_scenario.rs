use web_scan_rust::engine::WebScanEngine;

fn main() {
    println!("🔍 分析用户报告的具体场景");

    // 用户报告的关键问题：
    // "🚨 [攻击检测] 数据包 #2500-2505 规则ID: 2023628... 能出现这么多次吗？实际结果中更多"
    // 用户提到这些数据包都是 srm-dump.7z 相关请求

    // 1. 精确复制用户提到的请求
    let exact_request = b"GET /srm-dump.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n";

    // 2. 使用用户的实际规则文件格式
    let rule_line = r#"alert http any any -> $HOME_NET any (msg:"ET EXPLOIT Netgear R7000 Command Injection Exploit"; flow:established,to_server; http.uri; content:"/cgi-bin/"; startswith; content:"$IFS"; fast_pattern; distance:0; content:"|3b|"; reference:url,www.kb.cert.org/vuls/id/582384; classtype:attempted-user; sid:2023628; rev:1;)"#;

    std::fs::write("/tmp/user_scenario.rules", rule_line).expect("Failed to write rule");

    println!("\n📋 测试请求: {}", std::str::from_utf8(exact_request).unwrap());

    // 3. 分析规则要求
    println!("\n📋 规则2023628分析:");
    println!("- 必须以 '/cgi-bin/' 开头");
    println!("- 必须包含 '$IFS'");
    println!("- 必须包含分号 '|3b|' (hex: 0x3b)");

    println!("\n📋 请求分析:");
    let request_str = std::str::from_utf8(exact_request).unwrap();
    if let Some(space_pos) = request_str.find(' ') {
        if let Some(http_pos) = request_str[space_pos + 1..].find(" HTTP/") {
            let uri = &request_str[space_pos + 1..space_pos + 1 + http_pos];
            println!("- URI: '{}'", uri);
            println!("- 以 '/cgi-bin/' 开头: {}", uri.starts_with("/cgi-bin/"));
            println!("- 包含 '$IFS': {}", uri.contains("$IFS"));
            println!("- 包含 ';': {}", uri.contains(";"));
        }
    }

    // 4. 创建引擎测试
    let mut engine = WebScanEngine::new();
    match engine.init_with_rules("/tmp/user_scenario.rules") {
        Ok(()) => {
            println!("\n✅ 规则加载成功");
        }
        Err(e) => {
            println!("\n❌ 规则加载失败: {:?}", e);
            return;
        }
    }

    // 5. 模拟用户可能遇到的不同场景
    println!("\n🔍 场景1: 单次独立请求");
    match engine.process_payload_with_session(1, exact_request, true, true) {
        Ok(result) => {
            println!("会话1: matched={}, rule_id={}", result.is_matched, result.rule_id);
            if result.is_matched {
                println!("❌ 严重错误：正常请求被误报！");
            } else {
                println!("✅ 正常：没有误报");
            }
        }
        Err(e) => {
            println!("检测失败: {:?}", e);
        }
    }

    println!("\n🔍 场景2: 连续多个会话测试（模拟PCAP中的多个数据包）");
    let mut false_positive_count = 0;

    for session_id in 2500..=2505 {  // 模拟用户报告的数据包编号
        match engine.process_payload_with_session(session_id, exact_request, true, true) {
            Ok(result) => {
                println!("会话{}: matched={}, rule_id={}", session_id, result.is_matched, result.rule_id);
                if result.is_matched && result.rule_id == 2023628 {
                    false_positive_count += 1;
                    println!("  ❌ 会话{}: 误报！", session_id);
                } else {
                    println!("  ✅ 会话{}: 正常", session_id);
                }
            }
            Err(e) => {
                println!("  会话{}: 检测失败: {:?}", session_id, e);
            }
        }
    }

    println!("\n📊 总结:");
    if false_positive_count > 0 {
        println!("❌ 发现 {} 次误报！", false_positive_count);
        println!("这解释了为什么用户看到规则2023628多次匹配srm备份请求");
    } else {
        println!("✅ 没有发现误报");
        println!("用户报告的问题可能来自:");
        println!("- 不同的PCAP文件或请求格式");
        println!("- 会话状态管理问题（需要检查reset_on_request_end参数）");
        println!("- 代码版本差异");
    }
}