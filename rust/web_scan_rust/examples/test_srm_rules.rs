use web_scan_rust::rules::{RuleManager};

fn main() {
    println!("🔍 测试srm备份文件请求规则匹配");

    // 测试6个不同的srm备份请求 - 确保长度一致
    let test_requests = vec![
        b"GET /srm_dump.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        b"GET /srm-dump.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        b"GET /srmbackup.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        b"GET /srm_backup.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        b"GET /srm-backup.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        b"GET /backupsrm.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice()
    ];

    // 创建规则2023628
    let rule_line = r#"alert http any any -> $HOME_NET any (msg:"ET EXPLOIT Netgear R7000 Command Injection Exploit"; flow:established,to_server; http.uri; content:"/cgi-bin/"; startswith; content:"$IFS"; fast_pattern; distance:0; content:"|3b|"; reference:url,www.kb.cert.org/vuls/id/582384; classtype:attempted-user; sid:2023628; rev:1;)"#;

    std::fs::write("/tmp/test_2023628.rules", rule_line).expect("Failed to write test rule");

    let mut rule_manager = RuleManager::new();
    match rule_manager.load_rules_from_file(std::path::Path::new("/tmp/test_2023628.rules")) {
        Ok(_) => {
            println!("✅ 规则2023628加载成功");
        }
        Err(e) => {
            println!("❌ 规则加载失败: {:?}", e);
            return;
        }
    }

    if let Some(rule) = rule_manager.get_rule(2023628) {
        println!("规则2023628的patterns:");
        for (i, pattern) in rule.patterns.iter().enumerate() {
            println!("  Pattern{}: '{}'", i + 1, pattern.pattern);
            println!("    位置: {:?}", pattern.http_location);
        }

        println!("\n🔍 测试6个srm备份请求:");

        for (i, request) in test_requests.iter().enumerate() {
            let request_str = std::str::from_utf8(request).unwrap_or("Invalid UTF-8");
            println!("\n请求{}: {}", i + 1, request_str);

            // 手动测试pattern匹配
            if let Some(space_pos) = request_str.find(' ') {
                if let Some(http_pos) = request_str[space_pos + 1..].find(" HTTP/") {
                    let uri = &request_str[space_pos + 1..space_pos + 1 + http_pos];
                    println!("URI: '{}'", uri);

                    for (j, pattern) in rule.patterns.iter().enumerate() {
                        let matches = uri.contains(&pattern.pattern);
                        println!("  Pattern{} '{}' 在URI中: {}", j + 1, pattern.pattern, matches);
                    }
                } else {
                    println!("URI: (解析错误)");
                }
            } else {
                println!("URI: (无空格分隔符)");
            }
                let matches = uri.contains(&pattern.pattern);
                println!("  Pattern{} '{}' 在URI中: {}", j + 1, pattern.pattern, matches);
            }

            // 使用Rust引擎测试
            let mut engine = web_scan_rust::engine::WebScanEngine::new();
            match engine.init_with_rules("/tmp/test_2023628.rules") {
                Ok(()) => {
                    match engine.process_payload(request) {
                        Ok(result) => {
                            println!("  引擎检测结果: matched={}, rule_id={}", result.is_matched, result.rule_id);
                            if result.is_matched && result.rule_id == 2023628 {
                                println!("  ❌ 严重误报！这个请求不应该匹配Netgear R7000规则");
                            } else {
                                println!("  ✅ 正确：没有匹配Netgear R7000规则");
                            }
                        }
                        Err(e) => {
                            println!("  引擎检测失败: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("  引擎初始化失败: {:?}", e);
                }
            }
        }
    }
}