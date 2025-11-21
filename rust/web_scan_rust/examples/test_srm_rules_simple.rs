use web_scan_rust::engine::WebScanEngine;

fn main() {
    println!("🔍 简单测试srm备份文件请求");

    // 创建规则2023628 (Netgear R7000命令注入)
    let rule_line = r#"alert http any any -> $HOME_NET any (msg:"ET EXPLOIT Netgear R7000 Command Injection Exploit"; flow:established,to_server; http.uri; content:"/cgi-bin/"; startswith; content:"$IFS"; fast_pattern; distance:0; content:"|3b|"; reference:url,www.kb.cert.org/vuls/id/582384; classtype:attempted-user; sid:2023628; rev:1;)"#;

    std::fs::write("/tmp/test_2023628.rules", rule_line).expect("Failed to write test rule");

    let mut engine = WebScanEngine::new();
    match engine.init_with_rules("/tmp/test_2023628.rules") {
        Ok(()) => {
            println!("✅ 规则2023628加载成功");
        }
        Err(e) => {
            println!("❌ 规则加载失败: {:?}", e);
            return;
        }
    }

    // 测试6个不同的srm备份请求
    let test_requests = vec![
        b"GET /srm_dump.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        b"GET /srm-dump.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        b"GET /srmbackup.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        b"GET /srm_backup.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        b"GET /srm-backup.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice(),
        b"GET /backupsrm.7z HTTP/1.1\r\nHost: srm.innuovo-mag.com:8003\r\n\r\n".as_slice()
    ];

    println!("\n🔍 测试6个srm备份请求:");

    for (i, request) in test_requests.iter().enumerate() {
        let request_str = std::str::from_utf8(request).unwrap_or("Invalid UTF-8");
        println!("\n请求{}: {}", i + 1, request_str);

        match engine.process_payload(request) {
            Ok(result) => {
                println!("  检测结果: matched={}, rule_id={}", result.is_matched, result.rule_id);
                if result.is_matched && result.rule_id == 2023628 {
                    println!("  ❌ 严重误报！这个请求不应该匹配Netgear R7000规则");
                    println!("     规则2023628应该匹配以/cgi-bin/开头且包含$IFS和分号的URI");
                } else {
                    println!("  ✅ 正确：没有匹配Netgear R7000规则");
                }
            }
            Err(e) => {
                println!("  检测失败: {:?}", e);
            }
        }
    }

    println!("\n🎉 测试完成！");
}