//! HTTP流量PCRE检测示例
//!
//! 模拟真实的HTTP流量，测试PCRE规则在实际场景中的检测能力

use web_scan_rust::rules::{RuleManager, HttpParts};
use std::path::Path;

/// 模拟的HTTP流量数据
struct HttpTraffic {
    method: &'static str,
    uri: &'static str,
    headers: &'static str,
    body: &'static str,
    expected_detections: Vec<&'static str>, // 期望检测到的威胁类型
}

impl HttpTraffic {
    fn get_full_request(&self) -> String {
        format!("{} {} HTTP/1.1\r\n{}\r\n\r\n{}",
                self.method, self.uri, self.headers, self.body)
    }

    fn parse_http_parts(&self) -> HttpParts {
        let full_request = self.get_full_request();
        HttpParts::parse(full_request.as_bytes()).unwrap()
    }
}

fn create_detection_rules() -> Vec<&'static str> {
    vec![
        r#"
# 管理员访问检测
alert http any any -> any any (
    msg:"Admin panel access";
    pcre:"/admin|administrator/i";
    http.uri;
    sid:1001;
)
"#,

        r#"
# SQL注入检测
alert http any any -> any any (
    msg:"SQL Injection attempt";
    pcre:"/(union|select|insert|update|delete).*from/i";
    http.request_body;
    sid:1002;
)
"#,

        r#"
# XSS攻击检测
alert http any any -> any any (
    msg:"XSS attack attempt";
    pcre:"/<script[^>]*>.*?</script>/i";
    http.request_body;
    sid:1003;
)
"#,

        r#"
# 敏感信息泄露
alert http any any -> any any (
    msg:"Sensitive information disclosure";
    pcre:"/(password|passwd|secret|token|key).*=.*[a-zA-Z0-9]/i";
    http.request_body;
    sid:1004;
)
"#,

        r#"
# 恶意文件上传
alert http any any -> any any (
    msg:"Suspicious file upload";
    pcre:"/\.(php|jsp|asp|exe|bat|sh)$/i";
    http.uri;
    sid:1005;
)
"#,

        r#"
# 命令注入
alert http any any -> any any (
    msg:"Command injection attempt";
    pcre:"/[;&|`].*(ls|cat|rm|wget|curl|nc|netcat)/i";
    http.request_body;
    sid:1006;
)
"#,

        r#"
# 路径遍历
alert http any any -> any any (
    msg:"Path traversal attempt";
    pcre:"/\.\.[\/\\]/i";
    http.uri;
    sid:1007;
)
"#,

        r#"
# 会话劫持
alert http any any -> any any (
    msg:"Session hijacking attempt";
    pcre:"/session(id)?[=:][a-zA-Z0-9]{20,}/i";
    http.request_body;
    sid:1008;
)
"#,

        r#"
# API密钥泄露
alert http any any -> any any (
    msg:"API key disclosure";
    pcre:"/(api[_-]?key|apikey|access[_-]?token)[=:][a-zA-Z0-9]{16,}/i";
    http.request_body;
    sid:1009;
)
"#,

        r#"
# 数据库连接字符串
alert http any any -> any any (
    msg:"Database connection string";
    pcre:"/(mysql|postgresql|mongodb|redis)://[^\\s]+/i";
    http.request_body;
    sid:1010;
)
"#,
    ]
}

fn create_test_traffic() -> Vec<HttpTraffic> {
    vec![
        // 正常访问
        HttpTraffic {
            method: "GET",
            uri: "/index.html",
            headers: "Host: example.com\nUser-Agent: Mozilla/5.0",
            body: "",
            expected_detections: vec![],
        },

        // 管理员访问尝试
        HttpTraffic {
            method: "GET",
            uri: "/admin/login.php",
            headers: "Host: example.com\nUser-Agent: curl/7.68.0",
            body: "",
            expected_detections: vec!["Admin panel access"],
        },

        // SQL注入尝试
        HttpTraffic {
            method: "POST",
            uri: "/login.php",
            headers: "Host: example.com\nContent-Type: application/x-www-form-urlencoded",
            body: "username=admin' OR '1'='1&password=anything",
            expected_detections: vec!["SQL Injection attempt"],
        },

        // XSS攻击尝试
        HttpTraffic {
            method: "POST",
            uri: "/comment.php",
            headers: "Host: example.com\nContent-Type: application/x-www-form-urlencoded",
            body: "comment=<script>alert('XSS')</script>&post_id=123",
            expected_detections: vec!["XSS attack attempt"],
        },

        // 敏感信息泄露
        HttpTraffic {
            method: "POST",
            uri: "/api/config",
            headers: "Host: example.com\nContent-Type: application/json",
            body: r#"{"database_password":"secret123","api_key":"abcd1234567890abcd"}"#,
            expected_detections: vec!["Sensitive information disclosure", "API key disclosure"],
        },

        // 恶意文件上传
        HttpTraffic {
            method: "POST",
            uri: "/upload/shell.php",
            headers: "Host: example.com\nContent-Type: multipart/form-data",
            body: "<?php system($_GET['cmd']); ?>",
            expected_detections: vec!["Suspicious file upload"],
        },

        // 命令注入
        HttpTraffic {
            method: "POST",
            uri: "/search.php",
            headers: "Host: example.com\nContent-Type: application/x-www-form-urlencoded",
            body: "query=test; cat /etc/passwd",
            expected_detections: vec!["Command injection attempt"],
        },

        // 路径遍历
        HttpTraffic {
            method: "GET",
            uri: "/download?file=../../../../etc/passwd",
            headers: "Host: example.com\nUser-Agent: Mozilla/5.0",
            body: "",
            expected_detections: vec!["Path traversal attempt"],
        },

        // 会话劫持
        HttpTraffic {
            method: "POST",
            uri: "/profile.php",
            headers: "Host: example.com\nContent-Type: application/x-www-form-urlencoded",
            body: "session_id=abc123def456789ghi012jkl345mno678pqr901stu234vwx567yza890bcd123",
            expected_detections: vec!["Session hijacking attempt"],
        },

        // 数据库连接字符串泄露
        HttpTraffic {
            method: "POST",
            uri: "/debug.php",
            headers: "Host: example.com\nContent-Type: application/json",
            body: r#"{"db_config":"mysql://user:pass@localhost/dbname","redis_url":"redis://localhost:6379"}"#,
            expected_detections: vec!["Database connection string"],
        },
    ]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    env_logger::init();

    println!("🔍 HTTP流量PCRE检测测试开始...\n");

    // 创建规则管理器
    let mut rule_manager = RuleManager::new();

    // 创建规则文件
    let rules_content = create_detection_rules().join("\n");
    let rules_file = "/tmp/http_detection.rules";
    std::fs::write(rules_file, rules_content)?;

    // 加载检测规则
    println!("📋 加载检测规则...");
    let loaded_count = rule_manager.load_rules_from_file(Path::new(rules_file))?;
    println!("✅ 成功加载 {} 条检测规则\n", loaded_count);

    // 创建测试流量
    let test_traffic = create_test_traffic();

    println!("🌐 开始HTTP流量检测测试...\n");

    let mut total_detections = 0;
    let mut correct_detections = 0;

    for (i, traffic) in test_traffic.iter().enumerate() {
        println!("📨 测试流量 {}:", i + 1);
        println!("   方法: {}", traffic.method);
        println!("   URI: {}", traffic.uri);

        if !traffic.body.is_empty() {
            println!("   请求体: {}", &traffic.body[..std::cmp::min(traffic.body.len(), 50)]);
            if traffic.body.len() > 50 {
                println!("   ...");
            }
        }

        // 解析HTTP部分
        let http_parts = traffic.parse_http_parts();
        let full_request = traffic.get_full_request();

        // 执行检测
        println!("🔍 执行检测...");

        let mut detected_rules = Vec::new();

        // 检查content匹配
        if let Some(rule) = rule_manager.match_content(&full_request) {
            detected_rules.push((rule.id, rule.message.clone(), "content"));
        }

        // 检查HTTP特定部分匹配
        if let Some(rule) = rule_manager.match_http_content(&http_parts) {
            detected_rules.push((rule.id, rule.message.clone(), "http_location"));
        }

        // 检查PCRE匹配
        for (_, rule) in rule_manager.get_all_rules() {
            if rule.has_pcre_patterns() {
                if rule.pcre_matches(&full_request) || rule.pcre_matches_http(&http_parts) {
                    detected_rules.push((rule.id, rule.message.clone(), "pcre"));
                }
            }
        }

        // 显示检测结果
        if detected_rules.is_empty() {
            println!("   ❌ 未检测到威胁");
        } else {
            for (rule_id, message, detection_type) in detected_rules {
                println!("   ✅ 检测到威胁: {} (规则ID: {}, 类型: {})", message, rule_id, detection_type);
                total_detections += 1;

                // 检查是否是期望的检测
                if traffic.expected_detections.iter().any(|&expected| message.contains(expected)) {
                    correct_detections += 1;
                }
            }
        }

        // 显示期望的检测结果
        if !traffic.expected_detections.is_empty() {
            println!("   🎯 期望检测: {:?}", traffic.expected_detections);
        }

        println!();
    }

    // 统计结果
    println!("📊 检测统计:");
    println!("   总检测数: {}", total_detections);
    println!("   正确检测数: {}", correct_detections);

    let expected_detections: usize = test_traffic.iter()
        .map(|t| t.expected_detections.len())
        .sum();

    if expected_detections > 0 {
        let accuracy = (correct_detections as f64 / expected_detections as f64) * 100.0;
        println!("   准确率: {:.1}%", accuracy);
    }

    println!("\n🎉 HTTP流量PCRE检测测试完成！");

    // 清理临时文件
    let _ = std::fs::remove_file(rules_file);

    Ok(())
}

/// 运行性能基准测试
#[cfg(test)]
mod performance_tests {
    use super::*;

    #[test]
    fn test_pcre_detection_performance() {
        use std::time::Instant;

        let mut rule_manager = RuleManager::new();
        let rules_content = create_detection_rules().join("\n");
        let rules_file = "/tmp/perf_test.rules";
        std::fs::write(rules_file, &rules_content).unwrap();

        rule_manager.load_rules_from_file(Path::new(rules_file)).unwrap();

        let test_traffic = create_test_traffic();
        let iterations = 100;

        println!("Running performance test with {} iterations...", iterations);

        let start = Instant::now();

        for _ in 0..iterations {
            for traffic in &test_traffic {
                let full_request = traffic.get_full_request();
                let http_parts = traffic.parse_http_parts();

                // 模拟完整的检测流程
                let _ = rule_manager.match_content(&full_request);
                let _ = rule_manager.match_http_content(&http_parts);

                for (_, rule) in rule_manager.get_all_rules() {
                    if rule.has_pcre_patterns() {
                        let _ = rule.pcre_matches(&full_request);
                        let _ = rule.pcre_matches_http(&http_parts);
                    }
                }
            }
        }

        let duration = start.elapsed();
        let total_requests = iterations * test_traffic.len();
        let requests_per_second = total_requests as f64 / duration.as_secs_f64();

        println!("Performance results:");
        println!("  Total requests: {}", total_requests);
        println!("  Total time: {:?}", duration);
        println!("  Requests per second: {:.2}", requests_per_second);
        println!("  Average time per request: {:.2}ms", duration.as_millis() as f64 / total_requests as f64);

        let _ = std::fs::remove_file(rules_file);
    }
}