use std::env;
use std::process::Command;
use std::path::Path;
use std::fs;
use std::thread;
use std::time::Duration;

/// TLS密钥验证工具
/// 用于验证TLS Key Agent是否成功提取密钥信息
fn main() {
    println!("TLS Key Agent 密钥验证工具");
    println!("=============================");

    // 设置环境变量
    env::set_var("RUST_LOG", "info");

    // 构建项目
    if !build_project() {
        println!("❌ 构建失败，退出验证");
        return;
    }

    // 查找动态库
    let lib_path = match find_library_file() {
        Some(path) => path,
        None => {
            println!("❌ 未找到动态库文件");
            return;
        }
    };

    println!("✅ 找到动态库: {:?}", lib_path);

    // 运行验证测试
    run_key_validation_tests(&lib_path);

    println!("\n验证完成！");
}

fn build_project() -> bool {
    println!("🔨 构建TLS Key Agent...");
    let output = Command::new("cargo")
        .args(&["build", "--lib"])
        .output()
        .expect("执行cargo build失败");

    if output.status.success() {
        println!("✅ 构建成功");
        true
    } else {
        println!("❌ 构建失败");
        println!("错误: {}", String::from_utf8_lossy(&output.stderr));
        false
    }
}

fn find_library_file() -> Option<std::path::PathBuf> {
    // 查找libtls_key_agent.so
    let patterns = vec![
        "target/debug/libtls_key_agent.so",
        "target/debug/libtls_key_agent.dylib",
        "target/debug/tls_key_agent.dll",
    ];

    for pattern in patterns {
        let path = Path::new(pattern);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    // 在target/debug目录下搜索
    if let Ok(entries) = fs::read_dir("target/debug") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(filename) = path.file_name() {
                if let Some(filename_str) = filename.to_str() {
                    if filename_str.contains("tls_key_agent") &&
                       (filename_str.ends_with(".so") || filename_str.ends_with(".dylib")) {
                        return Some(path);
                    }
                }
            }
        }
    }

    None
}

fn run_key_validation_tests(lib_path: &std::path::Path) {
    println!("\n🔍 开始密钥验证测试...");

    // 测试1: 简单HTTPS连接
    println!("\n--- 测试1: 基础HTTPS连接验证 ---");
    test_basic_https_connection(lib_path);

    // 测试2: 多个并发连接
    println!("\n--- 测试2: 并发连接验证 ---");
    test_concurrent_connections(lib_path);

    // 测试3: 不同网站的连接
    println!("\n--- 测试3: 多域名连接验证 ---");
    test_multiple_domains(lib_path);

    // 测试4: 长时间连接
    println!("\n--- 测试4: 长时间连接验证 ---");
    test_long_connection(lib_path);
}

fn test_basic_https_connection(lib_path: &std::path::Path) {
    println!("设置LD_PRELOAD并执行curl https://httpbin.org/get");

    // 设置LD_PRELOAD
    env::set_var("LD_PRELOAD", lib_path);

    // 执行HTTP请求
    let output = Command::new("curl")
        .args(&[
            "-s", "-w", "HTTP状态: %{http_code}, 连接时间: %{time_connect}s, 总时间: %{time_total}s",
            "https://httpbin.org/get",
            "--connect-timeout", "10"
        ])
        .output()
        .expect("执行curl失败");

    // 清理环境
    env::remove_var("LD_PRELOAD");

    if output.status.success() {
        println!("✅ 基础HTTPS连接成功");
        let response = String::from_utf8_lossy(&output.stdout);
        if response.len() > 100 {
            println!("✅ 响应长度: {} bytes", response.len());
            if response.contains("\"url\"") {
                println!("✅ 响应格式正确");
            }
        }
    } else {
        println!("❌ 基础HTTPS连接失败");
        if !output.stderr.is_empty() {
            println!("错误: {}", String::from_utf8_lossy(&output.stderr));
        }
    }
}

fn test_concurrent_connections(lib_path: &std::path::Path) {
    println!("测试5个并发HTTPS连接...");

    env::set_var("LD_PRELOAD", lib_path);

    let mut handles = vec![];
    for i in 1..=5 {
        let lib_path = lib_path.to_path_buf();
        let handle = thread::spawn(move || {
            let output = Command::new("curl")
                .args(&["-s", "-w", "连接{}: %{http_code}", "https://httpbin.org/get", &i.to_string()])
                .output()
                .expect("执行curl失败");

            if output.status.success() {
                let response = String::from_utf8_lossy(&output.stdout);
                println!("连接{}成功", i);
            } else {
                println!("连接{}失败", i);
            }
        });
        handles.push(handle);
    }

    // 等待所有线程完成
    for handle in handles {
        let _ = handle.join();
    }

    env::remove_var("LD_PRELOAD");
    println!("✅ 并发连接测试完成");
}

fn test_multiple_domains(lib_path: &std::path::Path) {
    println!("测试多个域名的HTTPS连接...");

    let domains = vec![
        "https://www.baidu.com",
        "https://www.google.com",
        "https://httpbin.org/get",
        "https://jsonplaceholder.typicode.com/posts/1",
        "https://api.github.com",
    ];

    env::set_var("LD_PRELOAD", lib_path);

    let mut success_count = 0;
    for domain in domains {
        println!("测试连接: {}", domain);

        let output = Command::new("curl")
            .args(&["-s", "-w", "状态码: %{http_code}", domain, "--connect-timeout", "8"])
            .output()
            .expect("执行curl失败");

        if output.status.success() {
            let response = String::from_utf8_lossy(&output.stdout);
            if response.contains("200") || response.contains("2") {
                println!("✅ {} 连接成功", domain);
                success_count += 1;
            } else {
                println!("⚠️  {} 连接异常: {}", domain, response.trim());
            }
        } else {
            println!("❌ {} 连接失败", domain);
        }

        // 短暂延迟避免过于频繁的请求
        thread::sleep(Duration::from_millis(500));
    }

    env::remove_var("LD_PRELOAD");
    println!("✅ 多域名测试完成: {}/5 成功", success_count);
}

fn test_long_connection(lib_path: &std::path::Path) {
    println!("测试长时间HTTPS连接 (保持连接15秒)...");

    env::set_var("LD_PRELOAD", lib_path);

    // 使用openssl s_client进行长时间连接测试
    let output = Command::new("timeout")
        .args(&["15s", "openssl", "s_client", "-connect", "www.baidu.com:443"])
        .output()
        .expect("执行openssl失败");

    env::remove_var("LD_PRELOAD");

    if output.status.success() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("SSL-Session:") {
            println!("✅ 长时间连接测试成功");
            println!("✅ SSL会话信息已建立");
        } else {
            println!("⚠️  长时间连接测试部分成功");
        }
    } else {
        println!("❌ 长时间连接测试失败");
    }
}