//! 百度TLS密钥提取测试示例
//!
//! 这个示例演示如何使用TLS Key Agent来捕获访问百度时的TLS密钥信息
//!
//! 使用方法:
//! ```bash
//! cargo run --example baidu_test
//! ```
//!
//! 环境要求:
//! - Linux系统
//! - OpenSSL库
//! - 适当的权限来设置LD_PRELOAD

use std::env;
use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, error, warn};
use tracing_subscriber;
use tls_key_agent::{TlsKeyAgent, Config, TransportConfig, FilterRule, TransportType};
use tls_key_agent::config::{TcpTransportConfig, FileTransportConfig, FiveTupleFilter};
use tls_key_agent::common::session::Protocol;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志系统
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();

    print_banner();

    // 检查运行环境
    if !check_environment() {
        error!("环境检查失败，无法运行测试");
        return Ok(());
    }

    // 运行测试
    run_tls_key_extraction_test().await?;

    Ok(())
}

fn print_banner() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║           TLS Key Agent - 百度密钥提取测试                   ║");
    println!("║                                                              ║");
    println!("║  这个程序将测试通过LD_PRELOAD机制提取TLS密钥                   ║");
    println!("║  它会访问www.baidu.com并尝试捕获Client Random和Master Secret    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
}

/// 检查运行环境
fn check_environment() -> bool {
    info!("检查运行环境...");

    // 检查操作系统
    #[cfg(not(target_os = "linux"))]
    {
        error!("此测试仅支持Linux系统");
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        info!("✓ Linux系统");
    }

    // 检查是否在root权限下运行（LD_PRELOAD可能需要）
    if unsafe { libc::getuid() } == 0 {
        info!("✓ 以root权限运行");
    } else {
        warn!("⚠ 非root权限运行，某些功能可能受限");
    }

    // 检查网络连接
    if check_network_connectivity() {
        info!("✓ 网络连接正常");
    } else {
        error!("✗ 网络连接检查失败");
        return false;
    }

    true
}

/// 检查网络连接
fn check_network_connectivity() -> bool {
    // 简单的网络连接测试
    match std::net::TcpStream::connect("8.8.8.8:53") {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// 运行TLS密钥提取测试
async fn run_tls_key_extraction_test() -> Result<(), Box<dyn std::error::Error>> {
    info!("开始TLS密钥提取测试...");

    // 1. 创建配置
    let config = create_test_config()?;

    // 2. 创建TLS Key Agent
    let agent = TlsKeyAgent::new(config).await?;
    info!("✓ TLS Key Agent创建成功");

    // 3. 启动Agent
    agent.start().await?;
    info!("✓ TLS Key Agent启动成功");

    // 4. 设置LD_PRELOAD
    let library_path = setup_ld_preload()?;
    if library_path.is_empty() {
        error!("无法设置LD_PRELOAD，测试终止");
        agent.stop().await?;
        return Ok(());
    }

    // 5. 执行测试
    let test_results = execute_test_scenarios().await;

    // 6. 显示结果
    display_test_results(&test_results);

    // 7. 清理
    cleanup(&agent).await;

    Ok(())
}

/// 创建测试配置
fn create_test_config() -> Result<Config, Box<dyn std::error::Error>> {
    let mut config = Config::default();

    // 配置文件传输，便于验证
    config.transport = TransportConfig {
        enabled_transports: vec![TransportType::File],
        tcp: TcpTransportConfig::default(),
        file: FileTransportConfig {
            enabled: true,
            output_path: "/tmp/tls_agent_baidu_test.log".to_string(),
            rotation: false,
            max_file_size: 1024 * 1024, // 1MB
            max_files: 10,
        },
    };

    // 配置过滤器，只捕获百度的流量
    config.filters = vec![
        FilterRule {
            name: "Baidu Filter".to_string(),
            enabled: true,
            five_tuple: FiveTupleFilter {
                src_ip: None,
                src_port: None,
                dst_ip: Some("220.181.38.148".to_string()), // 百度的IP之一
                dst_port: Some(443),
                protocol: Some(Protocol::TCP),
            },
            process_name: None,
            pid: None,
        }
    ];

    Ok(config)
}

/// 设置LD_PRELOAD
fn setup_ld_preload() -> Result<String, Box<dyn std::error::Error>> {
    info!("设置LD_PRELOAD...");

    // 尝试找到或构建Hook库
    let library_paths = vec![
        "./target/debug/libtls_key_agent_hook.so",
        "./target/release/libtls_key_agent_hook.so",
        "./libtls_key_agent_hook.so",
    ];

    let mut library_path = String::new();

    for path in library_paths {
        if std::path::Path::new(path).exists() {
            library_path = path.to_string();
            break;
        }
    }

    if library_path.is_empty() {
        // 尝试构建库
        info!("未找到Hook库，尝试构建...");
        let output = Command::new("cargo")
            .args(&["build", "--lib"])
            .output()?;

        if !output.status.success() {
            error!("构建Hook库失败: {}", String::from_utf8_lossy(&output.stderr));
            return Ok(String::new());
        }

        library_path = "./target/debug/libtls_key_agent_hook.so".to_string();
    }

    // 设置环境变量
    env::set_var("LD_PRELOAD", &library_path);
    env::set_var("SSLKEYLOGFILE", "/tmp/baidu_test_ssl_keylog.log");

    info!("✓ LD_PRELOAD设置: {}", library_path);
    info!("✓ SSLKEYLOGFILE设置: /tmp/baidu_test_ssl_keylog.log");

    Ok(library_path)
}

/// 执行测试场景
async fn execute_test_scenarios() -> Vec<TestResult> {
    let mut results = Vec::new();

    info!("开始执行测试场景...");

    // 测试场景1: 使用curl访问百度
    results.push(test_curl_baidu().await);

    // 测试场景2: 使用原生HTTPS连接
    results.push(test_native_https().await);

    // 测试场景3: 多次连接测试
    results.push(test_multiple_connections().await);

    results
}

/// 测试场景1: curl测试
async fn test_curl_baidu() -> TestResult {
    info!("测试场景1: 使用curl访问百度");

    let start_time = std::time::Instant::now();

    let output = Command::new("curl")
        .args(&[
            "-s",
            "-m", "10", // 10秒超时
            "https://www.baidu.com"
        ])
        .output();

    let duration = start_time.elapsed();

    match output {
        Ok(output) => {
            if output.status.success() {
                let response = String::from_utf8_lossy(&output.stdout);
                let success = response.contains("baidu") || response.contains("百度");

                TestResult {
                    name: "curl百度访问".to_string(),
                    success,
                    duration,
                    details: format!(
                        "响应长度: {} 字节, 包含百度关键词: {}",
                        response.len(),
                        success
                    ),
                }
            } else {
                TestResult {
                    name: "curl百度访问".to_string(),
                    success: false,
                    duration,
                    details: format!("curl失败: {}", String::from_utf8_lossy(&output.stderr)),
                }
            }
        }
        Err(e) => {
            TestResult {
                name: "curl百度访问".to_string(),
                success: false,
                duration,
                details: format!("执行curl失败: {}", e),
            }
        }
    }
}

/// 测试场景2: 原生HTTPS测试
async fn test_native_https() -> TestResult {
    info!("测试场景2: 原生HTTPS连接");

    let start_time = std::time::Instant::now();

    let result = match tokio::net::TcpStream::connect("www.baidu.com:443").await {
        Ok(mut stream) => {
            // 发送HTTP请求
            let request = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";

            match tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await {
                Ok(()) => {
                    // 读取响应
                    let mut buffer = [0u8; 1024];
                    match tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await {
                        Ok(bytes_read) => {
                            let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                            let success = response.contains("HTTP/1.1") && bytes_read > 0;

                            TestResult {
                                name: "原生HTTPS连接".to_string(),
                                success,
                                duration: start_time.elapsed(),
                                details: format!(
                                    "读取 {} 字节, HTTP响应有效: {}",
                                    bytes_read,
                                    success
                                ),
                            }
                        }
                        Err(e) => {
                            TestResult {
                                name: "原生HTTPS连接".to_string(),
                                success: false,
                                duration: start_time.elapsed(),
                                details: format!("读取响应失败: {}", e),
                            }
                        }
                    }
                }
                Err(e) => {
                    TestResult {
                        name: "原生HTTPS连接".to_string(),
                        success: false,
                        duration: start_time.elapsed(),
                        details: format!("发送请求失败: {}", e),
                    }
                }
            }
        }
        Err(e) => {
            TestResult {
                name: "原生HTTPS连接".to_string(),
                success: false,
                duration: start_time.elapsed(),
                details: format!("TCP连接失败: {}", e),
            }
        }
    };

    result
}

/// 测试场景3: 多次连接测试
async fn test_multiple_connections() -> TestResult {
    info!("测试场景3: 多次连接测试");

    let start_time = std::time::Instant::now();
    let mut success_count = 0;
    let total_connections = 3;

    for i in 1..=total_connections {
        info!("执行第 {} 次连接", i);

        match tokio::net::TcpStream::connect("www.baidu.com:443").await {
            Ok(mut stream) => {
                let request = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";

                if tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await.is_ok() {
                    let mut buffer = [0u8; 512];
                    if tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await.is_ok() {
                        success_count += 1;
                    }
                }
            }
            Err(_) => {
                // 连接失败
            }
        }

        // 连接间隔
        sleep(Duration::from_millis(500)).await;
    }

    let success = success_count > 0;

    TestResult {
        name: "多次连接测试".to_string(),
        success,
        duration: start_time.elapsed(),
        details: format!(
            "成功连接: {}/{} 次",
            success_count,
            total_connections
        ),
    }
}

/// 显示测试结果
fn display_test_results(results: &[TestResult]) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                        测试结果                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let mut total_success = 0;
    let mut total_tests = 0;

    for result in results {
        total_tests += 1;
        if result.success {
            total_success += 1;
        }

        let status = if result.success { "✓ 成功" } else { "✗ 失败" };
        let duration_ms = result.duration.as_millis();

        println!("┌─ {} ──────────────────────────────", result.name);
        println!("│ 状态: {}", status);
        println!("│ 耗时: {} ms", duration_ms);
        println!("│ 详情: {}", result.details);
        println!("└────────────────────────────────────────");
        println!();
    }

    println!("总结: {}/{} 测试通过", total_success, total_tests);

    // 检查密钥提取结果
    check_key_extraction_results();
}

/// 检查密钥提取结果
fn check_key_extraction_results() {
    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                      密钥提取结果                            ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    let keylog_files = vec![
        "/tmp/tls_agent_baidu_test.log",
        "/tmp/baidu_test_ssl_keylog.log",
    ];

    let mut found_keys = false;

    for file_path in keylog_files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            if !content.is_empty() {
                found_keys = true;
                println!("✓ 发现密钥日志文件: {}", file_path);
                println!("  大小: {} 字节", content.len());

                // 分析密钥内容
                analyze_keylog_content(&content);
            } else {
                println!("⚠ 密钥日志文件为空: {}", file_path);
            }
        } else {
            println!("✗ 密钥日志文件不存在: {}", file_path);
        }
    }

    if !found_keys {
        println!("⚠ 未发现任何密钥日志");
        println!("可能的原因:");
        println!("  - LD_PRELOAD未正确设置");
        println!("  - Hook库未正确加载");
        println!("  - 程序未使用OpenSSL进行TLS连接");
        println!("  - 权限不足");
    }

    println!();
}

/// 分析密钥日志内容
fn analyze_keylog_content(content: &str) {
    let lines: Vec<&str> = content.lines().collect();
    let mut client_random_count = 0;
    let _master_secret_count = 0;

    for line in lines.iter().take(10) { // 只分析前10行
        if line.starts_with("CLIENT_RANDOM") {
            client_random_count += 1;
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                println!("  ✓ Client Random: {}...", &parts[1][..parts[1].len().min(16)]);
                println!("  ✓ Master Secret: {}...", &parts[2][..parts[2].len().min(16)]);
            }
        }
    }

    if client_random_count > 0 {
        println!("🎉 成功提取到 {} 个TLS密钥！", client_random_count);
    } else {
        println!("⚠ 未发现有效的TLS密钥信息");
    }
}

/// 清理资源
async fn cleanup(agent: &TlsKeyAgent) {
    info!("清理资源...");

    // 停止Agent
    if let Err(e) = agent.stop().await {
        error!("停止Agent失败: {}", e);
    }

    // 清理环境变量
    env::remove_var("LD_PRELOAD");
    env::remove_var("SSLKEYLOGFILE");

    info!("✓ 清理完成");
}

/// 测试结果结构
#[derive(Debug)]
struct TestResult {
    name: String,
    success: bool,
    duration: Duration,
    details: String,
}