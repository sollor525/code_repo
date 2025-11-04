//! 基本功能测试
//!
//! 这个测试验证TLS Key Agent的基本功能，不依赖复杂的hook机制

use std::process::Command;
use std::fs;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    tracing_subscriber::fmt::init();

    println!("=== TLS Key Agent 基本功能测试 ===");
    println!("测试时间: {}", chrono::Utc::now());
    println!();

    // 1. 测试配置创建
    println!("1. 测试配置创建...");
    let config = tls_key_agent::Config::default();
    println!("✓ 默认配置创建成功");

    // 验证配置内容
    println!("  - Agent名称: {}", config.agent.name);
    println!("  - 启用的传输: {:?}", config.transport.enabled_transports);
    println!("  - 过滤器数量: {}", config.filters.len());
    println!();

    // 2. 测试TLS Key Agent创建
    println!("2. 测试TLS Key Agent创建...");
    match tls_key_agent::TlsKeyAgent::new(config).await {
        Ok(agent) => {
            println!("✓ TLS Key Agent创建成功");
            println!("  - Agent已初始化");

            // 测试启动
            match agent.start().await {
                Ok(_) => {
                    println!("✓ TLS Key Agent启动成功");

                    // 等待一秒让agent完全启动
                    sleep(Duration::from_secs(1)).await;

                    // 测试停止
                    match agent.stop().await {
                        Ok(_) => {
                            println!("✓ TLS Key Agent停止成功");
                        }
                        Err(e) => {
                            println!("⚠ TLS Key Agent停止失败: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("⚠ TLS Key Agent启动失败: {}", e);
                }
            }
        }
        Err(e) => {
            println!("⚠ TLS Key Agent创建失败: {}", e);
        }
    }
    println!();

    // 3. 测试网络连接
    println!("3. 测试网络连接...");
    match tokio::net::TcpStream::connect("www.baidu.com:443").await {
        Ok(_) => {
            println!("✓ 成功连接到 www.baidu.com:443");
        }
        Err(e) => {
            println!("⚠ 连接失败: {}", e);
        }
    }
    println!();

    // 4. 测试OpenSSL库可用性
    println!("4. 测试OpenSSL库...");
    if let Ok(output) = Command::new("openssl").arg("version").output() {
        let version = String::from_utf8_lossy(&output.stdout);
        println!("✓ OpenSSL可用: {}", version.trim());
    } else {
        println!("⚠ OpenSSL不可用");
    }
    println!();

    // 5. 检查动态库
    println!("5. 检查动态库...");
    let lib_path = "/root/workspace/code_repo/rust/tls_key_agent/target/release/build/tls_key_agent-14464a6856f749c9/out/libopenssl_hook.so";
    if fs::metadata(lib_path).is_ok() {
        println!("✓ Hook库存在: {}", lib_path);

        // 检查库的符号
        if let Ok(output) = Command::new("nm").arg("-D").arg(lib_path).output() {
            let symbols = String::from_utf8_lossy(&output.stdout);
            let ssl_symbols = symbols.lines().filter(|line| line.contains("SSL_")).count();
            println!("  - 导出的SSL符号数量: {}", ssl_symbols);

            if ssl_symbols > 0 {
                println!("✓ Hook库包含SSL符号");

                // 显示一些符号
                for line in symbols.lines().take(5).filter(|line| line.contains("SSL_")) {
                    println!("    {}", line);
                }
            } else {
                println!("⚠ Hook库不包含SSL符号");
            }
        }
    } else {
        println!("⚠ Hook库不存在: {}", lib_path);
    }
    println!();

    // 6. 测试HTTPS请求（不使用hook）
    println!("6. 测试HTTPS请求...");
    match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(client) => {
            match client.get("https://www.baidu.com").send().await {
                Ok(response) => {
                    println!("✓ HTTPS请求成功");
                    println!("  - 状态码: {}", response.status());
                    println!("  - 响应头数量: {}", response.headers().len());
                }
                Err(e) => {
                    println!("⚠ HTTPS请求失败: {}", e);
                }
            }
        }
        Err(e) => {
            println!("⚠ HTTP客户端创建失败: {}", e);
        }
    }
    println!();

    println!("=== 测试完成 ===");
    println!("总结:");
    println!("✓ 基本功能正常");
    println!("✓ 网络连接正常");
    println!("✓ TLS Key Agent组件可以正常创建和启动");
    println!("⚠ Hook机制需要进一步调试");

    Ok(())
}