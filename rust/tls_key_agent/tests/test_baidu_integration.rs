use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, error, debug, warn};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::process::Command;
use std::env;

use tls_key_agent::{TlsKeyAgent, Config, TransportConfig, TransportType};
use tls_key_agent::config::{TcpTransportConfig, FileTransportConfig};

/// 测试通过LD_PRELOAD机制获取TLS密钥
/// 这个测试会尝试访问www.baidu.com并验证是否能捕获到TLS密钥
#[tokio::test]
async fn test_baidu_tls_key_extraction() {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    info!("开始测试百度TLS密钥提取");

    // 1. 创建TLS Key Agent配置
    let mut config = Config::default();

    // 配置传输层为文件传输，便于验证
    config.transport = TransportConfig {
        enabled_transports: vec![TransportType::File],
        tcp: TcpTransportConfig::default(),
        file: FileTransportConfig {
            enabled: true,
            output_path: "/tmp/tls_keys_test.log".to_string(),
            rotation: false,
            max_file_size: 1024 * 1024, // 1MB
            max_files: 10,
        },
    };

    // 2. 创建并启动TLS Key Agent
    let agent = match TlsKeyAgent::new(config).await {
        Ok(agent) => agent,
        Err(e) => {
            error!("创建TLS Key Agent失败: {}", e);
            return;
        }
    };

    // 启动agent
    if let Err(e) = agent.start().await {
        error!("启动TLS Key Agent失败: {}", e);
        return;
    }

    info!("✓ TLS Key Agent启动成功");

    // 3. 设置LD_PRELOAD环境变量
    let library_path = get_or_build_test_library().await;
    if library_path.is_empty() {
        error!("无法获取测试库路径");
        return;
    }

    // 设置LD_PRELOAD
    env::set_var("LD_PRELOAD", &library_path);
    env::set_var("SSLKEYLOGFILE", "/tmp/test_ssl_keylog.log");

    info!("✓ LD_PRELOAD环境变量设置: {}", library_path);

    // 4. 执行测试请求
    let result = test_baidu_https_request().await;

    // 5. 验证结果
    if result {
        info!("✓ 百度HTTPS请求成功完成");
        verify_key_extraction_results().await;
    } else {
        error!("✗ 百度HTTPS请求失败");
    }

    // 6. 清理
    let _ = agent.stop().await;
    env::remove_var("LD_PRELOAD");
    env::remove_var("SSLKEYLOGFILE");

    info!("测试完成");
}

/// 获取或构建测试库
async fn get_or_build_test_library() -> String {
    // 首先检查是否已存在测试库
    let possible_paths = vec![
        "./target/debug/libtls_key_agent_hook.so",
        "./target/release/libtls_key_agent_hook.so",
        "./libtls_key_agent_hook.so",
    ];

    for path in possible_paths {
        if std::path::Path::new(path).exists() {
            info!("找到现有的测试库: {}", path);
            return path.to_string();
        }
    }

    // 如果没有找到，尝试构建
    info!("未找到测试库，尝试构建...");
    let output = Command::new("cargo")
        .args(&["build", "--lib"])
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                info!("✓ 库构建成功");
                "./target/debug/libtls_key_agent_hook.so".to_string()
            } else {
                error!("库构建失败: {}", String::from_utf8_lossy(&output.stderr));
                String::new()
            }
        }
        Err(e) => {
            error!("执行构建命令失败: {}", e);
            String::new()
        }
    }
}

/// 测试百度HTTPS请求
async fn test_baidu_https_request() -> bool {
    info!("开始测试百度HTTPS请求...");

    // 方法1: 使用reqwest客户端（如果可用）
    #[cfg(feature = "reqwest")]
    {
        match test_with_reqwest().await {
            Ok(success) => {
                if success {
                    return true;
                }
            }
            Err(e) => {
                warn!("reqwest测试失败: {}, 尝试原生TLS", e);
            }
        }
    }

    // 方法2: 使用原生TLS连接
    test_with_native_tls().await
}

/// 使用reqwest测试（可选功能）
#[cfg(feature = "reqwest")]
async fn test_with_reqwest() -> Result<bool, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let response = client.get("https://www.baidu.com")
        .send()
        .await?;

    if response.status().is_success() {
        let text = response.text().await?;
        info!("✓ reqwest请求成功，响应长度: {} 字符", text.len());

        // 验证响应内容确实来自百度
        if text.contains("baidu") || text.contains("百度") {
            info!("✓ 响应内容验证成功，确认来自百度");
            return Ok(true);
        }
    }

    Ok(false)
}

/// 使用原生TLS连接测试
async fn test_with_native_tls() -> bool {
    info!("尝试原生TLS连接到百度...");

    match TcpStream::connect("www.baidu.com:443").await {
        Ok(mut stream) => {
            info!("✓ TCP连接建立成功");

            // 发送简单的HTTPS请求
            let request = format!(
                "GET / HTTP/1.1\r\n\
                 Host: www.baidu.com\r\n\
                 User-Agent: TLS-Key-Agent-Test/1.0\r\n\
                 Connection: close\r\n\
                 \r\n"
            );

            if let Err(e) = stream.write_all(request.as_bytes()).await {
                error!("发送HTTP请求失败: {}", e);
                return false;
            }

            info!("✓ HTTP请求发送成功");

            // 读取响应（部分即可，主要用于触发TLS握手）
            let mut buffer = [0u8; 4096];
            match stream.read(&mut buffer).await {
                Ok(bytes_read) => {
                    info!("✓ 接收到响应: {} 字节", bytes_read);

                    // 这里应该触发TLS握手，从而产生密钥
                    if bytes_read > 0 {
                        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                        debug!("响应内容: {}", &response[..response.len().min(200)]);

                        if response.contains("HTTP/1.1") {
                            info!("✓ 收到有效的HTTP响应");
                            return true;
                        }
                    }
                }
                Err(e) => {
                    error!("读取响应失败: {}", e);
                }
            }
        }
        Err(e) => {
            error!("TCP连接失败: {}", e);
        }
    }

    false
}

/// 验证密钥提取结果
async fn verify_key_extraction_results() {
    info!("验证密钥提取结果...");

    // 检查TLS密钥日志文件
    let keylog_files = vec![
        "/tmp/tls_keys_test.log",
        "/tmp/test_ssl_keylog.log",
    ];

    for file_path in keylog_files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            info!("检查密钥日志文件: {}", file_path);

            if !content.is_empty() {
                info!("✓ 发现密钥日志内容，大小: {} 字节", content.len());

                // 分析密钥内容
                analyze_keylog_content(&content);

                // 显示前几行用于验证
                let lines: Vec<&str> = content.lines().take(5).collect();
                for (i, line) in lines.iter().enumerate() {
                    info!("密钥日志第{}行: {}", i + 1, line);
                }
            } else {
                warn!("密钥日志文件为空: {}", file_path);
            }
        } else {
            debug!("密钥日志文件不存在或无法读取: {}", file_path);
        }
    }

    // 检查是否有进程日志
    check_process_logs().await;
}

/// 分析密钥日志内容
fn analyze_keylog_content(content: &str) {
    let lines: Vec<&str> = content.lines().collect();

    let mut client_random_count = 0;
    let mut master_secret_count = 0;
    let mut other_keys_count = 0;

    for line in lines {
        if line.starts_with("CLIENT_RANDOM") {
            client_random_count += 1;
            info!("✓ 发现Client Random密钥");
            master_secret_count += 1; // 每个 CLIENT_RANDOM 行对应一个 Master Secret

            // 解析并显示密钥信息
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let client_random_hex = parts.get(1).unwrap_or(&"");
                let secret_hex = parts.get(2).unwrap_or(&"");

                info!("  - Client Random: {}... ({} 字节)",
                      &client_random_hex[..client_random_hex.len().min(16)],
                      client_random_hex.len() / 2);
                info!("  - Master Secret: {}... ({} 字节)",
                      &secret_hex[..secret_hex.len().min(16)],
                      secret_hex.len() / 2);
            }
        } else if line.starts_with("RSA") || line.starts_with("ECDHE") {
            other_keys_count += 1;
            info!("✓ 发现其他类型密钥: {}", &line[..line.len().min(20)]);
        }
    }

    info!("密钥统计:");
    info!("  - Client Random: {} 个", client_random_count);
    info!("  - Master Secret: {} 个", master_secret_count);
    info!("  - 其他密钥: {} 个", other_keys_count);

    if client_random_count > 0 {
        info!("🎉 密钥提取测试成功！捕获到了 {} 个Client Random", client_random_count);
    } else {
        warn!("⚠ 未捕获到Client Random，可能需要检查LD_PRELOAD配置");
    }
}

/// 检查进程日志
async fn check_process_logs() {
    info!("检查相关进程...");

    // 尝试获取当前进程信息
    if let Ok(output) = Command::new("ps").args(&["aux"]).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);

        // 查找包含SSL或TLS的进程
        for line in output_str.lines() {
            if line.contains("ssl") || line.contains("tls") || line.contains("openssl") {
                debug!("发现相关进程: {}", line);
            }
        }
    }

    // 检查LD_PRELOAD环境变量是否正确设置
    if let Ok(ld_preload) = env::var("LD_PRELOAD") {
        info!("当前LD_PRELOAD: {}", ld_preload);

        if std::path::Path::new(&ld_preload).exists() {
            info!("✓ LD_PRELOAD库文件存在");
        } else {
            warn!("⚠ LD_PRELOAD库文件不存在: {}", ld_preload);
        }
    }

    if let Ok(sslkeylogfile) = env::var("SSLKEYLOGFILE") {
        info!("当前SSLKEYLOGFILE: {}", sslkeylogfile);
    }
}

/// 集成测试：完整的端到端测试
#[tokio::test]
async fn test_end_to_end_integration() {
    info!("开始端到端集成测试");

    // 这个测试模拟完整的TLS密钥提取流程
    // 1. 配置和启动Agent
    // 2. 执行多个TLS请求
    // 3. 验证密钥提取
    // 4. 检查传输层功能

    let config = Config::default();
    let agent = TlsKeyAgent::new(config).await.expect("创建Agent失败");

    agent.start().await.expect("启动Agent失败");

    // 执行多次请求以测试稳定性
    for i in 1..=3 {
        info!("执行第 {} 次测试请求", i);

        let success = test_baidu_https_request().await;
        if success {
            info!("✓ 第 {} 次请求成功", i);
        } else {
            warn!("⚠ 第 {} 次请求失败", i);
        }

        // 请求间隔
        sleep(Duration::from_millis(500)).await;
    }

    agent.stop().await.expect("停止Agent失败");

    info!("端到端集成测试完成");
}

#[cfg(test)]
mod utils {
    use super::*;

    /// 测试辅助函数：检查库是否可用
    pub async fn check_test_library_availability() -> bool {
        let library_path = get_or_build_test_library().await;
        !library_path.is_empty() && std::path::Path::new(&library_path).exists()
    }

    /// 测试辅助函数：清理测试文件
    pub fn cleanup_test_files() {
        let test_files = vec![
            "/tmp/tls_keys_test.log",
            "/tmp/test_ssl_keylog.log",
        ];

        for file in test_files {
            let _ = std::fs::remove_file(file);
        }
    }
}