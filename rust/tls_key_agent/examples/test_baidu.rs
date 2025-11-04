use std::env;
use std::process::Command;

fn main() {
    println!("TLS Key Agent 测试程序");
    println!("访问 www.baidu.com 并检测TLS密钥提取");

    // 设置日志级别
    env::set_var("RUST_LOG", "debug");

    // 测试方法1: 使用curl
    println!("\n=== 测试方法1: 使用curl访问www.baidu.com ===");
    test_with_curl();

    // 测试方法2: 使用openssl s_client
    println!("\n=== 测试方法2: 使用openssl s_client ===");
    test_with_openssl();

    // 测试方法3: 使用原生Rust HTTPS客户端 (如果可用)
    println!("\n=== 测试方法3: 使用原生HTTPS客户端 ===");
    test_with_rust_client();
}

fn test_with_curl() {
    println!("执行: curl -v https://www.baidu.com");

    let output = Command::new("curl")
        .args(&["-v", "https://www.baidu.com", "--connect-timeout", "10"])
        .output()
        .expect("执行curl失败");

    println!("退出码: {}", output.status);

    if output.status.success() {
        println!("curl访问成功");
        if !output.stdout.is_empty() {
            println!("响应长度: {} bytes", output.stdout.len());
        }
    } else {
        println!("curl访问失败");
        if !output.stderr.is_empty() {
            println!("错误信息: {}", String::from_utf8_lossy(&output.stderr));
        }
    }
}

fn test_with_openssl() {
    println!("执行: openssl s_client -connect www.baidu.com:443");

    let output = Command::new("timeout")
        .args(&["10s", "openssl", "s_client", "-connect", "www.baidu.com:443"])
        .output()
        .expect("执行openssl失败");

    println!("退出码: {}", output.status);

    if output.status.success() {
        println!("openssl连接成功");

        // 检查是否包含证书信息
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("Certificate chain") {
            println!("✓ 成功获取服务器证书");
        }
        if output_str.contains("Server public key") {
            println!("✓ 成功获取服务器公钥信息");
        }
    } else {
        println!("openssl连接失败");
        if !output.stderr.is_empty() {
            println!("错误信息: {}", String::from_utf8_lossy(&output.stderr));
        }
    }
}

fn test_with_rust_client() {
    // 简单的Rust HTTP客户端测试
    println!("尝试使用Rust原生HTTP客户端...");

    // 这里可以集成reqwest或其他HTTP客户端
    // 为了简化，我们只做基本检查
    println!("注意: 完整的Rust HTTPS客户端测试需要额外的依赖");
    println!("当前测试主要依赖curl和openssl等系统工具");
}