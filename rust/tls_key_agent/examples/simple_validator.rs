use std::env;
use std::process::Command;

/// 简化的TLS密钥验证工具
fn main() {
    println!("TLS Key Agent 简化验证工具");
    println!("========================");

    // 设置环境变量
    env::set_var("RUST_LOG", "info");

    // 构建项目
    println!("🔨 构建项目...");
    let output = Command::new("cargo")
        .args(&["build", "--lib"])
        .output()
        .expect("执行cargo build失败");

    if !output.status.success() {
        println!("❌ 构建失败");
        return;
    }
    println!("✅ 构建成功");

    // 查找动态库
    let lib_path = "target/debug/libtls_key_agent.so";
    if !std::path::Path::new(lib_path).exists() {
        println!("❌ 未找到动态库: {}", lib_path);
        return;
    }
    println!("✅ 找到动态库: {}", lib_path);

    // 运行简单的验证测试
    run_simple_validation(lib_path);
}

fn run_simple_validation(lib_path: &str) {
    println!("\n🔍 开始简化验证测试...");

    // 设置LD_PRELOAD
    env::set_var("LD_PRELOAD", lib_path);
    println!("设置 LD_PRELOAD = {}", lib_path);

    // 测试1: curl 百度
    println!("\n--- 测试1: curl https://www.baidu.com ---");
    let output = Command::new("curl")
        .args(&["-s", "-w", "状态码: %{http_code}, 大小: %{size_download} bytes",
               "https://www.baidu.com", "--connect-timeout", "10"])
        .output()
        .expect("执行curl失败");

    if output.status.success() {
        println!("✅ curl连接成功");
        let response = String::from_utf8_lossy(&output.stdout);
        println!("响应信息: {}", response.trim());
    } else {
        println!("❌ curl连接失败");
    }

    // 测试2: openssl连接
    println!("\n--- 测试2: openssl s_client ---");
    let output = Command::new("timeout")
        .args(&["10s", "openssl", "s_client", "-connect", "www.baidu.com:443"])
        .output()
        .expect("执行openssl失败");

    if output.status.success() {
        println!("✅ openssl连接成功");
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("Certificate chain") {
            println!("✅ 获取到证书链");
        }
        if output_str.contains("SSL-Session") {
            println!("✅ 建立了SSL会话");
        }
    } else {
        println!("❌ openssl连接失败");
    }

    // 清理环境
    env::remove_var("LD_PRELOAD");
    println!("\n✅ 验证测试完成，环境已清理");
}