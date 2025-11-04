use std::env;
use std::process::Command;
use std::path::Path;
use std::fs;

/// LD_PRELOAD集成测试程序
fn main() {
    println!("TLS Key Agent LD_PRELOAD 集成测试");
    println!("=====================================");

    // 设置环境变量
    env::set_var("RUST_LOG", "debug");

    // 检查当前目录
    let current_dir = env::current_dir().unwrap();
    println!("当前工作目录: {:?}", current_dir);

    // 尝试构建项目
    println!("\n=== 步骤1: 构建TLS Key Agent ===");
    if !build_project() {
        println!("构建失败，退出测试");
        return;
    }

    // 查找动态库文件
    println!("\n=== 步骤2: 查找动态库文件 ===");
    let lib_path = find_library_file();
    if lib_path.is_none() {
        println!("未找到动态库文件，退出测试");
        return;
    }
    let lib_path = lib_path.unwrap();
    println!("找到动态库: {:?}", lib_path);

    // 设置LD_PRELOAD
    println!("\n=== 步骤3: 设置LD_PRELOAD环境变量 ===");
    setup_ld_preload(&lib_path);

    // 运行测试
    println!("\n=== 步骤4: 运行HTTPS连接测试 ===");
    run_https_tests();

    // 清理环境
    println!("\n=== 步骤5: 清理环境 ===");
    cleanup_ld_preload();

    println!("\n测试完成！");
}

fn build_project() -> bool {
    println!("执行: cargo build --lib");

    let output = Command::new("cargo")
        .args(&["build", "--lib"])
        .output()
        .expect("执行cargo build失败");

    println!("构建退出码: {}", output.status);

    if output.status.success() {
        println!("✓ 项目构建成功");
        true
    } else {
        println!("✗ 项目构建失败");
        println!("错误信息:");
        println!("{}", String::from_utf8_lossy(&output.stderr));
        false
    }
}

fn find_library_file() -> Option<std::path::PathBuf> {
    // 常见的动态库文件名模式
    let library_patterns = vec![
        "target/debug/libtls_key_agent.so",
        "target/debug/libtls_key_agent.dylib", // macOS
        "target/debug/tls_key_agent.dll",      // Windows
        "target/debug/libtls_key_agent.so",    // Linux
    ];

    for pattern in library_patterns {
        let path = Path::new(pattern);
        if path.exists() {
            println!("找到库文件: {:?}", path);
            return Some(path.to_path_buf());
        }
    }

    // 查找target目录下所有.so文件
    if let Ok(entries) = fs::read_dir("target/debug") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(filename) = path.file_name() {
                if let Some(filename_str) = filename.to_str() {
                    if filename_str.contains("tls_key_agent") &&
                       (filename_str.ends_with(".so") || filename_str.ends_with(".dylib")) {
                        println!("找到匹配的库文件: {:?}", path);
                        return Some(path);
                    }
                }
            }
        }
    }

    println!("未找到动态库文件");
    None
}

fn setup_ld_preload(lib_path: &std::path::Path) {
    let lib_path_str = lib_path.to_string_lossy();

    // 获取当前LD_PRELOAD值
    let current_preload = env::var("LD_PRELOAD").unwrap_or_default();

    // 设置新的LD_PRELOAD
    let new_preload = if current_preload.is_empty() {
        lib_path_str.to_string()
    } else {
        format!("{}:{}", current_preload, lib_path_str)
    };

    env::set_var("LD_PRELOAD", &new_preload);
    println!("设置 LD_PRELOAD = {}", new_preload);

    // 验证设置
    if let Ok(preload_check) = env::var("LD_PRELOAD") {
        if preload_check.contains(&*lib_path_str) {
            println!("✓ LD_PRELOAD设置成功");
        } else {
            println!("✗ LD_PRELOAD设置失败");
        }
    }
}

fn run_https_tests() {
    // 测试1: curl
    println!("\n--- 测试1: curl www.baidu.com ---");
    test_curl_baidu();

    // 测试2: openssl s_client
    println!("\n--- 测试2: openssl s_client ---");
    test_openssl_baidu();

    // 测试3: python requests (如果可用)
    println!("\n--- 测试3: Python requests ---");
    test_python_baidu();
}

fn test_curl_baidu() {
    let output = Command::new("curl")
        .args(&["-v", "https://www.baidu.com", "--connect-timeout", "10", "-m", "30"])
        .output()
        .expect("执行curl失败");

    println!("curl退出码: {}", output.status);

    if output.status.success() {
        println!("✓ curl访问成功");
        println!("响应长度: {} bytes", output.stdout.len());

        // 检查是否包含百度相关内容
        let response = String::from_utf8_lossy(&output.stdout);
        if response.contains("baidu") || response.contains("百度") {
            println!("✓ 响应内容包含百度标识");
        }
    } else {
        println!("✗ curl访问失败");
        if !output.stderr.is_empty() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            println!("错误: {}", error_msg);

            // 检查是否是库相关错误
            if error_msg.contains("cannot open shared object file") ||
               error_msg.contains("ld.so") ||
               error_msg.contains("library") {
                println!("⚠️  这可能是LD_PRELOAD库加载问题");
            }
        }
    }
}

fn test_openssl_baidu() {
    let output = Command::new("timeout")
        .args(&["15s", "openssl", "s_client", "-connect", "www.baidu.com:443"])
        .output()
        .expect("执行openssl失败");

    println!("openssl退出码: {}", output.status);

    if output.status.success() {
        println!("✓ openssl连接成功");

        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.contains("Certificate chain") {
            println!("✓ 获取到服务器证书链");
        }
        if output_str.contains("Server public key") {
            println!("✓ 获取到服务器公钥信息");
        }
        if output_str.contains("TLSv1.") {
            println!("✓ TLS握手完成");
        }
    } else {
        println!("✗ openssl连接失败");
        if !output.stderr.is_empty() {
            println!("错误: {}", String::from_utf8_lossy(&output.stderr));
        }
    }
}

fn test_python_baidu() {
    // 检查Python是否可用
    if Command::new("python3").arg("--version").output().is_ok() ||
       Command::new("python").arg("--version").output().is_ok() {

        let python_cmd = if Command::new("python3").arg("--version").output().is_ok() {
            "python3"
        } else {
            "python"
        };

        let script = r#"
import sys
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    response = requests.get('https://www.baidu.com', timeout=10, verify=False)
    print(f"HTTP状态码: {response.status_code}")
    print(f"响应长度: {len(response.text)} bytes")
    if 'baidu' in response.text.lower():
        print("✓ 响应包含百度内容")
except ImportError:
    print("Python requests库未安装")
except Exception as e:
    print(f"Python请求失败: {e}")
"#;

        let output = Command::new(python_cmd)
            .arg("-c")
            .arg(script)
            .output();

        if let Ok(result) = output {
            println!("Python退出码: {}", result.status);
            if !result.stdout.is_empty() {
                println!("{}", String::from_utf8_lossy(&result.stdout));
            }
            if !result.stderr.is_empty() {
                println!("错误: {}", String::from_utf8_lossy(&result.stderr));
            }
        } else {
            println!("无法执行Python");
        }
    } else {
        println!("Python不可用，跳过Python测试");
    }
}

fn cleanup_ld_preload() {
    // 恢复原始LD_PRELOAD
    env::remove_var("LD_PRELOAD");
    println!("已清除LD_PRELOAD环境变量");
}