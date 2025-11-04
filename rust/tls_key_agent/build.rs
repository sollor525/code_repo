use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/openssl_hook.c");
    println!("cargo:rerun-if-changed=src/ffi/hook_library.rs");

    // 获取目标架构
    let target = env::var("TARGET").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();

    // 只在Linux系统下构建Hook库
    if !target.contains("linux") {
        return;
    }

    // 编译C语言的OpenSSL Hook
    compile_c_hook_library(&out_dir);

    // 编译Rust语言的Hook库
    compile_rust_hook_library(&out_dir);
}

fn compile_c_hook_library(out_dir: &str) {
    // 编译OpenSSL Hook C代码
    let hook_lib_path = Path::new(out_dir).join("libopenssl_hook.so");

    println!("编译C语言OpenSSL Hook库...");

    let cc_output = Command::new("gcc")
        .args([
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-o", hook_lib_path.to_str().unwrap(),
            "src/openssl_hook.c",
            "-ldl"
        ])
        .output();

    match cc_output {
        Ok(output) => {
            if output.status.success() {
                println!("✓ C Hook库编译成功: {}", hook_lib_path.display());
                println!("cargo:rustc-link-search=native={}", out_dir);
                println!("cargo:rustc-link-lib=dylib=openssl_hook");
            } else {
                println!("⚠ C Hook库编译失败，将跳过C Hook功能");
                println!("错误: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(e) => {
            println!("⚠ 无法执行gcc编译器，将跳过C Hook功能: {}", e);
        }
    }
}

fn compile_rust_hook_library(out_dir: &str) {
    println!("编译Rust语言TLS Hook库...");

    // 检查Rust Hook源文件是否存在
    if !Path::new("src/ffi/hook_library.rs").exists() {
        println!("⚠ Rust Hook源文件不存在，跳过Rust Hook编译");
        return;
    }

    let hook_lib_path = Path::new(out_dir).join("libtls_key_agent_hook.so");

    let rustc_output = Command::new("rustc")
        .args([
            "--crate-type", "cdylib",
            "--edition", "2021",
            "-O",
            "-o", hook_lib_path.to_str().unwrap(),
            "src/ffi/hook_library.rs",
        ])
        .output();

    match rustc_output {
        Ok(output) => {
            if output.status.success() {
                println!("✓ Rust Hook库编译成功: {}", hook_lib_path.display());

                // 创建符号链接到target目录
                create_symlink_to_target_dir(&hook_lib_path);
            } else {
                println!("⚠ Rust Hook库编译失败:");
                println!("{}", String::from_utf8_lossy(&output.stderr));
            }
        }
        Err(e) => {
            println!("⚠ 无法执行rustc编译器: {}", e);
        }
    }
}

fn create_symlink_to_target_dir(hook_lib_path: &Path) {
    let profile = env::var("PROFILE").unwrap_or("debug".to_string());
    let target_dir = Path::new("target").join(&profile);

    // 创建目标目录
    if let Err(e) = fs::create_dir_all(&target_dir) {
        println!("创建目标目录失败: {}", e);
        return;
    }

    let symlink_path = target_dir.join("libtls_key_agent_hook.so");

    // 删除已存在的符号链接
    if symlink_path.exists() {
        let _ = fs::remove_file(&symlink_path);
    }

    // 创建新的符号链接
    if let Err(e) = std::os::unix::fs::symlink(hook_lib_path, &symlink_path) {
        println!("创建符号链接失败: {}", e);
        // 如果符号链接失败，尝试复制文件
        if let Err(e) = fs::copy(hook_lib_path, &symlink_path) {
            println!("复制Hook库文件也失败: {}", e);
        } else {
            println!("✓ Hook库文件复制成功: {}", symlink_path.display());
        }
    } else {
        println!("✓ Hook库符号链接创建成功: {}", symlink_path.display());
    }
}