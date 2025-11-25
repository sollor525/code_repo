//! Rust项目的构建脚本
//! 
//! 这个文件在项目编译时自动执行，用于：
//! 1. 生成C语言头文件（通过cbindgen）
//! 2. 配置链接器设置
//! 3. 检测系统依赖库
//! 
//! 在Rust中，build.rs是一个特殊的构建脚本，会在编译前执行

// 导入标准库中的环境变量处理模块
use std::env;
// 导入标准库中的路径处理模块
use std::path::PathBuf;

/// 主构建函数
/// 
/// 这个函数在cargo build时自动调用，用于：
/// - 生成C语言绑定头文件
/// - 配置编译选项
/// - 设置链接器参数
fn main() {
    // 获取当前crate（Rust包）的目录路径
    // CARGO_MANIFEST_DIR是cargo设置的环境变量，指向Cargo.toml所在目录
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    
    // 获取包名（来自Cargo.toml中的name字段）
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    
    // 构建输出头文件的完整路径
    // target_dir()函数获取目标目录，然后拼接include子目录和头文件名
    let output_file = target_dir()
        .join("include")                    // 添加include子目录
        .join(format!("{}.h", package_name)); // 生成头文件名（如web_scan_rust.h）

    // 确保输出目录存在
    // parent()获取父目录，create_dir_all()创建所有必要的父目录
    // unwrap()用于获取Result的Ok值，如果失败则panic（在构建脚本中这是可以接受的）
    std::fs::create_dir_all(output_file.parent().unwrap()).unwrap();

    // 使用cbindgen生成C语言头文件
    // cbindgen是一个工具，可以将Rust代码转换为C语言头文件
    // 如果生成失败，只输出警告，不中断编译
    match cbindgen::Builder::new()                    // 创建新的cbindgen构建器
        .with_crate(crate_dir)                  // 指定要处理的crate目录
        .with_language(cbindgen::Language::C)   // 生成C语言头文件
        .with_config(cbindgen::Config::from_file("cbindgen.toml").unwrap()) // 使用配置文件
        .generate() {                              // 生成绑定
        Ok(bindings) => {
            bindings.write_to_file(&output_file);           // 将结果写入文件
        }
        Err(e) => {
            // 如果生成失败，输出警告但不中断编译
            eprintln!("Warning: Failed to generate C bindings: {}", e);
            eprintln!("Continuing build without C header file generation...");
        }
    }

    // 告诉cargo何时需要重新运行构建脚本
    // 这些println!语句是cargo的特殊指令格式
    println!("cargo:rerun-if-changed=src/");           // 如果src目录有变化，重新运行
    println!("cargo:rerun-if-changed=cbindgen.toml");  // 如果配置文件有变化，重新运行
    
    // 检测并链接hyperscan库（如果系统中有的话）
    // pkg_config::probe_library()尝试查找名为"libhs"的库
    if pkg_config::probe_library("libhs").is_ok() {
        // 如果找到了hyperscan库，告诉链接器链接它
        println!("cargo:rustc-link-lib=hs");           // 链接libhs库
        println!("cargo:rustc-cfg=feature=\"hyperscan\""); // 启用hyperscan特性
    }
}

/// 获取目标目录路径
/// 
/// 这个函数返回编译输出的目标目录路径。
/// 在Rust中，编译后的文件通常放在target目录下。
/// 
/// # 返回值
/// * `PathBuf` - 目标目录的路径
fn target_dir() -> PathBuf {
    // 首先尝试从环境变量获取目标目录
    if let Ok(target) = env::var("CARGO_TARGET_DIR") {
        // 如果设置了CARGO_TARGET_DIR环境变量，使用它
        PathBuf::from(target)
    } else {
        // 否则使用默认的target目录（在crate根目录下）
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("target")
    }
}