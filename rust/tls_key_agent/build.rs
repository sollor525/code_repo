use std::env;

fn main() {
    // 获取目标架构
    let target = env::var("TARGET").unwrap_or_else(|_| "x86_64-unknown-linux-gnu".to_string());

    // 只在Linux系统下构建eBPF程序
    if !target.contains("linux") {
        println!("警告：eBPF功能仅在Linux系统上支持");
        return;
    }

    // 注意：项目已升级为eBPF架构，不再需要编译LD_PRELOAD Hook库
    // eBPF程序将在运行时加载和编译

    println!("cargo:rerun-if-changed=src/injector/ebpf.rs");
    println!("cargo:rerun-if-changed=src/ffi/mod.rs");
    println!("cargo:rerun-if-changed=build.rs");

    // 链接系统库以支持eBPF和网络功能
    println!("cargo:rustc-link-lib=dylib=elf");
    println!("cargo:rustc-link-lib=dylib=z");

    // 输出构建信息
    println!("cargo:warning=TLS Key Agent 现在使用eBPF架构，无需编译LD_PRELOAD Hook库");
}