use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    // 获取环境变量
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // 获取项目根目录（规范化的路径）
    let manifest_path = PathBuf::from(&manifest_dir);
    let project_root = manifest_path
        .parent()
        .expect("Failed to get project root");

    // 设置 eBPF 编译目标
    let target = "bpfel-unknown-none";
    let package_name = "xdp-scanner-detect-ebpf";

    // 设置 RUSTFLAGS 用于 eBPF 编译
    // 注意：使用 -Z build-std 时需要显式设置 panic=abort
    let rustflags = format!(
        "--cfg=bpf_target_arch=\"x86_64\"\x1f-Cpanic=abort\x1f-Cdebuginfo=2\x1f-Clink-arg=--btf"
    );

    // 构建命令
    let status = Command::new("rustup")
        .args([
            "run",
            "nightly",
            "cargo",
            "build",
            "--package",
            package_name,
            "-Z",
            "build-std=core",
            "--bins",
            "--release",
            "--target",
            target,
            "--target-dir",
            &out_dir,
        ])
        .env("CARGO_ENCODED_RUSTFLAGS", &rustflags)
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .current_dir(&project_root)
        .status()
        .expect("Failed to execute cargo build");

    if !status.success() {
        panic!("Failed to build eBPF program");
    }

    // 源文件路径
    let src_file = format!("{}/{}/release/{}", out_dir, target, package_name);

    // 获取项目根目录的 target 目录（使用规范化的路径）
    let target_dir = project_root.join("target");
    let dest_dir = target_dir.join(target).join("release");

    // 创建目标目录
    fs::create_dir_all(&dest_dir).expect("Failed to create target directory");

    // 复制文件
    let dest_file = dest_dir.join(package_name);
    fs::copy(&src_file, &dest_file).expect("Failed to copy eBPF binary");

    println!("cargo:warning=eBPF binary copied to: {}", dest_file.display());
    println!("cargo:rerun-if-changed=../ebpf");
}
