use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // 注入「编译时间」（Unix 秒），供 license 模块计算一年有效期。
    // 优先取 SOURCE_DATE_EPOCH（可复现构建约定），否则用当前系统时间。
    // 发布产物一般由干净构建生成，此刻即真实编译时间。
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=CT_BUILD_EPOCH={epoch}");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    // tauri_build::build() 依赖 `tauri` crate 注入的构建指令（cargo:dev 等）。
    // 服务模式（--no-default-features）不编译 tauri，因此仅在 desktop 特性下调用，
    // 否则会 panic（"missing cargo:dev instruction"）。
    if std::env::var_os("CARGO_FEATURE_DESKTOP").is_some() {
        tauri_build::build();
    }
}
