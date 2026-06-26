fn main() {
    // tauri_build::build() 依赖 `tauri` crate 注入的构建指令（cargo:dev 等）。
    // 服务模式（--no-default-features）不编译 tauri，因此仅在 desktop 特性下调用，
    // 否则会 panic（"missing cargo:dev instruction"）。
    if std::env::var_os("CARGO_FEATURE_DESKTOP").is_some() {
        tauri_build::build();
    }
}
