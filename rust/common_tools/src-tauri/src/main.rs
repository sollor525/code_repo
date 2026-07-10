// 发布版桌面程序隐藏控制台窗口（仅 Windows + release + 桌面特性）。
#![cfg_attr(
    all(not(debug_assertions), feature = "desktop", target_os = "windows"),
    windows_subsystem = "windows"
)]

mod network_utils;
mod packet_analyzer;
mod pcap_generator;
mod regex_matcher;
mod md5_utils;
mod string_converter;
mod cron_utils;
mod base64_utils;
mod json_utils;
mod web_api;
mod server;

// =========================================================================
// 桌面模式（默认）：在后台线程启动内嵌 axum 服务，再打开指向它的 Tauri 窗口。
// 这样既保留了现有的 HTML/CSS/JS 前端与 fetch('/api/...') 调用，
// 又获得了原生桌面外壳。
// =========================================================================
#[cfg(feature = "desktop")]
fn main() {
    use std::sync::mpsc;

    let (port_tx, port_rx) = mpsc::channel::<u16>();

    // 后台线程：独立的 Tokio 运行时承载内嵌服务
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("无法创建 Tokio 运行时");

        runtime.block_on(async move {
            match tokio::net::TcpListener::bind("127.0.0.1:0").await {
                Ok(listener) => {
                    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
                    let _ = port_tx.send(port);
                    if let Err(e) = axum::serve(listener, server::create_router()).await {
                        eprintln!("内嵌服务异常退出: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("无法绑定本地端口: {e}");
                    let _ = port_tx.send(0);
                }
            }
        });
    });

    // 等待服务选定端口后再加载窗口
    let port = port_rx.recv().expect("未能获取内嵌服务端口");
    let url = format!("http://127.0.0.1:{port}");

    tauri::Builder::default()
        .setup(move |app| {
            tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::External(url.parse().expect("内嵌服务 URL 无效")),
            )
            .title("开发辅助工具")
            .inner_size(1240.0, 840.0)
            .min_inner_size(900.0, 600.0)
            .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Tauri 应用启动失败");
}

// =========================================================================
// 服务模式（--no-default-features）：纯 axum 服务，无 Tauri 依赖。
// 用于在没有 WebView 运行时的环境（如本 Linux 构建机）验证全部应用逻辑。
// 端口可用环境变量 CT_PORT 指定，默认自动选择空闲端口。
// =========================================================================
#[cfg(not(feature = "desktop"))]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;

    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let port: u16 = std::env::var("CT_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let bound = listener.local_addr()?;
    tracing::info!("开发辅助工具（服务模式）已启动: http://{}", bound);

    axum::serve(listener, server::create_router()).await?;
    Ok(())
}
