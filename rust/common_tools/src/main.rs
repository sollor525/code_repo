mod network_utils;
mod packet_analyzer;
mod regex_matcher;
mod web_api;

use clap::Parser;
use log::info;
use std::env;
use std::net::SocketAddr;
use warp::Filter;

#[derive(Parser)]
#[command(name = "common_tools")]
#[command(about = "A collection of common utility tools as a web service")]
#[command(version = "0.1.0")]
struct Args {
    /// Server port to listen on
    #[arg(short, long, default_value = "3030")]
    port: u16,

    /// Server host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    info!("启动通用工具集 Web 服务");

    let args = Args::parse();

    // 设置日志级别
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info");
    }

    info!("服务器启动在 http://{}:{}", args.host, args.port);

    // 创建 Web API 路由
    let api = web_api::create_routes();
    info!("API 路由创建完成");

    // 健康检查端点
    let health = warp::path("health")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "service": "common_tools"
            }))
        });

    // CORS 支持
    let cors = warp::cors()
        .allow_any_origin()
        .allow_headers(vec!["content-type"])
        .allow_methods(vec!["GET", "POST", "OPTIONS"]);

    // 静态文件服务 - 优先处理HTML页面
    let index = warp::path::end()
        .and(warp::fs::file("static/index.html"));

    let html_files = warp::path("network.html")
        .and(warp::fs::file("static/network.html"))
        .or(warp::path("packet.html")
            .and(warp::fs::file("static/packet.html")))
        .or(warp::path("regex.html")
            .and(warp::fs::file("static/regex.html")));

    let static_files = warp::path("static")
        .and(warp::fs::dir("static"))
        .or(index)
        .or(html_files);

    info!("静态文件路由配置完成");

      // API信息路由 - 返回JSON API信息
    let api_info = warp::path("api")
        .and(warp::path::end())
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "name": "Common Tools Web API",
                "version": "0.1.0",
                "endpoints": {
                    "health": "/health",
                    "network": "/api/network",
                    "packet": "/api/packet",
                    "regex": "/api/regex"
                },
                "description": "A collection of common utility tools"
            }))
        });

    // 组合所有路由 - 重要：静态文件路由优先级最高
    let routes = health
        .or(api_info)
        .or(api)
        .or(static_files)
        .with(cors)
        .with(warp::log("common_tools"));

    info!("所有路由配置完成");

    // 启动服务器
    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    info!("服务器正在监听: {}", addr);

    warp::serve(routes)
        .run(addr)
        .await;

    Ok(())
}