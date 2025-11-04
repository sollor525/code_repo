/**
 * @file integration_test.rs
 * @brief TLS Key Agent 集成测试示例
 * @author sollor525@hotmail.com
 * @version 0.1.0
 * @date 2023-11-04
 */

use std::sync::Arc;
use std::path::Path;
use tracing::{info, error, debug};
use tracing_subscriber;

use tls_key_agent::{TlsKeyAgent, Config};
use tls_key_agent::extractor::ld_preload::get_ld_preload_manager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志系统
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    info!("=== TLS Key Agent 集成测试开始 ===");

    // 创建配置
    let config = Config::default();
    info!("配置初始化完成");

    // 获取 OpenSSL Hook 库路径
    let library_path = "./target/release/libopenssl_hook.so";
    if !Path::new(library_path).exists() {
        error!("OpenSSL Hook 库文件不存在: {}", library_path);
        error!("请先运行: cargo build --release");
        return Err("库文件不存在".into());
    }

    // 获取 LD_PRELOAD 管理器
    let preload_manager = get_ld_preload_manager();

    // 加载 OpenSSL Hook 库
    match preload_manager.load_library(library_path) {
        Ok(()) => info!("OpenSSL Hook 库加载成功"),
        Err(e) => {
            error!("OpenSSL Hook 库加载失败: {}", e);
            return Err(e.into());
        }
    }

    // 安装 SSL Hook
    match preload_manager.install_ssl_hooks(Some("./config.toml")) {
        Ok(()) => info!("SSL Hook 安装成功"),
        Err(e) => {
            error!("SSL Hook 安装失败: {}", e);
            return Err(e.into());
        }
    }

    // 检查 Hook 状态
    match preload_manager.get_hook_status() {
        Ok(status) => info!("Hook 状态: {}", if status { "已激活" } else { "未激活" }),
        Err(e) => error!("获取 Hook 状态失败: {}", e),
    }

    // 设置日志级别
    if let Err(e) = preload_manager.set_log_level(1) {
        error!("设置日志级别失败: {}", e);
    }

    // 创建 TLS Key Agent 实例
    let agent = match TlsKeyAgent::new(config).await {
        Ok(agent) => {
            info!("TLS Key Agent 创建成功");
            agent
        }
        Err(e) => {
            error!("TLS Key Agent 创建失败: {}", e);
            return Err(e.into());
        }
    };

    // 启动 Agent
    match agent.start().await {
        Ok(()) => info!("TLS Key Agent 启动成功"),
        Err(e) => {
            error!("TLS Key Agent 启动失败: {}", e);
            return Err(e.into());
        }
    }

    info!("集成测试完成 - Hook 已安装并激活");
    info!("现在可以运行使用 OpenSSL 的应用程序来测试密钥提取功能");
    info!("例如: LD_PRELOAD={} curl https://www.google.com", library_path);

    // 保持运行状态
    tokio::signal::ctrl_c().await?;
    info!("收到终止信号，开始清理...");

    // 停止 Agent
    if let Err(e) = agent.stop().await {
        error!("停止 TLS Key Agent 失败: {}", e);
    }

    // 卸载 SSL Hook
    if let Err(e) = preload_manager.uninstall_ssl_hooks() {
        error!("卸载 SSL Hook 失败: {}", e);
    }

    // 卸载库
    preload_manager.unload_library();

    info!("=== TLS Key Agent 集成测试结束 ===");
    Ok(())
}