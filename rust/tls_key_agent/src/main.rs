use clap::{Arg, Command};
use std::process;
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tls_key_agent::{Config, TlsKeyAgent};

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tls_key_agent=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let matches = Command::new("TLS Key Agent")
        .version("0.1.0")
        .author("sollor525@hotmail.com")
        .about("高性能TLS密钥提取Agent")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("配置文件路径")
                .default_value("config.toml"),
        )
        .arg(
            Arg::new("daemon")
                .short('d')
                .long("daemon")
                .help("以守护进程模式运行")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    info!("启动TLS密钥提取Agent v0.1.0");

    // 加载配置
    let config_path = matches.get_one::<String>("config").unwrap();
    let config = match Config::from_file(config_path) {
        Ok(config) => {
            info!("成功加载配置文件: {}", config_path);
            config
        }
        Err(e) => {
            error!("加载配置文件失败: {}", e);
            process::exit(1);
        }
    };

    // 创建Agent实例
    let agent = match TlsKeyAgent::new(config).await {
        Ok(agent) => agent,
        Err(e) => {
            error!("创建Agent失败: {}", e);
            process::exit(1);
        }
    };

    // 设置信号处理
    let agent_clone = agent.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("无法监听Ctrl+C信号");
        info!("收到停止信号，正在关闭Agent...");
        if let Err(e) = agent_clone.stop().await {
            error!("停止Agent时发生错误: {}", e);
        }
        process::exit(0);
    });

    // 启动Agent
    if let Err(e) = agent.start().await {
        error!("启动Agent失败: {}", e);
        process::exit(1);
    }

    info!("TLS密钥提取Agent已启动，按Ctrl+C停止");

    // 保持主线程运行
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        if !agent.is_running().await {
            error!("Agent异常停止");
            process::exit(1);
        }
    }
}
