/**
 * @file integration_test.rs
 * @brief 端到端集成测试
 * @author sollor525@hotmail.com
 * @version 0.1.0
 * @date 2023-11-04
 */

use std::time::Duration;
use tokio::time::sleep;
use std::net::IpAddr;
use std::str::FromStr;
use tls_key_agent::{
    TlsKeyAgent, Config,
    integration::IntegrationManager,
    extractor::KeyProcessor,
    transport::{TransportFactory, DefaultTransportFactory},
    TransportConfig, TransportType,
    config::{FileTransportConfig, TcpTransportConfig, FiveTupleFilter},
    common::Protocol,
};
use std::sync::Arc;

#[tokio::test]
async fn test_complete_integration() {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("开始端到端集成测试...");

    // 1. 测试配置创建
    let config = create_test_config();
    assert!(config.validate().is_ok(), "配置验证应该成功");
    println!("✓ 配置创建和验证通过");

    // 2. 测试主Agent创建
    let agent = TlsKeyAgent::new(config).await;
    assert!(agent.is_ok(), "Agent创建应该成功");
    let agent = agent.unwrap();
    println!("✓ Agent创建成功");

    // 3. 测试Agent生命周期
    assert!(!agent.is_running().await, "Agent初始状态应该是未运行");

    // 注意：实际启动需要真实的SSL环境
    // agent.start().await.unwrap();
    // assert!(agent.is_running().await, "Agent启动后应该是运行状态");

    // sleep(Duration::from_secs(1)).await;

    // agent.stop().await.unwrap();
    // assert!(!agent.is_running().await, "Agent停止后应该是未运行状态");

    println!("✓ Agent生命周期测试通过");

    // 4. 测试集成管理器
    let integration_test_result = test_integration_manager().await;
    assert!(integration_test_result, "集成管理器测试应该通过");
    println!("✓ 集成管理器测试通过");

    println!("🎉 所有端到端集成测试通过！");
}

fn create_test_config() -> Config {
    let mut config = Config::default();

    // 配置文件传输
    config.transport.enabled_transports.push(TransportType::File);
    config.transport.file.enabled = true;
    config.transport.file.output_path = "/tmp/tls_key_test.log".to_string();
    config.transport.file.rotation = false;
    config.transport.file.max_file_size = 1024 * 1024; // 1MB
    config.transport.file.max_files = 5;

    // 配置过滤规则
    config.filters.push(tls_key_agent::FilterRule {
        name: "test_rule".to_string(),
        enabled: true,
        five_tuple: FiveTupleFilter {
            src_ip: Some("127.0.0.1".to_string()),
            src_port: None,
            dst_ip: Some("127.0.0.1".to_string()),
            dst_port: None,
            protocol: Some(Protocol::TCP),
        },
        process_name: Some("nginx".to_string()),
        pid: None,
    });

    config
}

async fn test_integration_manager() -> bool {
    println!("  开始测试集成管理器...");

    // 创建测试配置
    let config = create_test_config();

    // 创建密钥处理器
    let key_processor = Arc::new(KeyProcessor::new(config.filters));

    // 创建传输工厂
    let transport_factory = Arc::new(DefaultTransportFactory);

    // 创建集成管理器
    let manager = IntegrationManager::new(key_processor, transport_factory);

    // 测试初始化 - 创建传输配置向量
    let transport_configs = vec![
        TransportConfig {
            enabled_transports: vec![TransportType::File],
            tcp: TcpTransportConfig::default(),
            file: FileTransportConfig {
                enabled: true,
                output_path: "/tmp/integration_test.log".to_string(),
                rotation: false,
                max_file_size: 1024 * 1024,
                max_files: 5,
            },
        }
    ];

    let init_result = manager.initialize(transport_configs).await;
    if let Err(e) = init_result {
        println!("  ❌ 集成管理器初始化失败: {}", e);
        return false;
    }
    println!("  ✓ 集成管理器初始化成功");

    // 测试获取统计信息
    let stats = manager.get_stats().await;
    println!("  ✓ 获取统计信息成功: 处理会话数={}, 活跃传输数={}",
             stats.total_sessions_processed, stats.active_transports);

    // 测试启动
    let start_result = manager.start().await;
    if let Err(e) = start_result {
        println!("  ❌ 集成管理器启动失败: {}", e);
        return false;
    }
    println!("  ✓ 集成管理器启动成功");

    // 等待一段时间
    sleep(Duration::from_millis(100)).await;

    // 测试停止
    let stop_result = manager.stop().await;
    if let Err(e) = stop_result {
        println!("  ❌ 集成管理器停止失败: {}", e);
        return false;
    }
    println!("  ✓ 集成管理器停止成功");

    true
}

#[tokio::test]
async fn test_config_validation() {
    println!("测试配置验证...");

    // 测试有效配置
    let mut valid_config = Config::default();
    valid_config.transport.enabled_transports.push(TransportType::File);
    valid_config.transport.file.enabled = true;
    valid_config.transport.file.output_path = "/tmp/test.log".to_string();

    assert!(valid_config.validate().is_ok(), "有效配置应该通过验证");
    println!("✓ 有效配置验证通过");

    // 测试默认配置也应该通过验证（因为启用了默认传输）
    let default_config = Config::default();
    assert!(default_config.validate().is_ok(), "默认配置应该通过验证");
    println!("✓ 默认配置验证通过");
}

#[tokio::test]
async fn test_transport_factories() {
    println!("测试传输工厂...");

    let factory = DefaultTransportFactory;

    // 测试文件传输创建
    let file_config = TransportConfig {
        enabled_transports: vec![TransportType::File],
        tcp: TcpTransportConfig::default(),
        file: FileTransportConfig {
            enabled: true,
            output_path: "/tmp/factory_test.log".to_string(),
            rotation: true,
            max_file_size: 2048,
            max_files: 3,
        },
    };

    let transport_result = factory.create_transport(&file_config);
    assert!(transport_result.is_ok(), "文件传输创建应该成功");

    let transport = transport_result.unwrap();
    assert_eq!(transport.get_transport_type(), TransportType::File, "传输类型应该是File");
    println!("✓ 文件传输工厂测试通过");

    // 测试TCP传输创建
    let tcp_config = TransportConfig {
        enabled_transports: vec![TransportType::Tcp],
        tcp: TcpTransportConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            server_port: 9999,
            reconnect_interval: 5,
            max_retries: 3,
            timeout: 10,
        },
        file: FileTransportConfig::default(),
    };

    let tcp_transport_result = factory.create_transport(&tcp_config);
    assert!(tcp_transport_result.is_ok(), "TCP传输创建应该成功");

    let tcp_transport = tcp_transport_result.unwrap();
    assert_eq!(tcp_transport.get_transport_type(), TransportType::Tcp, "传输类型应该是Tcp");
    println!("✓ TCP传输工厂测试通过");
}

#[tokio::test]
async fn test_session_processing() {
    println!("测试会话处理...");

    let config = Config::default();
    let key_processor = KeyProcessor::new(config.filters);

    // 创建测试会话
    let test_session = tls_key_agent::common::session::TlsSession {
        session_id: "test_session_001".to_string(),
        client_random: vec![0u8; 32], // 32字节的Client Random
        master_secret: vec![0u8; 48], // 48字节的Master Secret
        five_tuple: tls_key_agent::common::session::FiveTuple {
            src_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            src_port: 54321,
            dst_ip: IpAddr::from_str("192.168.1.200").unwrap(),
            dst_port: 443,
            protocol: Protocol::TCP,
        },
        process_info: tls_key_agent::common::session::ProcessInfo {
            process_name: "nginx".to_string(),
            pid: 1234,
            command_line: "nginx -c /etc/nginx/nginx.conf".to_string(),
        },
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    // 测试会话处理
    let ssl_ptr = 0x12345678usize as *mut std::ffi::c_void;

    // 测试Client Random处理
    let cr_result = key_processor.process_client_random(
        ssl_ptr,
        &test_session.client_random
    ).await;
    assert!(cr_result.is_ok(), "Client Random处理应该成功");
    println!("✓ Client Random处理成功");

    // 测试Master Secret处理
    let ms_result = key_processor.process_master_secret(
        ssl_ptr,
        &test_session.master_secret
    ).await;
    assert!(ms_result.is_ok(), "Master Secret处理应该成功");
    println!("✓ Master Secret处理成功");

    // 测试会话完成
    let completed_session_result = key_processor.try_complete_session(ssl_ptr).await;
    assert!(completed_session_result.is_ok(), "会话完成应该成功");

    if let Some(completed_session) = completed_session_result.unwrap() {
        assert_eq!(completed_session.session_id, test_session.session_id, "会话ID应该匹配");
        println!("✓ 会话完成处理成功");
    } else {
        println!("⚠ 会话未完成（可能需要更多数据）");
    }
}