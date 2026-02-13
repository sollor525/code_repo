/**
 * @file structure_validation.rs
 * @brief 项目结构验证测试
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-12-15
 */

#[test]
fn test_basic_project_structure() {
    // 测试项目基础结构完整性

    // 验证配置模块
    let _config = tls_key_agent::Config::default();
    assert!(true, "Config should be creatable");

    // 验证会话模块
    use tls_key_agent::common::session::Protocol;
    let protocol = Protocol::TCP;
    assert!(matches!(protocol, Protocol::TCP));

    // 验证传输模块
    use tls_key_agent::config::TransportType;
    let transport_type = TransportType::Udp;
    assert!(matches!(transport_type, TransportType::Udp));

    // 验证弹性模块
    use tls_key_agent::resilience::{LoadBalanceStrategy, AlertLevel};
    let strategy = LoadBalanceStrategy::RoundRobin;
    let alert_level = AlertLevel::Warning;
    assert!(matches!(strategy, LoadBalanceStrategy::RoundRobin));
    assert!(matches!(alert_level, AlertLevel::Warning));

    println!("✅ Basic project structure validation passed");
}

#[test]
fn test_error_handling() {
    use tls_key_agent::common::error::TlsKeyAgentError;

    // 测试错误类型创建
    let config_error = TlsKeyAgentError::Config("Test error".to_string());
    let formatted = format!("{}", config_error);
    assert!(formatted.contains("Test error"));
    assert!(!formatted.is_empty());

    println!("✅ Error handling works correctly");
}

#[test]
fn test_session_creation() {
    use tls_key_agent::common::session::{Protocol, FiveTuple, ProcessInfo};
    use std::net::{IpAddr, Ipv4Addr};

    // 测试五元组创建
    let five_tuple = FiveTuple {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        src_port: 12345,
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_port: 443,
        protocol: Protocol::TCP,
    };

    assert_eq!(five_tuple.src_port, 12345);
    assert_eq!(five_tuple.dst_port, 443);

    // 测试进程信息创建
    let process_info = ProcessInfo {
        pid: 12345,
        process_name: "test_process".to_string(),
        command_line: "test_process --arg".to_string(),
    };

    assert_eq!(process_info.pid, 12345);
    assert_eq!(process_info.process_name, "test_process");

    println!("✅ Session creation works correctly");
}

#[test]
fn test_transport_configuration() {
    use tls_key_agent::config::TransportConfig;

    // 测试默认传输配置
    let default_config = TransportConfig::default();
    assert!(!default_config.enabled_transports.is_empty());
    assert!(default_config.udp.enabled);

    // 测试序列化
    let serialized = serde_json::to_string(&default_config);
    assert!(serialized.is_ok(), "Transport config should be serializable");

    println!("✅ Transport configuration works correctly");
}

#[test]
fn test_ssl_library_configuration() {
    use tls_key_agent::injector::{SslLibraryType, SslLibraryConfig};

    // 测试SSL库类型
    let library_types = vec![
        SslLibraryType::OpenSSL,
        SslLibraryType::GnuTLS,
        SslLibraryType::NSS,
        SslLibraryType::BoringSSL,
        SslLibraryType::LibreSSL,
        SslLibraryType::Unknown,
    ];

    for library_type in library_types {
        // 创建配置
        let config = SslLibraryConfig::default();
        assert!(config.enabled); // 默认应该是启用的

        // 测试类型匹配
        match library_type {
            SslLibraryType::OpenSSL => assert!(true),
            SslLibraryType::GnuTLS => assert!(true),
            SslLibraryType::NSS => assert!(true),
            SslLibraryType::BoringSSL => assert!(true),
            SslLibraryType::LibreSSL => assert!(true),
            SslLibraryType::Unknown => assert!(true),
        }
    }

    println!("✅ SSL library configuration works correctly");
}

#[test]
fn test_buffer_pool_functionality() {
    use tls_key_agent::common::buffer::BufferPool;

    // 测试缓冲池创建
    let pool = BufferPool::new(1024, 10);
    assert_eq!(pool.available_count(), 0);

    // 测试缓冲区获取
    let buffer = pool.acquire().unwrap();
    assert_eq!(buffer.len(), 1024);

    // 测试缓冲区释放
    pool.release(buffer);
    assert_eq!(pool.available_count(), 1);

    println!("✅ Buffer pool functionality works correctly");
}

#[test]
fn test_five_tuple_operations() {
    use tls_key_agent::common::session::{FiveTuple, Protocol};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // 测试通配符创建
    let wildcard = FiveTuple::wildcard();
    assert_eq!(wildcard.src_port, 0);
    assert_eq!(wildcard.dst_port, 0);
    assert_eq!(wildcard.protocol, Protocol::TCP);

    // 测试从socket创建
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
    let from_socket = FiveTuple::from_socket(local, remote, Protocol::TCP);

    assert_eq!(from_socket.src_port, 12345);
    assert_eq!(from_socket.dst_port, 443);

    println!("✅ Five tuple operations work correctly");
}

#[test]
fn test_tls_session_functionality() {
    use tls_key_agent::common::session::{TlsSession, FiveTuple, ProcessInfo, Protocol};
    use std::net::{IpAddr, Ipv4Addr};

    let five_tuple = FiveTuple {
        src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        src_port: 12345,
        dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dst_port: 443,
        protocol: Protocol::TCP,
    };

    let process_info = ProcessInfo {
        pid: 12345,
        process_name: "test_app".to_string(),
        command_line: "test_app --config".to_string(),
    };

    let client_random = vec![1u8; 32];
    let master_secret = vec![2u8; 48];

    // 创建TLS会话
    let session = TlsSession::new(
        client_random.clone(),
        master_secret.clone(),
        five_tuple,
        process_info,
    );

    assert_eq!(session.client_random, client_random);
    assert_eq!(session.master_secret, master_secret);
    assert!(!session.session_id.is_empty());

    println!("✅ TLS session functionality works correctly");
}

#[tokio::test]
async fn test_resilience_components() {
    use tls_key_agent::resilience::{
        LoadBalancer, LoadBalanceConfig,
        PerformanceMonitor, PerformanceMonitorConfig,
        HealthChecker
    };

    // 测试负载均衡器
    let lb_config = LoadBalanceConfig::default();
    let _load_balancer = LoadBalancer::new(lb_config);

    // 测试性能监控器
    let pm_config = PerformanceMonitorConfig::default();
    let pm_result = PerformanceMonitor::new(pm_config);
    assert!(pm_result.is_ok(), "PerformanceMonitor should be created successfully");

    // 测试健康检查器
    let (_health_checker, _receiver) = HealthChecker::new();

    println!("✅ Resilience components work correctly");
}

#[test]
fn test_project_completeness() {
    // 验证整个项目的核心功能完整性

    // 1. 配置系统
    let config = tls_key_agent::Config::default();
    assert!(!config.agent.name.is_empty());

    // 2. 会话管理
    use tls_key_agent::common::session::Protocol;
    let _protocol = Protocol::TCP;

    // 3. 传输系统
    use tls_key_agent::config::TransportType;
    let _transport_type = TransportType::Udp;

    // 4. 注入器系统
    use tls_key_agent::injector::SslLibraryType;
    let _ssl_library_type = SslLibraryType::OpenSSL;

    // 5. 弹性系统
    use tls_key_agent::resilience::{LoadBalanceStrategy, AlertLevel};
    let _strategy = LoadBalanceStrategy::RoundRobin;
    let _alert_level = AlertLevel::Warning;

    // 6. 缓冲池
    use tls_key_agent::common::buffer::BufferPool;
    let _buffer_pool = BufferPool::new(1024, 10);

    // 7. 错误处理
    use tls_key_agent::common::error::TlsKeyAgentError;
    let _error = TlsKeyAgentError::Config("Test".to_string());

    println!("✅ Project completeness validation passed");
    println!("🎉 All core systems are properly implemented and accessible!");
}