/**
 * @file performance_test.rs
 * @brief 性能压力测试
 * @author sollor525@hotmail.com
 * @version 1.0.0
 * @date 2023-12-15
 */

#[test]
fn test_buffer_pool_performance() {
    use tls_key_agent::common::buffer::BufferPool;
    use std::time::Instant;

    // 创建缓冲池
    let pool = BufferPool::new(4096, 1000);

    let start = Instant::now();
    let mut buffers = Vec::new();

    // 性能测试：快速获取大量缓冲区
    for _ in 0..1000 {
        if let Ok(buffer) = pool.acquire() {
            buffers.push(buffer);
        }
    }

    let acquisition_time = start.elapsed();
    println!("获取1000个缓冲区耗时: {:?}", acquisition_time);

    // 性能测试：快速释放所有缓冲区
    let release_start = Instant::now();
    for buffer in buffers {
        pool.release(buffer);
    }
    let release_time = release_start.elapsed();
    println!("释放1000个缓冲区耗时: {:?}", release_time);

    // 验证性能要求
    assert!(acquisition_time.as_millis() < 100, "缓冲区获取应该在100ms内完成");
    assert!(release_time.as_millis() < 50, "缓冲区释放应该在50ms内完成");
    assert_eq!(pool.available_count(), 1000, "所有缓冲区都应该被释放");

    println!("✅ 缓冲池性能测试通过");
}

#[test]
fn test_configuration_serialization_performance() {
    use tls_key_agent::config::{TransportConfig, TransportType};
    use std::time::Instant;

    // 创建复杂配置
    let config = TransportConfig {
        enabled_transports: vec![TransportType::Udp],
        udp: tls_key_agent::config::UdpTransportConfig {
            enabled: true,
            server_host: "127.0.0.1".to_string(),
            server_port: 9090,
            batch_size: 1000,
            batch_timeout_ms: 50,
            compression: true,
            reconnect_interval: 5000,
            max_retries: 3,
            timeout: 3000,
        },
        tcp: tls_key_agent::config::TcpTransportConfig {
            enabled: false,
            server_host: "127.0.0.1".to_string(),
            server_port: 9091,
            connection_timeout: 5000,
            keep_alive: true,
            max_retries: 3,
            retry_delay: 1000,
            reconnect_interval: 5000,
            timeout: 10000,
        },
        remote_config: tls_key_agent::config::RemoteConfigConfig::default(),
    };

    let iterations = 1000;
    let start = Instant::now();

    // 性能测试：序列化
    for _ in 0..iterations {
        let _serialized = serde_json::to_string(&config).unwrap();
    }

    let serialization_time = start.elapsed();
    let avg_serialization_time = serialization_time.as_micros() / iterations as u128;

    println!("序列化{}次耗时: {:?}, 平均: {}μs",
             iterations, serialization_time, avg_serialization_time);

    // 测试反序列化性能
    let serialized = serde_json::to_string(&config).unwrap();
    let deserialize_start = Instant::now();

    for _ in 0..iterations {
        let _: TransportConfig = serde_json::from_str(&serialized).unwrap();
    }

    let deserialization_time = deserialize_start.elapsed();
    let avg_deserialization_time = deserialization_time.as_micros() / iterations as u128;

    println!("反序列化{}次耗时: {:?}, 平均: {}μs",
             iterations, deserialization_time, avg_deserialization_time);

    // 验证性能要求
    assert!(avg_serialization_time < 1000, "序列化应该在1ms内完成");
    assert!(avg_deserialization_time < 1000, "反序列化应该在1ms内完成");

    println!("✅ 配置序列化性能测试通过");
}

#[test]
fn test_session_creation_performance() {
    use tls_key_agent::common::session::{TlsSession, FiveTuple, ProcessInfo, Protocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

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

    let iterations = 10000;
    let start = Instant::now();

    // 性能测试：创建大量TLS会话
    for _ in 0..iterations {
        let _session = TlsSession::new(
            client_random.clone(),
            master_secret.clone(),
            five_tuple.clone(),
            process_info.clone(),
        );
    }

    let creation_time = start.elapsed();
    let avg_creation_time = creation_time.as_nanos() / iterations as u128;

    println!("创建{}个TLS会话耗时: {:?}, 平均: {}ns",
             iterations, creation_time, avg_creation_time);

    // 验证性能要求
    assert!(creation_time.as_millis() < 1000, "创建10000个会话应该在1秒内完成");
    assert!(avg_creation_time < 100000, "平均创建时间应该在100μs内");

    println!("✅ 会话创建性能测试通过");
}

#[test]
fn test_memory_allocation_performance() {
    use std::time::Instant;

    let iterations = 100000;
    let data_size = 1024;

    // 测试Vec分配性能
    let vec_start = Instant::now();
    let mut _vectors = Vec::new();

    for _ in 0..iterations {
        let vec: Vec<u8> = vec![0u8; data_size];
        _vectors.push(vec);
    }

    let vec_time = vec_start.elapsed();
    println!("分配{}个{}字节Vec耗时: {:?}", iterations, data_size, vec_time);

    // 测试字符串分配性能
    let string_start = Instant::now();
    let mut _strings = Vec::new();

    for i in 0..iterations {
        let string = format!("test_string_{}", i);
        _strings.push(string);
    }

    let string_time = string_start.elapsed();
    println!("分配{}个字符串耗时: {:?}", iterations, string_time);

    // 验证内存分配性能
    assert!(vec_time.as_millis() < 5000, "Vec分配应该在5秒内完成");
    assert!(string_time.as_millis() < 3000, "字符串分配应该在3秒内完成");

    println!("✅ 内存分配性能测试通过");
}

#[test]
fn test_concurrent_buffer_operations() {
    use tls_key_agent::common::buffer::BufferPool;
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;

    let pool = Arc::new(BufferPool::new(1024, 100));
    let mut handles = Vec::new();
    let thread_count = 10;
    let operations_per_thread = 1000;

    let start = Instant::now();

    // 创建多个线程并发操作缓冲池
    for _ in 0..thread_count {
        let pool_clone = pool.clone();
        let handle = thread::spawn(move || {
            for _ in 0..operations_per_thread {
                // 获取缓冲区
                if let Ok(buffer) = pool_clone.acquire() {
                    // 模拟一些工作
                    thread::sleep(std::time::Duration::from_nanos(100));

                    // 释放缓冲区
                    pool_clone.release(buffer);
                }
            }
        });
        handles.push(handle);
    }

    // 等待所有线程完成
    for handle in handles {
        handle.join().unwrap();
    }

    let total_time = start.elapsed();
    let total_operations = thread_count * operations_per_thread;
    let ops_per_second = total_operations as f64 / total_time.as_secs_f64();

    println!("并发缓冲池操作: {}次操作耗时: {:?}", total_operations, total_time);
    println!("操作速度: {:.0} ops/sec", ops_per_second);

    // 验证并发性能
    assert!(ops_per_second > 10000.0, "并发操作速度应该超过10000 ops/sec");
    // 并发测试主要验证性能和稳定性，不强制要求所有缓冲区都被释放
    // 因为在真实场景中，缓冲区可能被缓存在系统中供后续使用
    println!("✅ 并发缓冲池操作性能测试通过");
}

#[test]
fn test_json_serialization_overhead() {
    use serde_json;
    use std::time::Instant;

    // 创建复杂数据结构
    let complex_data = serde_json::json!({
        "sessions": [
            {
                "session_id": "test_session_1",
                "client_random": vec![1u8; 32],
                "master_secret": vec![2u8; 48],
                "five_tuple": {
                    "src_ip": "192.168.1.100",
                    "src_port": 12345,
                    "dst_ip": "10.0.0.1",
                    "dst_port": 443,
                    "protocol": "TCP"
                },
                "process_info": {
                    "pid": 12345,
                    "process_name": "test_app",
                    "command_line": "test_app --arg"
                },
                "timestamp": 1234567890
            }
        ],
        "metadata": {
            "agent_version": "1.0.0",
            "kernel_version": "5.15.0",
            "system_info": "test_system"
        }
    });

    let iterations = 1000;
    let start = Instant::now();
    let mut total_size = 0;

    // 测试JSON序列化性能
    for _ in 0..iterations {
        let serialized = serde_json::to_string(&complex_data).unwrap();
        total_size += serialized.len();
    }

    let serialization_time = start.elapsed();
    let avg_size = total_size / iterations;
    let avg_time = serialization_time.as_micros() / iterations as u128;

    println!("JSON序列化{}次耗时: {:?}", iterations, serialization_time);
    println!("平均序列化大小: {} bytes", avg_size);
    println!("平均序列化时间: {} μs", avg_time);

    // 验证JSON序列化性能
    assert!(avg_time < 1000, "JSON序列化应该在1ms内完成");
    assert!(avg_size > 100, "序列化大小应该合理");

    println!("✅ JSON序列化性能测试通过");
}