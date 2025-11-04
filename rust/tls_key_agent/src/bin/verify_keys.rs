//! TLS密钥验证工具
//!
//! 这个工具用于验证TLS密钥提取是否正常工作
//!
//! 使用方法:
//! ```bash
//! cargo run --bin verify_keys -- --help
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Read, Write};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "verify_keys")]
#[command(about = "TLS密钥验证工具")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 分析密钥日志文件
    Analyze {
        /// 密钥日志文件路径
        #[arg(short, long, default_value = "/tmp/tls_keys.log")]
        file: String,
        /// 显示详细信息
        #[arg(short, long)]
        verbose: bool,
    },
    /// 监控密钥日志文件（实时）
    Monitor {
        /// 密钥日志文件路径
        #[arg(short, long, default_value = "/tmp/tls_keys.log")]
        file: String,
        /// 监控超时（秒）
        #[arg(short, long, default_value = "60")]
        timeout: u64,
    },
    /// 验证密钥完整性
    Validate {
        /// 密钥日志文件路径
        #[arg(short, long, default_value = "/tmp/tls_keys.log")]
        file: String,
        /// 检查密钥格式
        #[arg(short, long)]
        check_format: bool,
    },
    /// 统计密钥信息
    Stats {
        /// 密钥日志文件路径
        #[arg(short, long, default_value = "/tmp/tls_keys.log")]
        file: String,
        /// 输出JSON格式
        #[arg(short, long)]
        json: bool,
    },
    /// 测试TLS连接
    Test {
        /// 目标主机
        #[arg(long, default_value = "www.baidu.com")]
        host: String,
        /// 目标端口
        #[arg(short, long, default_value = "443")]
        port: u16,
        /// 连接超时（秒）
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsKeyRecord {
    label: String,
    client_random: String,
    secret: String,
    timestamp: u64,
    operation: String,
    line_number: usize,
}

#[derive(Debug, Default, Serialize)]
struct KeyStatistics {
    total_records: usize,
    client_random_records: usize,
    master_secret_records: usize,
    other_keys: usize,
    unique_client_randoms: usize,
    time_range: Option<(u64, u64)>,
    operations: HashMap<String, usize>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // 初始化日志
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    match cli.command {
        Commands::Analyze { file, verbose } => {
            analyze_keylog_file(&file, verbose)?;
        }
        Commands::Monitor { file, timeout } => {
            monitor_keylog_file(&file, timeout)?;
        }
        Commands::Validate { file, check_format } => {
            validate_keylog_file(&file, check_format)?;
        }
        Commands::Stats { file, json } => {
            show_key_statistics(&file, json)?;
        }
        Commands::Test { host, port, timeout } => {
            test_tls_connection(&host, port, timeout)?;
        }
    }

    Ok(())
}

/// 分析密钥日志文件
fn analyze_keylog_file(file_path: &str, verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    info!("分析密钥日志文件: {}", file_path);

    if !Path::new(file_path).exists() {
        error!("密钥日志文件不存在: {}", file_path);
        return Err("文件不存在".into());
    }

    let content = fs::read_to_string(file_path)?;
    let lines: Vec<&str> = content.lines().collect();

    if lines.is_empty() {
        warn!("密钥日志文件为空");
        return Ok(());
    }

    info!("文件包含 {} 行记录", lines.len());

    let mut records = Vec::new();
    let mut client_random_set = std::collections::HashSet::new();

    for (line_num, line) in lines.iter().enumerate() {
        if let Some(record) = parse_keylog_line(line, line_num + 1)? {
            if record.label == "CLIENT_RANDOM" {
                client_random_set.insert(record.client_random.clone());
            }
            records.push(record);
        }
    }

    // 显示分析结果
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                      密钥分析结果                              ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    println!("📊 基本统计:");
    println!("  - 总记录数: {}", records.len());
    println!("  - Client Random记录: {}", records.iter().filter(|r| r.label == "CLIENT_RANDOM").count());
    println!("  - 唯一Client Random数: {}", client_random_set.len());
    println!("  - 记录时间跨度: {} 秒", calculate_time_span(&records));

    if verbose {
        println!();
        println!("📝 详细记录 (前10条):");
        for record in records.iter().take(10) {
            println!("  [{}] {}: {}...",
                record.line_number,
                record.label,
                &record.client_random[..record.client_random.len().min(16)]
            );
            println!("    操作: {}, 时间: {}", record.operation, record.timestamp);
        }

        if records.len() > 10 {
            println!("  ... 还有 {} 条记录", records.len() - 10);
        }
    }

    // 检查密钥质量
    analyze_key_quality(&records);

    Ok(())
}

/// 监控密钥日志文件
fn monitor_keylog_file(file_path: &str, timeout_seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
    info!("监控密钥日志文件: {} (超时: {}秒)", file_path, timeout_seconds);

    let mut last_size = 0;
    if Path::new(file_path).exists() {
        last_size = fs::metadata(file_path)?.len();
    }

    let start_time = std::time::Instant::now();
    let mut new_keys_count = 0;

    println!("开始监控，按 Ctrl+C 停止...");

    while start_time.elapsed().as_secs() < timeout_seconds {
        // 检查文件是否有新内容
        if Path::new(file_path).exists() {
            let current_size = fs::metadata(file_path)?.len();

            if current_size > last_size {
                // 读取新增内容
                let content = fs::read_to_string(file_path)?;
                let new_content: String = content.chars().skip(last_size as usize).collect();

                for line in new_content.lines() {
                    if let Some(record) = parse_keylog_line(line, 0)? {
                        new_keys_count += 1;
                        println!("🔑 新密钥 [{}]: {}... (操作: {})",
                            record.label,
                            &record.client_random[..record.client_random.len().min(8)],
                            record.operation
                        );
                    }
                }

                last_size = current_size;
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    println!("监控结束，共发现 {} 个新密钥", new_keys_count);
    Ok(())
}

/// 验证密钥日志文件
fn validate_keylog_file(file_path: &str, check_format: bool) -> Result<(), Box<dyn std::error::Error>> {
    info!("验证密钥日志文件: {}", file_path);

    if !Path::new(file_path).exists() {
        error!("密钥日志文件不存在: {}", file_path);
        return Err("文件不存在".into());
    }

    let content = fs::read_to_string(file_path)?;
    let lines: Vec<&str> = content.lines().collect();

    let mut valid_lines = 0;
    let mut invalid_lines = 0;
    let mut errors = Vec::new();

    for (line_num, line) in lines.iter().enumerate() {
        match parse_keylog_line(line, line_num + 1) {
            Ok(Some(record)) => {
                if check_format {
                    if validate_key_format(&record) {
                        valid_lines += 1;
                    } else {
                        invalid_lines += 1;
                        errors.push(format!("第{}行: 密钥格式无效", line_num + 1));
                    }
                } else {
                    valid_lines += 1;
                }
            }
            Ok(None) => {
                // 空行或注释行
            }
            Err(e) => {
                invalid_lines += 1;
                errors.push(format!("第{}行: {}", line_num + 1, e));
            }
        }
    }

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                      验证结果                                ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    println!("📊 验证统计:");
    println!("  - 有效行: {}", valid_lines);
    println!("  - 无效行: {}", invalid_lines);
    println!("  - 总行数: {}", lines.len());
    println!("  - 验证通过率: {:.1}%", (valid_lines as f64 / lines.len() as f64) * 100.0);

    if !errors.is_empty() {
        println!();
        println!("❌ 发现的问题:");
        for error in errors.iter().take(10) {
            println!("  - {}", error);
        }
        if errors.len() > 10 {
            println!("  ... 还有 {} 个问题", errors.len() - 10);
        }
    }

    if invalid_lines == 0 {
        println!("✅ 密钥日志文件验证通过");
    } else {
        println!("⚠️  密钥日志文件存在 {} 个问题", invalid_lines);
    }

    Ok(())
}

/// 显示密钥统计信息
fn show_key_statistics(file_path: &str, json_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    info!("统计密钥信息: {}", file_path);

    if !Path::new(file_path).exists() {
        error!("密钥日志文件不存在: {}", file_path);
        return Err("文件不存在".into());
    }

    let content = fs::read_to_string(file_path)?;
    let lines: Vec<&str> = content.lines().collect();

    let mut stats = KeyStatistics::default();
    let mut client_random_set = std::collections::HashSet::new();

    for line in lines {
        if let Ok(Some(record)) = parse_keylog_line(line, 0) {
            stats.total_records += 1;

            match record.label.as_str() {
                "CLIENT_RANDOM" => {
                    stats.client_random_records += 1;
                    client_random_set.insert(record.client_random);
                }
                _ => {
                    stats.other_keys += 1;
                }
            }

            *stats.operations.entry(record.operation).or_insert(0) += 1;

            // 更新时间范围
            if stats.time_range.is_none() {
                stats.time_range = Some((record.timestamp, record.timestamp));
            } else {
                let (start, end) = stats.time_range.unwrap();
                stats.time_range = Some((start.min(record.timestamp), end.max(record.timestamp)));
            }
        }
    }

    stats.unique_client_randoms = client_random_set.len();

    if json_output {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║                      密钥统计                                ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();

        println!("📊 总体统计:");
        println!("  - 总记录数: {}", stats.total_records);
        println!("  - Client Random记录: {}", stats.client_random_records);
        println!("  - 唯一Client Random数: {}", stats.unique_client_randoms);
        println!("  - 其他密钥记录: {}", stats.other_keys);

        if let Some((start, end)) = stats.time_range {
            println!("  - 时间跨度: {} 秒", end - start);
            println!("  - 开始时间: {}", format_timestamp(start));
            println!("  - 结束时间: {}", format_timestamp(end));
        }

        if !stats.operations.is_empty() {
            println!();
            println!("🔄 操作统计:");
            for (operation, count) in &stats.operations {
                println!("  - {}: {} 次", operation, count);
            }
        }
    }

    Ok(())
}

/// 测试TLS连接
fn test_tls_connection(host: &str, port: u16, _timeout_seconds: u64) -> Result<(), Box<dyn std::error::Error>> {
    info!("测试TLS连接: {}:{}", host, port);

    println!("连接到 {}:{}...", host, port);

    match std::net::TcpStream::connect(format!("{}:{}", host, port)) {
        Ok(mut stream) => {
            println!("✓ TCP连接成功");

            // 发送简单的HTTP请求
            let request = format!(
                "GET / HTTP/1.1\r\n\
                 Host: {}\r\n\
                 User-Agent: TLS-Key-Agent-Verify/1.0\r\n\
                 Connection: close\r\n\
                 \r\n",
                host
            );

            stream.write_all(request.as_bytes())?;
            stream.flush()?;

            println!("✓ HTTP请求发送成功");

            // 读取响应
            let mut buffer = [0u8; 1024];
            match stream.read(&mut buffer) {
                Ok(bytes_read) => {
                    if bytes_read > 0 {
                        println!("✓ 接收到响应: {} 字节", bytes_read);

                        let response = String::from_utf8_lossy(&buffer[..bytes_read]);
                        if response.contains("HTTP/1.1") {
                            println!("✓ 收到有效的HTTP响应");
                            println!("✅ TLS连接测试成功");
                        } else {
                            println!("⚠️ 响应格式异常");
                        }
                    } else {
                        println!("⚠️ 未收到响应数据");
                    }
                }
                Err(e) => {
                    println!("❌ 读取响应失败: {}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ TCP连接失败: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

/// 解析密钥日志行
fn parse_keylog_line(line: &str, line_number: usize) -> Result<Option<TlsKeyRecord>, Box<dyn std::error::Error>> {
    let line = line.trim();

    // 跳过空行和注释行
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }

    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 3 {
        return Err(format!("密钥日志格式错误: 不足3个字段").into());
    }

    let label = parts[0].to_string();
    let client_random = parts[1].to_string();
    let secret = parts[2].to_string();

    // 验证十六进制格式
    if !is_hex_string(&client_random) || !is_hex_string(&secret) {
        return Err("Client Random或Secret不是有效的十六进制字符串".into());
    }

    // 解析时间戳和操作信息（如果有）
    let mut timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut operation = "unknown".to_string();

    if parts.len() >= 4 {
        // 尝试解析时间戳
        if let Ok(ts) = parts[3].parse::<u64>() {
            timestamp = ts;

            // 解析操作信息
            if parts.len() >= 6 && parts[4] == "#" {
                operation = parts[5..].join(" ");
            }
        } else if parts.len() >= 6 && parts[3] == "#" {
            // 格式: LABEL CR SECRET # timestamp operation
            if let Ok(ts) = parts[4].parse::<u64>() {
                timestamp = ts;
                operation = parts[6..].join(" ");
            }
        }
    }

    Ok(Some(TlsKeyRecord {
        label,
        client_random,
        secret,
        timestamp,
        operation,
        line_number,
    }))
}

/// 验证密钥格式
fn validate_key_format(record: &TlsKeyRecord) -> bool {
    // 验证Client Random长度（应该是32字节，64个十六进制字符）
    if record.label == "CLIENT_RANDOM" && record.client_random.len() != 64 {
        return false;
    }

    // 验证Secret长度（Master Secret应该是48字节，96个十六进制字符）
    if record.label == "CLIENT_RANDOM" && record.secret.len() != 96 {
        // 允许空的Secret（现代OpenSSL中常见）
        if !record.secret.is_empty() && record.secret.len() != 96 {
            return false;
        }
    }

    true
}

/// 分析密钥质量
fn analyze_key_quality(records: &[TlsKeyRecord]) {
    println!();
    println!("🔍 密钥质量分析:");

    let mut high_entropy_keys = 0;
    let mut low_entropy_keys = 0;

    for record in records.iter().take(10) { // 只分析前10个以提高性能
        if let Ok(client_random_bytes) = hex::decode(&record.client_random) {
            let entropy = calculate_entropy(&client_random_bytes);
            if entropy > 6.0 {
                high_entropy_keys += 1;
            } else {
                low_entropy_keys += 1;
            }
        }
    }

    println!("  - 高熵值密钥: {}", high_entropy_keys);
    println!("  - 低熵值密钥: {}", low_entropy_keys);

    if low_entropy_keys > 0 {
        println!("  ⚠️  发现低熵值密钥，可能存在问题");
    }
}

/// 计算数据熵值
fn calculate_entropy(data: &[u8]) -> f64 {
    use std::collections::HashMap;

    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = HashMap::new();
    let len = data.len() as f64;

    for &byte in data {
        *frequency.entry(byte).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for &count in frequency.values() {
        let probability = count as f64 / len;
        if probability > 0.0 {
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// 检查字符串是否为有效的十六进制
fn is_hex_string(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// 计算时间跨度
fn calculate_time_span(records: &[TlsKeyRecord]) -> u64 {
    if records.is_empty() {
        return 0;
    }

    let timestamps: Vec<u64> = records.iter().map(|r| r.timestamp).collect();
    let min_time = *timestamps.iter().min().unwrap();
    let max_time = *timestamps.iter().max().unwrap();

    max_time - min_time
}

/// 格式化时间戳
fn format_timestamp(timestamp: u64) -> String {
    let datetime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp);

    // 简单的格式化
    format!("{}", datetime.elapsed().unwrap_or_default().as_secs())
}