use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::Command;
use std::path::Path;

fn main() {
    println!("🔍 TLS JA4/JA3 指纹计算测试 - 直接调用可执行文件");
    println!("==================================================");
    
    let pcapng_file = "/root/workspace/code_repo/rust/tls_ja4/tls3.pcapng";
    let result_file = "/root/workspace/code_repo/rust/tls_ja4/result.txt";
    let executable = "./target/release/tls_ja4";
    
    // 检查文件是否存在
    if !Path::new(pcapng_file).exists() {
        eprintln!("❌ PCAPNG文件不存在: {}", pcapng_file);
        return;
    }
    
    if !Path::new(result_file).exists() {
        eprintln!("❌ 结果文件不存在: {}", result_file);
        return;
    }
    
    if !Path::new(executable).exists() {
        eprintln!("❌ 可执行文件不存在: {}", executable);
        eprintln!("请先运行: cargo build --release");
        return;
    }
    
    println!("📁 处理文件: {}", pcapng_file);
    println!("📁 对比文件: {}", result_file);
    println!("🚀 可执行文件: {}", executable);
    
    // 运行tls_ja4程序
    println!("🔄 正在运行TLS JA4分析...");
    let output = match Command::new(executable)
        .arg("--input")
        .arg(pcapng_file)
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            eprintln!("❌ 运行失败: {}", e);
            return;
        }
    };
    
    if !output.status.success() {
        eprintln!("❌ 程序执行失败:");
        eprintln!("   退出码: {:?}", output.status.code());
        eprintln!("   错误输出: {}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("✅ 程序执行成功");
    println!("📊 输出长度: {} 字节", stdout.len());
    
    // 保存输出到文件
    let output_file = "test_output.txt";
    if let Err(e) = std::fs::write(output_file, stdout.as_bytes()) {
        eprintln!("❌ 保存输出失败: {}", e);
        return;
    }
    println!("📝 输出已保存到: {}", output_file);
    
    // 解析输出结果
    let results = parse_output_results(&stdout);
    println!("📊 解析到 {} 个JA4结果", results.len());
    
    // 显示前几个结果的五元组信息
    for (i, result) in results.iter().take(3).enumerate() {
        println!("   {}: JA4={}, 五元组={}:{} -> {}:{}", 
            i + 1, result.ja4, result.source_ip, result.source_port, 
            result.dest_ip, result.dest_port);
    }
    
    // 与result.txt比对
    match compare_with_expected_results(&results, result_file) {
        Ok(comparison) => {
            println!("📊 比对结果:");
            println!("   总结果数: {}", comparison.total_results);
            println!("   匹配数: {}", comparison.matches);
            println!("   不匹配数: {}", comparison.mismatches.len());
            println!("   匹配率: {:.2}%", comparison.match_rate);
            
            if !comparison.mismatches.is_empty() {
                println!("❌ 不匹配的结果:");
                for (i, mismatch) in comparison.mismatches.iter().enumerate() {
                    if i < 5 { // 只显示前5个不匹配
                        println!("   {}: 期望={}, 实际={}", 
                            i + 1, mismatch.expected, mismatch.actual);
                    }
                }
                if comparison.mismatches.len() > 5 {
                    println!("   ... 还有 {} 个不匹配结果", comparison.mismatches.len() - 5);
                }
            } else {
                println!("🎉 所有结果都匹配！");
            }
        }
        Err(e) => {
            eprintln!("❌ 比对失败: {}", e);
        }
    }
    
    println!("🏁 测试完成");
}

#[derive(Debug, Clone)]
struct FingerprintResult {
    ja4: String,
    source_ip: String,
    dest_ip: String,
    source_port: u16,
    dest_port: u16,
}

fn parse_output_results(output: &str) -> Vec<FingerprintResult> {
    let mut results = Vec::new();
    let mut current_result: Option<FingerprintResult> = None;
    
    for line in output.lines() {
        let line = line.trim();
        
        // 解析Session信息来获取五元组
        if line.starts_with("Session: ") {
            if let Some(session) = line.strip_prefix("Session: ") {
                // 解析格式: "10.108.20.68:60493 -> 20.42.73.31:443"
                if let Some((src, dst)) = session.split_once(" -> ") {
                    if let Some((src_ip, src_port)) = src.split_once(':') {
                        if let Some((dst_ip, dst_port)) = dst.split_once(':') {
                            if let Some(ref mut result) = current_result {
                                result.source_ip = src_ip.to_string();
                                result.source_port = src_port.parse().unwrap_or(0);
                                result.dest_ip = dst_ip.to_string();
                                result.dest_port = dst_port.parse().unwrap_or(0);
                            }
                        }
                    }
                }
            }
        }
        // 解析JA4指纹（仅JA4，不包括JA4L等）
        else if line.starts_with("JA4: ") && !line.contains("JA4L") && !line.contains("JA4_b") {
            if let Some(ja4) = line.strip_prefix("JA4: ") {
                if let Some(mut result) = current_result.take() {
                    result.ja4 = ja4.to_string();
                    results.push(result);
                }
                current_result = Some(FingerprintResult {
                    ja4: ja4.to_string(),
                    source_ip: String::new(),
                    dest_ip: String::new(),
                    source_port: 0,
                    dest_port: 0,
                });
            }
        }
    }
    
    // 处理最后一个结果
    if let Some(result) = current_result {
        results.push(result);
    }
    
    results
}

#[derive(Debug)]
struct ComparisonResult {
    total_results: usize,
    matches: usize,
    mismatches: Vec<Mismatch>,
    match_rate: f64,
}

#[derive(Debug)]
struct Mismatch {
    expected: String,
    actual: String,
}

fn compare_with_expected_results(
    actual_results: &[FingerprintResult],
    expected_file: &str,
) -> Result<ComparisonResult, std::io::Error> {
    let file = File::open(expected_file)?;
    let reader = BufReader::new(file);
    
    let mut expected_results = Vec::new();
    let mut current_result: Option<ExpectedResult> = None;
    
    for line in reader.lines() {
        let line = line?;
        
        // 解析期望的JA4指纹（仅JA4，不包括JA4L等）
        if line.contains("ja4: ") && !line.contains("ja4l") && !line.contains("ja4_b") {
            if let Some(ja4) = line.split("ja4: ").nth(1) {
                // 如果当前有结果，先保存它
                if let Some(mut result) = current_result.take() {
                    result.ja4 = ja4.trim().to_string();
                    expected_results.push(result);
                }
                // 创建新的结果，但保留五元组信息（如果有的话）
                current_result = Some(ExpectedResult {
                    ja4: ja4.trim().to_string(),
                    source_ip: String::new(),
                    dest_ip: String::new(),
                    source_port: 0,
                    dest_port: 0,
                });
            }
        }
        // 解析源IP
        else if line.contains("src: ") {
            if let Some(ip) = line.split("src: ").nth(1) {
                if let Some(ref mut result) = current_result {
                    result.source_ip = ip.trim().to_string();
                }
            }
        }
        // 解析目标IP
        else if line.contains("dst: ") {
            if let Some(ip) = line.split("dst: ").nth(1) {
                if let Some(ref mut result) = current_result {
                    result.dest_ip = ip.trim().to_string();
                }
            }
        }
        // 解析源端口
        else if line.contains("src_port: ") {
            if let Some(port) = line.split("src_port: ").nth(1) {
                if let Some(ref mut result) = current_result {
                    result.source_port = port.trim().parse().unwrap_or(0);
                }
            }
        }
        // 解析目标端口
        else if line.contains("dst_port: ") {
            if let Some(port) = line.split("dst_port: ").nth(1) {
                if let Some(ref mut result) = current_result {
                    result.dest_port = port.trim().parse().unwrap_or(0);
                }
            }
        }
    }
    
    // 处理最后一个结果
    if let Some(result) = current_result {
        expected_results.push(result);
    }
    
    let mut matches = 0;
    let mut mismatches = Vec::new();
    
    // 基于五元组进行匹配
    for actual in actual_results {
        let mut found_match = false;
        
        for expected in &expected_results {
            // 检查五元组是否匹配
            if actual.source_ip == expected.source_ip &&
               actual.dest_ip == expected.dest_ip &&
               actual.source_port == expected.source_port &&
               actual.dest_port == expected.dest_port {
                
                // 五元组匹配，检查JA4指纹
                if actual.ja4 == expected.ja4 {
                    matches += 1;
                    found_match = true;
                    break;
                } else {
                    mismatches.push(Mismatch {
                        expected: format!("{} (五元组: {}:{} -> {}:{})", 
                            expected.ja4, expected.source_ip, expected.source_port, 
                            expected.dest_ip, expected.dest_port),
                        actual: format!("{} (五元组: {}:{} -> {}:{})", 
                            actual.ja4, actual.source_ip, actual.source_port, 
                            actual.dest_ip, actual.dest_port),
                    });
                    found_match = true;
                    break;
                }
            }
        }
        
        if !found_match {
            mismatches.push(Mismatch {
                expected: "未找到匹配的五元组".to_string(),
                actual: format!("{} (五元组: {}:{} -> {}:{})", 
                    actual.ja4, actual.source_ip, actual.source_port, 
                    actual.dest_ip, actual.dest_port),
            });
        }
    }
    
    let total_results = actual_results.len();
    let match_rate = if total_results > 0 {
        (matches as f64 / total_results as f64) * 100.0
    } else {
        0.0
    };
    
    Ok(ComparisonResult {
        total_results,
        matches,
        mismatches,
        match_rate,
    })
}

#[derive(Debug, Clone)]
struct ExpectedResult {
    ja4: String,
    source_ip: String,
    dest_ip: String,
    source_port: u16,
    dest_port: u16,
}
