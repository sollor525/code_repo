//! 性能对比图表生成
//! 
//! 生成ASCII图表展示优化前后的性能对比

use std::time::Instant;
use tls_ja4::fingerprint::{
    calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data,
    calculate_ja4_optimized, calculate_ja3_optimized,
};
use tls_ja4::performance::{UltraFastJa4Calculator, UltraFastJa3Calculator};
use tls_parser::TlsVersion;

fn generate_test_data() -> (TlsVersion, Vec<u16>, Vec<u16>, Vec<u16>, Vec<u8>) {
    let version = TlsVersion::Tls13;
    let ciphers = (0x1301..=0x130f).collect::<Vec<u16>>();
    let extensions = (0x0000..=0x0010).collect::<Vec<u16>>();
    let elliptic_curves = vec![29, 23, 30, 25, 24];
    let payload = b"performance test payload for TLS fingerprint calculation with optimization";
    
    (version, ciphers, extensions, elliptic_curves, payload.to_vec())
}

fn create_bar_chart(data: &[(String, f64)], title: &str, unit: &str) {
    let max_value = data.iter().map(|(_, v)| *v).fold(0.0, f64::max);
    let scale = 50.0 / max_value;
    
    println!("\n{}", title);
    println!("{}", "=".repeat(title.len()));
    
    for (label, value) in data {
        let bar_length = (value * scale) as usize;
        let bar = "█".repeat(bar_length);
        println!("{:<20} │{:<50} {:.2}{}", label, bar, value, unit);
    }
}

fn create_speedup_chart(data: &[(String, f64)], title: &str) {
    let max_value = data.iter().map(|(_, v)| *v).fold(0.0, f64::max);
    let scale = 50.0 / max_value;
    
    println!("\n{}", title);
    println!("{}", "=".repeat(title.len()));
    
    for (label, value) in data {
        let bar_length = (value * scale) as usize;
        let bar = "█".repeat(bar_length);
        let speedup_text = if *value >= 1.0 {
            format!("{:.2}x 提升", *value)
        } else {
            format!("{:.2}x 下降", *value)
        };
        println!("{:<20} │{:<50} {}", label, bar, speedup_text);
    }
}

fn benchmark_performance() -> (Vec<(String, f64)>, Vec<(String, f64)>, Vec<(String, f64)>) {
    let (version, ciphers, extensions, elliptic_curves, payload) = generate_test_data();
    let ec_point_formats = vec![0, 1, 2];
    let iterations = 5000;
    
    // JA4 性能测试
    let start = Instant::now();
    for _ in 0..iterations {
        let _ja4 = calculate_ja4_from_parsed_data(version, &ciphers, &extensions, &[], &payload);
    }
    let ja4_original_time = start.elapsed().as_micros() as f64 / iterations as f64;
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ja4 = calculate_ja4_optimized(version, &ciphers, &extensions, &[], &payload);
    }
    let ja4_optimized_time = start.elapsed().as_micros() as f64 / iterations as f64;
    
    let start = Instant::now();
    let mut ja4_calc = UltraFastJa4Calculator::new();
    for _ in 0..iterations {
        let _ja4 = ja4_calc.calculate_ja4_ultra_fast(version, &ciphers, &extensions, &[], &payload);
    }
    let ja4_ultra_fast_time = start.elapsed().as_micros() as f64 / iterations as f64;
    
    // JA3 性能测试
    let start = Instant::now();
    for _ in 0..iterations {
        let _ja3 = calculate_ja3_from_parsed_data(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats);
    }
    let ja3_original_time = start.elapsed().as_micros() as f64 / iterations as f64;
    
    let start = Instant::now();
    for _ in 0..iterations {
        let _ja3 = calculate_ja3_optimized(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats);
    }
    let ja3_optimized_time = start.elapsed().as_micros() as f64 / iterations as f64;
    
    let start = Instant::now();
    let mut ja3_calc = UltraFastJa3Calculator::new();
    for _ in 0..iterations {
        let _ja3 = ja3_calc.calculate_ja3_ultra_fast(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats);
    }
    let ja3_ultra_fast_time = start.elapsed().as_micros() as f64 / iterations as f64;
    
    // 准备图表数据
    let ja4_times = vec![
        ("原始实现".to_string(), ja4_original_time),
        ("优化实现".to_string(), ja4_optimized_time),
        ("超快速实现".to_string(), ja4_ultra_fast_time),
    ];
    
    let ja3_times = vec![
        ("原始实现".to_string(), ja3_original_time),
        ("优化实现".to_string(), ja3_optimized_time),
        ("超快速实现".to_string(), ja3_ultra_fast_time),
    ];
    
    let speedups = vec![
        ("JA4 优化实现".to_string(), ja4_original_time / ja4_optimized_time),
        ("JA4 超快速实现".to_string(), ja4_original_time / ja4_ultra_fast_time),
        ("JA3 优化实现".to_string(), ja3_original_time / ja3_optimized_time),
        ("JA3 超快速实现".to_string(), ja3_original_time / ja3_ultra_fast_time),
    ];
    
    (ja4_times, ja3_times, speedups)
}

fn benchmark_throughput() -> Vec<(String, f64)> {
    let (version, ciphers, extensions, elliptic_curves, payload) = generate_test_data();
    let ec_point_formats = vec![0, 1, 2];
    let sizes = [100, 1000, 5000, 10000];
    let mut throughput_data = Vec::new();
    
    for &size in &sizes {
        let start = Instant::now();
        for _ in 0..size {
            let _ja4 = calculate_ja4_optimized(version, &ciphers, &extensions, &[], &payload);
            let _ja3 = calculate_ja3_optimized(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats);
        }
        let time = start.elapsed();
        let throughput = size as f64 / time.as_secs_f64();
        throughput_data.push((format!("{} 个指纹", size), throughput));
    }
    
    throughput_data
}

fn main() {
    println!("🚀 TLS JA4/JA3 指纹计算性能对比图表");
    println!("=====================================");
    
    // 预热
    println!("正在预热...");
    for _ in 0..100 {
        let (version, ciphers, extensions, elliptic_curves, payload) = generate_test_data();
        let ec_point_formats = vec![0, 1, 2];
        let _ja4 = calculate_ja4_optimized(version, &ciphers, &extensions, &[], &payload);
        let _ja3 = calculate_ja3_optimized(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats);
    }
    println!("预热完成！\n");
    
    // 运行性能测试
    let (ja4_times, ja3_times, speedups) = benchmark_performance();
    let throughput_data = benchmark_throughput();
    
    // 生成图表
    create_bar_chart(&ja4_times, "JA4 指纹计算时间对比", "μs");
    create_bar_chart(&ja3_times, "JA3 指纹计算时间对比", "μs");
    create_speedup_chart(&speedups, "性能提升对比");
    create_bar_chart(&throughput_data, "吞吐量扩展测试", "指纹/秒");
    
    // 性能总结
    println!("\n📊 性能优化总结");
    println!("================");
    
    let ja4_original = ja4_times[0].1;
    let ja4_optimized = ja4_times[1].1;
    let ja4_ultra_fast = ja4_times[2].1;
    
    let ja3_original = ja3_times[0].1;
    let ja3_optimized = ja3_times[1].1;
    let ja3_ultra_fast = ja3_times[2].1;
    
    println!("JA4 指纹计算:");
    println!("  原始实现: {:.2}μs", ja4_original);
    println!("  优化实现: {:.2}μs (提升 {:.1}%)", ja4_optimized, (ja4_original - ja4_optimized) / ja4_original * 100.0);
    println!("  超快速实现: {:.2}μs (提升 {:.1}%)", ja4_ultra_fast, (ja4_original - ja4_ultra_fast) / ja4_original * 100.0);
    
    println!("\nJA3 指纹计算:");
    println!("  原始实现: {:.2}μs", ja3_original);
    println!("  优化实现: {:.2}μs (提升 {:.1}%)", ja3_optimized, (ja3_original - ja3_optimized) / ja3_original * 100.0);
    println!("  超快速实现: {:.2}μs (提升 {:.1}%)", ja3_ultra_fast, (ja3_original - ja3_ultra_fast) / ja3_original * 100.0);
    
    println!("\n🎯 最佳性能:");
    println!("  JA4 最佳: {:.2}μs (超快速实现)", ja4_ultra_fast);
    println!("  JA3 最佳: {:.2}μs (优化实现)", ja3_optimized);
    
    let max_throughput = throughput_data.iter().map(|(_, v)| *v).fold(0.0, f64::max);
    println!("  最大吞吐量: {:.0} 指纹/秒", max_throughput);
    
    println!("\n✅ 性能测试完成！");
}
