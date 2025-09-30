//! 性能对比测试
//! 
//! 比较优化前后的TLS JA4/JA3指纹计算性能

use std::time::Instant;
use tls_ja4::fingerprint::{
    calculate_ja4_from_parsed_data, calculate_ja3_from_parsed_data,
    calculate_ja4_optimized, calculate_ja3_optimized,
};
use tls_ja4::performance::{
    UltraFastJa4Calculator, UltraFastJa3Calculator,
    HighPerformanceMemoryPool, ParallelTlsProcessor,
    TlsProcessingTask,
};
use tls_parser::TlsVersion;

fn generate_test_data() -> (TlsVersion, Vec<u16>, Vec<u16>, Vec<u16>, Vec<u8>) {
    let version = TlsVersion::Tls13;
    let ciphers = (0x1301..=0x130f).collect::<Vec<u16>>();
    let extensions = (0x0000..=0x0010).collect::<Vec<u16>>();
    let elliptic_curves = vec![29, 23, 30, 25, 24];
    let payload = b"performance test payload for TLS fingerprint calculation with optimization";
    
    (version, ciphers, extensions, elliptic_curves, payload.to_vec())
}

fn benchmark_ja4_comparison() {
    println!("=== JA4 指纹计算性能对比 ===");
    
    let (version, ciphers, extensions, _, payload) = generate_test_data();
    let iterations = 10000;
    
    // 原始实现
    let start = Instant::now();
    for _ in 0..iterations {
        let _ja4 = calculate_ja4_from_parsed_data(
            version,
            &ciphers,
            &extensions,
            &[],
            &payload,
        );
    }
    let original_time = start.elapsed();
    
    // 优化实现
    let start = Instant::now();
    for _ in 0..iterations {
        let _ja4 = calculate_ja4_optimized(
            version,
            &ciphers,
            &extensions,
            &[],
            &payload,
        );
    }
    let optimized_time = start.elapsed();
    
    // 超快速实现
    let start = Instant::now();
    let mut calculator = UltraFastJa4Calculator::new();
    for _ in 0..iterations {
        let _ja4 = calculator.calculate_ja4_ultra_fast(
            version,
            &ciphers,
            &extensions,
            &[],
            &payload,
        );
    }
    let ultra_fast_time = start.elapsed();
    
    println!("原始实现: {:.2}ms ({:.2}μs/次)", 
             original_time.as_millis(), 
             original_time.as_micros() as f64 / iterations as f64);
    println!("优化实现: {:.2}ms ({:.2}μs/次)", 
             optimized_time.as_millis(), 
             optimized_time.as_micros() as f64 / iterations as f64);
    println!("超快速实现: {:.2}ms ({:.2}μs/次)", 
             ultra_fast_time.as_millis(), 
             ultra_fast_time.as_micros() as f64 / iterations as f64);
    
    let speedup_optimized = original_time.as_micros() as f64 / optimized_time.as_micros() as f64;
    let speedup_ultra_fast = original_time.as_micros() as f64 / ultra_fast_time.as_micros() as f64;
    
    println!("优化实现加速比: {:.2}x", speedup_optimized);
    println!("超快速实现加速比: {:.2}x", speedup_ultra_fast);
    println!();
}

fn benchmark_ja3_comparison() {
    println!("=== JA3 指纹计算性能对比 ===");
    
    let (version, ciphers, extensions, elliptic_curves, _) = generate_test_data();
    let ec_point_formats = vec![0, 1, 2];
    let iterations = 10000;
    
    // 原始实现
    let start = Instant::now();
    for _ in 0..iterations {
        let _ja3 = calculate_ja3_from_parsed_data(
            version,
            &ciphers,
            &extensions,
            &elliptic_curves,
            &ec_point_formats,
        );
    }
    let original_time = start.elapsed();
    
    // 优化实现
    let start = Instant::now();
    for _ in 0..iterations {
        let _ja3 = calculate_ja3_optimized(
            version,
            &ciphers,
            &extensions,
            &elliptic_curves,
            &ec_point_formats,
        );
    }
    let optimized_time = start.elapsed();
    
    // 超快速实现
    let start = Instant::now();
    let mut calculator = UltraFastJa3Calculator::new();
    for _ in 0..iterations {
        let _ja3 = calculator.calculate_ja3_ultra_fast(
            version,
            &ciphers,
            &extensions,
            &elliptic_curves,
            &ec_point_formats,
        );
    }
    let ultra_fast_time = start.elapsed();
    
    println!("原始实现: {:.2}ms ({:.2}μs/次)", 
             original_time.as_millis(), 
             original_time.as_micros() as f64 / iterations as f64);
    println!("优化实现: {:.2}ms ({:.2}μs/次)", 
             optimized_time.as_millis(), 
             optimized_time.as_micros() as f64 / iterations as f64);
    println!("超快速实现: {:.2}ms ({:.2}μs/次)", 
             ultra_fast_time.as_millis(), 
             ultra_fast_time.as_micros() as f64 / iterations as f64);
    
    let speedup_optimized = original_time.as_micros() as f64 / optimized_time.as_micros() as f64;
    let speedup_ultra_fast = original_time.as_micros() as f64 / ultra_fast_time.as_micros() as f64;
    
    println!("优化实现加速比: {:.2}x", speedup_optimized);
    println!("超快速实现加速比: {:.2}x", speedup_ultra_fast);
    println!();
}

fn benchmark_memory_pool_performance() {
    println!("=== 内存池性能测试 ===");
    
    let iterations = 100000;
    
    // 标准分配
    let start = Instant::now();
    for _ in 0..iterations {
        let _buffer: Vec<u8> = Vec::with_capacity(256);
    }
    let standard_time = start.elapsed();
    
    // 内存池分配
    let start = Instant::now();
    let pool = HighPerformanceMemoryPool::new();
    for _ in 0..iterations {
        let buffer = pool.get_small_buffer();
        pool.return_small_buffer(buffer);
    }
    let pool_time = start.elapsed();
    
    println!("标准分配: {:.2}ms ({:.2}ns/次)", 
             standard_time.as_millis(), 
             standard_time.as_nanos() as f64 / iterations as f64);
    println!("内存池分配: {:.2}ms ({:.2}ns/次)", 
             pool_time.as_millis(), 
             pool_time.as_nanos() as f64 / iterations as f64);
    
    let speedup = standard_time.as_nanos() as f64 / pool_time.as_nanos() as f64;
    println!("内存池加速比: {:.2}x", speedup);
    println!();
}

fn benchmark_parallel_processing() {
    println!("=== 并行处理性能测试 ===");
    
    let task_count = 1000;
    let tasks: Vec<TlsProcessingTask> = (0..task_count)
        .map(|i| TlsProcessingTask {
            payload: generate_test_data().4,
            task_id: i,
            timestamp: Instant::now(),
        })
        .collect();
    
    // 串行处理
    let start = Instant::now();
    for task in &tasks {
        let _result = process_single_task(task);
    }
    let serial_time = start.elapsed();
    
    // 并行处理
    let start = Instant::now();
    let processor = ParallelTlsProcessor::new();
    let _results = processor.process_parallel(tasks.clone());
    let parallel_time = start.elapsed();
    
    println!("串行处理: {:.2}ms", serial_time.as_millis());
    println!("并行处理: {:.2}ms", parallel_time.as_millis());
    
    let speedup = serial_time.as_millis() as f64 / parallel_time.as_millis() as f64;
    println!("并行处理加速比: {:.2}x", speedup);
    println!();
}

fn process_single_task(task: &TlsProcessingTask) -> String {
    // 简化的单任务处理
    let (version, ciphers, extensions, elliptic_curves, _) = generate_test_data();
    let ec_point_formats = vec![0, 1, 2];
    
    let ja4 = calculate_ja4_optimized(version, &ciphers, &extensions, &[], &task.payload);
    let ja3 = calculate_ja3_optimized(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats);
    
    format!("Task {}: JA4={}, JA3={:?}", task.task_id, ja4, ja3)
}

fn benchmark_throughput_scaling() {
    println!("=== 吞吐量扩展测试 ===");
    
    let sizes = [100, 1000, 10000, 100000];
    
    for &size in &sizes {
        let (version, ciphers, extensions, elliptic_curves, payload) = generate_test_data();
        let ec_point_formats = vec![0, 1, 2];
        
        let start = Instant::now();
        for _ in 0..size {
            let _ja4 = calculate_ja4_optimized(version, &ciphers, &extensions, &[], &payload);
            let _ja3 = calculate_ja3_optimized(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats);
        }
        let time = start.elapsed();
        
        let throughput = size as f64 / time.as_secs_f64();
        println!("处理 {} 个指纹: {:.2}ms, 吞吐量: {:.0} 指纹/秒", 
                 size, time.as_millis(), throughput);
    }
    println!();
}

fn main() {
    println!("🚀 TLS JA4/JA3 指纹计算性能对比测试");
    println!("=====================================");
    println!();
    
    // 预热
    println!("正在预热...");
    for _ in 0..1000 {
        let (version, ciphers, extensions, elliptic_curves, payload) = generate_test_data();
        let ec_point_formats = vec![0, 1, 2];
        let _ja4 = calculate_ja4_optimized(version, &ciphers, &extensions, &[], &payload);
        let _ja3 = calculate_ja3_optimized(version, &ciphers, &extensions, &elliptic_curves, &ec_point_formats);
    }
    println!("预热完成！\n");
    
    // 运行性能测试
    benchmark_ja4_comparison();
    benchmark_ja3_comparison();
    benchmark_memory_pool_performance();
    benchmark_parallel_processing();
    benchmark_throughput_scaling();
    
    println!("✅ 性能测试完成！");
}
