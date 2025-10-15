use anyhow::Result;
use clap::Parser;
use std::time::SystemTime;
use tls_ja4::{load_config, process_pcap_file, save_fingerprints_to_file};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 输入pcap文件路径
    #[arg(short, long)]
    input: String,
    
    /// 输出JSON文件路径
    #[arg(short, long, default_value = "fingerprints.json")]
    output: String,
    
    /// 配置文件路径
    #[arg(short, long, default_value = "config.json")]
    config: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    println!("TLS JA4/JA3 Fingerprint Extractor (using tls-parser)");
    println!("Input file: {}", args.input);
    println!("Config file: {}", args.config);
    
    // 加载配置
    let config = load_config(&args.config)?;
    
    // 处理pcap文件
    let start_time = SystemTime::now();
    let (sessions, total_packets, tls_packets) = process_pcap_file(&args.input, &config)?;
    let processing_time = start_time.elapsed().unwrap();
    
    // 统计信息
    let client_hellos: usize = sessions.values().map(|s| s.client_hellos.len()).sum();
    let server_hellos: usize = sessions.values().map(|s| s.server_hellos.len()).sum();
    let ja4_count: usize = sessions.values().map(|s| s.client_hellos.len()).sum();
    let ja3_count: usize = sessions.values().map(|s| s.ja3_fingerprints.len()).sum();
    
    println!("Total packets processed: {}", total_packets);
    println!("TLS packets found: {}", tls_packets);
    println!("Client Hellos found: {}", client_hellos);
    println!("Server Hellos found: {}", server_hellos);
    println!("Sessions created: {}", sessions.len());
    println!("JA4 fingerprints calculated: {}", ja4_count);
    println!("JA3 fingerprints calculated: {}", ja3_count);
    println!("Processing time: {:.2?}", processing_time);
    
    // 保存结果
    save_fingerprints_to_file(&sessions, total_packets, tls_packets, &args.output, &config)?;
    println!("Fingerprint data saved to: {}", args.output);
    
    // 显示会话详情
    println!("Found {} TLS sessions", sessions.len());
    for (session_key, session) in &sessions {
        println!("Session: {}", session_key);
        println!("  Client Hellos: {}", session.client_hellos.len());
        println!("  Server Hellos: {}", session.server_hellos.len());
        
        // 计算并显示指纹
        for (i, client_hello) in session.client_hellos.iter().enumerate() {
            if let Some((version, ciphers, extensions, _elliptic_curves, _ec_point_formats, signature_algorithms)) = 
                tls_ja4::parse_client_hello_with_tls_parser(client_hello) {
                
                println!("  Client Hello #{}: {} ciphers, {} extensions", i+1, ciphers.len(), extensions.len());
                
                let ja4 = tls_ja4::calculate_ja4_from_parsed_data(version, &ciphers, &extensions, &signature_algorithms, client_hello);
                let ja4b = tls_ja4::calculate_ja4b_from_parsed_data(&ciphers);
                let ja4c = tls_ja4::calculate_ja4c_from_parsed_data(&extensions, &signature_algorithms);
                
                println!("  JA4: {}", ja4);
                println!("  JA4_b: {}", ja4b);
                println!("  JA4_c: {}", ja4c);
            }
        }
        
        for ja3 in &session.ja3_fingerprints {
            println!("  JA3: {}", ja3);
        }
    }
    
    Ok(())
}
