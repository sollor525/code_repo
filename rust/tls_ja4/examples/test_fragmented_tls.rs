use tls_ja4::{process_pcap_file, load_config};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <pcap_file>", args[0]);
        std::process::exit(1);
    }
    
    let pcap_file = &args[1];
    let config = load_config("config.json")?;
    
    println!("Processing pcap file: {}", pcap_file);
    println!("Supporting fragmented TLS Hello packets...");
    
    let (sessions, total_packets, tls_packets) = process_pcap_file(pcap_file, &config)?;
    
    println!("\n=== Results ===");
    println!("Total packets processed: {}", total_packets);
    println!("TLS packets found: {}", tls_packets);
    println!("TLS sessions found: {}", sessions.len());
    
    for (session_key, session) in &sessions {
        println!("\nSession: {}", session_key);
        println!("  Client Hellos: {}", session.client_hellos.len());
        println!("  Server Hellos: {}", session.server_hellos.len());
        
        for (i, client_hello) in session.client_hellos.iter().enumerate() {
            println!("  Client Hello #{}: {} bytes", i + 1, client_hello.len());
            
            // 尝试解析Client Hello
            if let Some((version, ciphers, extensions, elliptic_curves, ec_point_formats, signature_algorithms)) =
                tls_ja4::parse_client_hello_with_tls_parser(client_hello) {
                
                println!("    Version: {:?}", version);
                println!("    Cipher suites: {} ({} total)", ciphers.len(), ciphers.len());
                println!("    Extensions: {} ({} total)", extensions.len(), extensions.len());
                println!("    Elliptic curves: {}", elliptic_curves.len());
                println!("    EC point formats: {}", ec_point_formats.len());
                println!("    Signature algorithms: {}", signature_algorithms.len());
                
                // 计算指纹
                let ja4 = tls_ja4::calculate_ja4_from_client_hello_data(version, &ciphers, &extensions, &signature_algorithms, client_hello);
                let ja4b = tls_ja4::calculate_ja4b_from_parsed_data(&ciphers);
                let ja4c = tls_ja4::calculate_ja4c_from_parsed_data(&extensions, &signature_algorithms);
                
                println!("    JA4: {}", ja4);
                println!("    JA4_b: {}", ja4b);
                println!("    JA4_c: {}", ja4c);
            } else {
                println!("    Failed to parse Client Hello");
            }
        }
        
        for ja3 in &session.ja3_fingerprints {
            println!("  JA3: {}", ja3);
        }
    }
    
    Ok(())
}
