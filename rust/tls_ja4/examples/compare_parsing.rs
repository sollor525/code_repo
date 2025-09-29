use tls_ja4::{parse_client_hello_with_tls_parser, parse_tls_extensions_correctly};
use tls_parser::parse_tls_extensions;
use std::io::Read;

fn main() {
    // 读取pcap文件并提取TLS数据
    let mut file = std::fs::File::open("/root/workspace/pcap/tls3.pcapng").unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    
    let mut offset = 0;
    
    // 查找TLS Client Hello
    while offset < buffer.len() - 100 {
        if buffer[offset] == 0x16 && buffer[offset + 1] == 0x03 {
            let length = u16::from_be_bytes([buffer[offset + 3], buffer[offset + 4]]) as usize;
            if offset + 5 + length < buffer.len() {
                let tls_data = &buffer[offset..offset + 5 + length];
                
                if tls_data.len() > 10 && tls_data[5] == 0x01 {
                    // 找到Client Hello，提取扩展数据
                    if tls_data.len() > 50 {
                        // 跳过TLS记录头(5) + Handshake头(4) + 版本(2) + 随机数(32) + 会话ID + 密码套件
                        let mut ext_offset = 5 + 4 + 2 + 32; // 43
                        
                        // 跳过会话ID
                        if ext_offset < tls_data.len() {
                            let session_id_len = tls_data[ext_offset] as usize;
                            ext_offset += 1 + session_id_len;
                        }
                        
                        // 跳过密码套件
                        if ext_offset + 2 < tls_data.len() {
                            let cipher_suites_len = u16::from_be_bytes([tls_data[ext_offset], tls_data[ext_offset + 1]]) as usize;
                            ext_offset += 2 + cipher_suites_len;
                        }
                        
                        // 跳过压缩方法
                        if ext_offset < tls_data.len() {
                            let compression_methods_len = tls_data[ext_offset] as usize;
                            ext_offset += 1 + compression_methods_len;
                        }
                        
                        // 现在应该到达扩展数据
                        if ext_offset + 2 < tls_data.len() {
                            let extensions_len = u16::from_be_bytes([tls_data[ext_offset], tls_data[ext_offset + 1]]) as usize;
                            ext_offset += 2;
                            
                            if ext_offset + extensions_len <= tls_data.len() {
                                let extensions_data = &tls_data[ext_offset..ext_offset + extensions_len];
                                
                                println!("=== 比较两种解析方法 ===");
                                println!("扩展数据长度: {}", extensions_data.len());
                                
                                // 方法1：直接使用tls-parser
                                match parse_tls_extensions(extensions_data) {
                                    Ok((remaining, extensions)) => {
                                        println!("方法1 - 直接tls-parser:");
                                        println!("  剩余数据长度: {}", remaining.len());
                                        println!("  解析出的扩展数量: {}", extensions.len());
                                        
                                        let mut extension_types = Vec::new();
                                        for ext in &extensions {
                                            let ext_type = match ext {
                                                tls_parser::TlsExtension::SNI(_) => 0,
                                                tls_parser::TlsExtension::MaxFragmentLength(_) => 1,
                                                tls_parser::TlsExtension::StatusRequest(_) => 5,
                                                tls_parser::TlsExtension::EllipticCurves(_) => 10,
                                                tls_parser::TlsExtension::EcPointFormats(_) => 11,
                                                tls_parser::TlsExtension::SignatureAlgorithms(_) => 13,
                                                tls_parser::TlsExtension::Heartbeat(_) => 15,
                                                tls_parser::TlsExtension::ALPN(_) => 16,
                                                tls_parser::TlsExtension::SignedCertificateTimestamp(_) => 18,
                                                tls_parser::TlsExtension::Padding(_) => 21,
                                                tls_parser::TlsExtension::RecordSizeLimit(_) => 28,
                                                tls_parser::TlsExtension::SessionTicket(_) => 35,
                                                tls_parser::TlsExtension::KeyShareOld(_) => 40,
                                                tls_parser::TlsExtension::PreSharedKey(_) => 41,
                                                tls_parser::TlsExtension::EarlyData(_) => 42,
                                                tls_parser::TlsExtension::SupportedVersions(_) => 43,
                                                tls_parser::TlsExtension::Cookie(_) => 44,
                                                tls_parser::TlsExtension::PskExchangeModes(_) => 45,
                                                tls_parser::TlsExtension::OidFilters(_) => 48,
                                                tls_parser::TlsExtension::PostHandshakeAuth => 49,
                                                tls_parser::TlsExtension::KeyShare(_) => 51,
                                                _ => 999,
                                            };
                                            extension_types.push(ext_type);
                                        }
                                        extension_types.sort();
                                        println!("  扩展类型: {:?}", extension_types);
                                    }
                                    Err(e) => {
                                        println!("方法1解析失败: {:?}", e);
                                    }
                                }
                                
                                // 方法2：使用我们的parse_tls_extensions_correctly
                                let (extensions2, _, _, _) = parse_tls_extensions_correctly(extensions_data);
                                println!("方法2 - parse_tls_extensions_correctly:");
                                println!("  解析出的扩展数量: {}", extensions2.len());
                                println!("  扩展类型: {:?}", extensions2);
                                
                                // 方法3：使用parse_client_hello_with_tls_parser
                                if let Some((_, _, extensions3, _, _, _)) = parse_client_hello_with_tls_parser(tls_data) {
                                    println!("方法3 - parse_client_hello_with_tls_parser:");
                                    println!("  解析出的扩展数量: {}", extensions3.len());
                                    println!("  扩展类型: {:?}", extensions3);
                                } else {
                                    println!("方法3解析失败");
                                }
                                
                                return; // 只处理第一个
                            }
                        }
                    }
                }
            }
        }
        offset += 1;
    }
    
    println!("未找到Client Hello");
}
