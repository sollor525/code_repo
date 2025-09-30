use std::env;

fn main() {
    println!("🔍 测试QUIC协议支持");
    println!("==================");
    
    // 测试QUIC包检测
    let quic_v1_packet = [0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04]; // QUIC版本1
    let quic_v2_packet = [0x6b, 0x33, 0x43, 0xcf, 0x01, 0x02, 0x03, 0x04]; // QUIC版本2
    let tls_packet = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01]; // TLS Client Hello
    let random_packet = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    
    println!("测试QUIC版本1包检测: {}", tls_ja4::is_quic_packet(&quic_v1_packet));
    println!("测试QUIC版本2包检测: {}", tls_ja4::is_quic_packet(&quic_v2_packet));
    println!("测试TLS包检测: {}", tls_ja4::is_quic_packet(&tls_packet));
    println!("测试随机包检测: {}", tls_ja4::is_quic_packet(&random_packet));
    
    // 测试QUIC JA4计算
    if let Some(ja4) = tls_ja4::calculate_quic_ja4(&quic_v1_packet) {
        println!("QUIC版本1 JA4: {}", ja4);
    }
    
    if let Some(ja4) = tls_ja4::calculate_quic_ja4(&quic_v2_packet) {
        println!("QUIC版本2 JA4: {}", ja4);
    }
    
    println!("\n✅ QUIC支持测试完成");
}
