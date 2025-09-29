//! 网络流管理功能


/// 生成流键
pub fn generate_flow_key(src_ip: &[u8; 16], dst_ip: &[u8; 16], src_port: u16, dst_port: u16) -> String {
    // 确保流键的一致性：总是使用较小的IP:端口作为键的前半部分
    let (ip1, port1, ip2, port2) = if src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port) {
        (src_ip, src_port, dst_ip, dst_port)
    } else {
        (dst_ip, dst_port, src_ip, src_port)
    };
    
    format!("{}:{}->{}:{}", 
        super::ip::format_ip(ip1), port1,
        super::ip::format_ip(ip2), port2)
}
