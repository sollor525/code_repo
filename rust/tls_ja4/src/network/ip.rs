//! IP头解析功能

/// IP头结构体
#[derive(Debug, Clone)]
pub struct IpHeader {
    pub version: u8,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub protocol: u8,
    pub header_len: usize,
}

/// 解析IP头
pub fn parse_ip_header(packet: &[u8]) -> Result<IpHeader, i32> {
    if packet.len() < 20 {
        return Err(-1); // TLS_JA4_INVALID_PACKET
    }
    
    let version = (packet[0] >> 4) & 0x0F;
    
    match version {
        4 => {
            // IPv4
            let ihl = (packet[0] & 0x0F) as usize * 4;
            if packet.len() < ihl {
                return Err(-1); // TLS_JA4_INVALID_PACKET
            }
            
            let protocol = packet[9];
            let mut src_ip = [0u8; 16];
            let mut dst_ip = [0u8; 16];
            
            // IPv4地址存储在最后4字节
            src_ip[12..16].copy_from_slice(&packet[12..16]);
            dst_ip[12..16].copy_from_slice(&packet[16..20]);
            
            Ok(IpHeader {
                version: 4,
                src_ip,
                dst_ip,
                protocol,
                header_len: ihl,
            })
        },
        6 => {
            // IPv6 - 暂不支持
            Err(-11) // TLS_JA4_IPV6_NOT_SUPPORTED
        },
        _ => Err(-1) // TLS_JA4_INVALID_PACKET
    }
}

/// 格式化IP地址为字符串
pub fn format_ip(ip: &[u8]) -> String {
    if ip[0..12] == [0u8; 12] {
        // IPv4
        format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15])
    } else {
        // IPv6
        format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
            ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
    }
}
