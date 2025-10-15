//! TCP头解析功能

/// TCP头结构体
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub header_len: usize,
    pub payload_offset: usize,
}

/// 解析TCP头
pub fn parse_tcp_header(packet: &[u8], ip_header_len: usize) -> Result<TcpHeader, i32> {
    if packet.len() <= ip_header_len + 20 {
        return Err(-1); // TLS_JA4_INVALID_PACKET
    }
    
    let tcp_start = ip_header_len;
    let src_port = ((packet[tcp_start] as u16) << 8) | packet[tcp_start + 1] as u16;
    let dst_port = ((packet[tcp_start + 2] as u16) << 8) | packet[tcp_start + 3] as u16;
    
    let seq = ((packet[tcp_start + 4] as u32) << 24) |
              ((packet[tcp_start + 5] as u32) << 16) |
              ((packet[tcp_start + 6] as u32) << 8) |
              packet[tcp_start + 7] as u32;
    
    let ack = ((packet[tcp_start + 8] as u32) << 24) |
              ((packet[tcp_start + 9] as u32) << 16) |
              ((packet[tcp_start + 10] as u32) << 8) |
              packet[tcp_start + 11] as u32;
    
    let flags = packet[tcp_start + 13];
    let header_len = ((packet[tcp_start + 12] >> 4) & 0x0F) as usize * 4;
    
    if packet.len() < tcp_start + header_len {
        return Err(-1); // TLS_JA4_INVALID_PACKET
    }
    
    Ok(TcpHeader {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        header_len,
        payload_offset: tcp_start + header_len,
    })
}
