//! 数据包信息结构
//!
//! 流分析使用的精简数据包信息

use std::net::IpAddr;

/// 数据包信息
///
/// 流分析只需要包头字段与负载长度，不保留负载字节本身，
/// 以避免逐包的堆分配与拷贝。
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// 时间戳（微秒）
    pub timestamp: u64,
    /// 源IP地址
    pub src_ip: IpAddr,
    /// 目的IP地址
    pub dst_ip: IpAddr,
    /// 源端口
    pub src_port: u16,
    /// 目的端口
    pub dst_port: u16,
    /// 协议类型
    pub protocol: u8,
    /// 传输层负载长度（字节）
    pub payload_len: usize,
    /// TCP序列号
    pub tcp_seq: Option<u32>,
    /// TCP确认号
    pub tcp_ack: Option<u32>,
    /// TCP标志位（数值）
    pub tcp_flags: Option<u8>,
    /// TCP窗口大小
    pub tcp_window: Option<u16>,
    /// IPv4 TTL（用于识别NPatch注入报文的TTL签名）
    pub ip_ttl: Option<u8>,
    /// IPv4 identification（用于识别NPatch hijack报文的签名）
    pub ip_id: Option<u16>,
}

impl From<crate::types::packet::Packet> for PacketInfo {
    fn from(packet: crate::types::packet::Packet) -> Self {
        Self {
            timestamp: packet.timestamp().as_micros() as u64,
            src_ip: packet.src_ip.unwrap_or_else(|| IpAddr::V4(0.into())),
            dst_ip: packet.dst_ip.unwrap_or_else(|| IpAddr::V4(0.into())),
            src_port: packet.src_port.unwrap_or(0),
            dst_port: packet.dst_port.unwrap_or(0),
            protocol: packet.protocol(),
            payload_len: packet.payload().map_or(0, |p| p.len()),
            tcp_seq: packet.tcp_seq,
            tcp_ack: packet.tcp_ack,
            tcp_flags: packet.tcp_flags.map(|f| f.to_byte()),
            tcp_window: packet.tcp_window,
            ip_ttl: packet.ip_ttl,
            ip_id: packet.ip_id,
        }
    }
}
