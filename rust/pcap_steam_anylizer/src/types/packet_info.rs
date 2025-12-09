//! 数据包信息结构
//!
//! 用于流重组的简化数据包信息

use std::net::IpAddr;

/// 数据包信息
///
/// 用于流重组的简化数据包信息，包含必要的字段
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
    /// 负载数据
    pub payload: Vec<u8>,
    /// TCP序列号
    pub tcp_seq: Option<u32>,
    /// TCP确认号
    pub tcp_ack: Option<u32>,
    /// TCP标志位（数值）
    pub tcp_flags: Option<u8>,
    /// TCP窗口大小
    pub tcp_window: Option<u16>,
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
            payload: packet.payload().unwrap_or(&[]).to_vec(),
            tcp_seq: packet.tcp_seq,
            tcp_ack: packet.tcp_ack,
            tcp_flags: packet.tcp_flags.map(|f| f.to_byte()),
            tcp_window: packet.tcp_window,
        }
    }
}