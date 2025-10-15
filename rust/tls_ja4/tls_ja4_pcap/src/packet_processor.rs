//! 数据包处理器
//!
//! 处理网络数据包，提取TLS/QUIC数据并支持TCP流重组

use std::collections::HashMap;
use std::net::IpAddr;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use tls_ja4_core::{is_tls_packet, is_quic_packet};

/// VLAN标签结构体
#[derive(Debug, Clone)]
pub struct VlanTag {
    pub vlan_id: u16,
    pub priority: u8,
    pub ether_type: u16,
}

/// TCP流重组缓冲区
#[derive(Debug, Clone)]
pub struct TcpStreamBuffer {
    pub data: Vec<u8>,
    pub expected_seq: u32,
    pub is_complete: bool,
    pub last_activity: u64, // 时间戳，用于清理超时的流
}

#[derive(Debug, Clone)]
pub struct BidirectionalTcpStream {
    pub client_to_server: TcpStreamBuffer,
    pub server_to_client: TcpStreamBuffer,
    pub last_activity: u64,
}

/// 处理后的数据包类型
#[derive(Debug)]
pub enum ProcessedPacket {
    Tls(Vec<u8>, (IpAddr, u16, IpAddr, u16)),
    Quic(Vec<u8>, (IpAddr, u16, IpAddr, u16)),
}

/// 解析VLAN标签
pub fn parse_vlan_tags(data: &[u8]) -> (Vec<VlanTag>, usize, u16) {
    let mut vlan_tags = Vec::new();
    let mut offset = 0;
    let mut ether_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
    offset += 2;

    // 检查是否有VLAN标签
    while ether_type == 0x8100 || ether_type == 0x88a8 || ether_type == 0x9100 {
        if offset + 4 > data.len() {
            break;
        }

        // 解析VLAN标签
        let vlan_tci = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let priority = ((vlan_tci >> 13) & 0x07) as u8;
        let vlan_id = vlan_tci & 0x0FFF;

        ether_type = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);

        vlan_tags.push(VlanTag {
            vlan_id,
            priority,
            ether_type,
        });

        offset += 4;
    }

    (vlan_tags, offset, ether_type)
}

/// 从数据包中提取TCP流信息（支持分段重组）
pub fn extract_tcp_stream_from_packet(data: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16, u32, u32, Vec<u8>)> {
    if data.len() < 14 {
        return None;
    }

    // 解析以太网头部
    let _ethernet = EthernetPacket::new(data)?;
    let _offset = 14; // 以太网头部长度

    // 处理VLAN标签
    let (_vlan_tags, vlan_offset, final_ether_type) = parse_vlan_tags(&data[12..]);
    let offset = 12 + vlan_offset;
    let ether_type = match final_ether_type {
        0x0800 => EtherTypes::Ipv4,
        0x86DD => EtherTypes::Ipv6,
        _ => return None,
    };

    // 检查是否为IPv4或IPv6
    match ether_type {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(&data[offset..])?;
            let src_ip = IpAddr::V4(ipv4.get_source());
            let dst_ip = IpAddr::V4(ipv4.get_destination());

            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                let ip_header_length = (ipv4.get_header_length() as usize) * 4;
                let tcp_offset = offset + ip_header_length;

                if let Some(tcp) = TcpPacket::new(&data[tcp_offset..]) {
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let seq = tcp.get_sequence();
                    let ack = tcp.get_acknowledgement();
                    let tcp_header_length = (tcp.get_data_offset() as usize) * 4;
                    let payload_offset = tcp_offset + tcp_header_length;

                    if payload_offset < data.len() {
                        let payload = data[payload_offset..].to_vec();
                        return Some((src_ip, dst_ip, src_port, dst_port, seq, ack, payload));
                    }
                }
            }
        }
        EtherTypes::Ipv6 => {
            let ipv6 = Ipv6Packet::new(&data[offset..])?;
            let src_ip = IpAddr::V6(ipv6.get_source());
            let dst_ip = IpAddr::V6(ipv6.get_destination());

            if ipv6.get_next_header() == IpNextHeaderProtocols::Tcp {
                let tcp_offset = offset + 40; // IPv6头部固定40字节

                if let Some(tcp) = TcpPacket::new(&data[tcp_offset..]) {
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let seq = tcp.get_sequence();
                    let ack = tcp.get_acknowledgement();
                    let tcp_header_length = (tcp.get_data_offset() as usize) * 4;
                    let payload_offset = tcp_offset + tcp_header_length;

                    if payload_offset < data.len() {
                        let payload = data[payload_offset..].to_vec();
                        return Some((src_ip, dst_ip, src_port, dst_port, seq, ack, payload));
                    }
                }
            }
        }
        _ => return None,
    }

    None
}

/// 从数据包中提取TLS数据（支持TCP和UDP/QUIC）
pub fn extract_tls_data_from_packet(data: &[u8]) -> Option<(IpAddr, IpAddr, u16, u16, Vec<u8>)> {
    if data.len() < 14 {
        return None;
    }

    // 解析以太网头部
    let _ethernet = EthernetPacket::new(data)?;
    let _offset = 14; // 以太网头部长度

    // 处理VLAN标签
    let (_vlan_tags, vlan_offset, final_ether_type) = parse_vlan_tags(&data[12..]);
    let offset = 12 + vlan_offset;
    let ether_type = match final_ether_type {
        0x0800 => EtherTypes::Ipv4,
        0x86DD => EtherTypes::Ipv6,
        _ => return None,
    };

    // 检查是否为IPv4或IPv6
    match ether_type {
        EtherTypes::Ipv4 => {
            let ipv4 = Ipv4Packet::new(&data[offset..])?;
            let src_ip = IpAddr::V4(ipv4.get_source());
            let dst_ip = IpAddr::V4(ipv4.get_destination());

            // 处理TCP协议
            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                let ip_header_length = (ipv4.get_header_length() as usize) * 4;
                let tcp_offset = offset + ip_header_length;

                if let Some(tcp) = TcpPacket::new(&data[tcp_offset..]) {
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let tcp_header_length = (tcp.get_data_offset() as usize) * 4;
                    let payload_offset = tcp_offset + tcp_header_length;

                    if payload_offset < data.len() {
                        let tls_data = data[payload_offset..].to_vec();
                        if is_tls_packet(&tls_data) {
                            return Some((src_ip, dst_ip, src_port, dst_port, tls_data));
                        }
                    }
                }
            }
            // 处理UDP/QUIC协议
            else if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                let ip_header_length = (ipv4.get_header_length() as usize) * 4;
                let udp_offset = offset + ip_header_length;

                if let Some(udp) = UdpPacket::new(&data[udp_offset..]) {
                    let src_port = udp.get_source();
                    let dst_port = udp.get_destination();
                    let udp_data = udp.payload().to_vec();

                    // 检查是否为QUIC协议
                    if is_quic_packet(&udp_data) {
                        return Some((src_ip, dst_ip, src_port, dst_port, udp_data));
                    }
                }
            }
        }
        EtherTypes::Ipv6 => {
            let ipv6 = Ipv6Packet::new(&data[offset..])?;
            let src_ip = IpAddr::V6(ipv6.get_source());
            let dst_ip = IpAddr::V6(ipv6.get_destination());

            // 处理TCP协议
            if ipv6.get_next_header() == IpNextHeaderProtocols::Tcp {
                let tcp_offset = offset + 40; // IPv6头部固定40字节

                if let Some(tcp) = TcpPacket::new(&data[tcp_offset..]) {
                    let src_port = tcp.get_source();
                    let dst_port = tcp.get_destination();
                    let tcp_header_length = (tcp.get_data_offset() as usize) * 4;
                    let payload_offset = tcp_offset + tcp_header_length;

                    if payload_offset < data.len() {
                        let tls_data = data[payload_offset..].to_vec();
                        if is_tls_packet(&tls_data) {
                            return Some((src_ip, dst_ip, src_port, dst_port, tls_data));
                        }
                    }
                }
            }
            // 处理UDP/QUIC协议
            else if ipv6.get_next_header() == IpNextHeaderProtocols::Udp {
                let udp_offset = offset + 40; // IPv6头部固定40字节

                if let Some(udp) = UdpPacket::new(&data[udp_offset..]) {
                    let src_port = udp.get_source();
                    let dst_port = udp.get_destination();
                    let udp_data = udp.payload().to_vec();

                    // 检查是否为QUIC协议
                    if is_quic_packet(&udp_data) {
                        return Some((src_ip, dst_ip, src_port, dst_port, udp_data));
                    }
                }
            }
        }
        _ => return None,
    }

    None
}

/// 生成会话键
pub fn generate_session_key(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16, _is_client_to_server: bool) -> String {
    // 使用标准的源->目标格式
    format!("{}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port)
}

/// 生成TCP流键（双向）
pub fn generate_tcp_stream_key(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> String {
    // 使用固定的顺序来确保双向流使用相同的键
    if (src_ip, src_port) < (dst_ip, dst_port) {
        format!("{}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port)
    } else {
        format!("{}:{} -> {}:{}", dst_ip, dst_port, src_ip, src_port)
    }
}

/// 重组TCP流数据（双向）
pub fn reassemble_tcp_stream(
    stream_buffers: &mut HashMap<String, BidirectionalTcpStream>,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seq: u32,
    data: &[u8],
    timestamp: u64,
) -> Vec<Vec<u8>> {
    let stream_key = generate_tcp_stream_key(src_ip, src_port, dst_ip, dst_port);
    let stream = stream_buffers.entry(stream_key).or_insert_with(|| {
        BidirectionalTcpStream {
            client_to_server: TcpStreamBuffer {
                data: Vec::new(),
                expected_seq: 0,
                is_complete: false,
                last_activity: timestamp,
            },
            server_to_client: TcpStreamBuffer {
                data: Vec::new(),
                expected_seq: 0,
                is_complete: false,
                last_activity: timestamp,
            },
            last_activity: timestamp,
        }
    });

    stream.last_activity = timestamp;

    // 确定数据方向：通常客户端端口 < 服务器端口
    let is_client_to_server = src_port < dst_port;
    let buffer = if is_client_to_server {
        &mut stream.client_to_server
    } else {
        &mut stream.server_to_client
    };

    buffer.last_activity = timestamp;

    // 如果是第一个包，初始化序列号
    if buffer.expected_seq == 0 {
        buffer.expected_seq = seq;
    }

    // 处理序列号
    if seq == buffer.expected_seq {
        // 序列号匹配，添加数据
        buffer.data.extend_from_slice(data);
        buffer.expected_seq = seq.wrapping_add(data.len() as u32);
    } else if seq > buffer.expected_seq {
        // 有数据丢失，重置缓冲区
        buffer.data.clear();
        buffer.data.extend_from_slice(data);
        buffer.expected_seq = seq.wrapping_add(data.len() as u32);
    } else if seq < buffer.expected_seq {
        // 检查是否有重叠
        let overlap_start = buffer.expected_seq.wrapping_sub(seq) as usize;
        if overlap_start < data.len() {
            // 有重叠，只添加新数据部分
            buffer.data.extend_from_slice(&data[overlap_start..]);
            buffer.expected_seq = seq.wrapping_add(data.len() as u32);
        }
        // 如果完全重叠，忽略这个包
    }

    // 检查是否有完整的TLS记录
    let mut tls_records = Vec::new();
    if buffer.data.len() >= 5 {
        let mut offset = 0;
        while offset + 5 <= buffer.data.len() {
            let length = u16::from_be_bytes([buffer.data[offset + 3], buffer.data[offset + 4]]) as usize;
            let record_end = offset + 5 + length;

            if record_end <= buffer.data.len() {
                let record = buffer.data[offset..record_end].to_vec();
                if is_tls_packet(&record) {
                    tls_records.push(record);
                }
                offset = record_end;
            } else {
                break; // 不完整的记录
            }
        }

        // 移除已处理的数据
        if offset > 0 {
            buffer.data.drain(0..offset);
        }
    }

    tls_records
}

/// 处理数据包并返回提取的TLS/QUIC数据
pub fn process_packet(
    data: &[u8],
    stream_buffers: &mut HashMap<String, BidirectionalTcpStream>
) -> Option<ProcessedPacket> {
    // 首先尝试直接提取TLS数据（用于非分段的包）
    if let Some((src_ip, dst_ip, src_port, dst_port, tls_data)) = extract_tls_data_from_packet(data) {
        if is_quic_packet(&tls_data) {
            return Some(ProcessedPacket::Quic(tls_data, (src_ip, src_port, dst_ip, dst_port)));
        } else {
            return Some(ProcessedPacket::Tls(tls_data, (src_ip, src_port, dst_ip, dst_port)));
        }
    }

    // 如果不是完整的TLS包，尝试TCP流重组
    if let Some((src_ip, dst_ip, src_port, dst_port, seq, _ack, payload)) = extract_tcp_stream_from_packet(data)
        && !payload.is_empty() {
        // 使用时间戳作为简单的时间标识
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 重组TCP流
        let tls_records = reassemble_tcp_stream(
            stream_buffers,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            seq,
            &payload,
            timestamp,
        );

        // 处理重组后的TLS记录
        for tls_data in tls_records {
            if is_quic_packet(&tls_data) {
                return Some(ProcessedPacket::Quic(tls_data, (src_ip, src_port, dst_ip, dst_port)));
            } else {
                return Some(ProcessedPacket::Tls(tls_data, (src_ip, src_port, dst_ip, dst_port)));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vlan_parsing() {
        let data = [0x81, 0x00, 0x00, 0x01, 0x08, 0x00]; // VLAN tag + IPv4 ether type
        let (vlan_tags, offset, ether_type) = parse_vlan_tags(&data);
        assert_eq!(vlan_tags.len(), 1);
        assert_eq!(vlan_tags[0].vlan_id, 1);
        assert_eq!(ether_type, 0x0800);
        assert_eq!(offset, 6); // 2 bytes for initial ether_type + 4 bytes for VLAN tag
    }
}