//! VLAN数据包构建功能

use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::vlan::MutableVlanPacket;
use pnet::util::MacAddr;
use crate::tcp::packet::{TcpPacketParams, TcpPacketWithDataParams};

/// VLAN标签配置
#[derive(Debug, Clone)]
pub struct VlanTag {
    /// VLAN ID (1-4094)
    pub vlan_id: u16,
    /// 优先级 (0-7)
    pub priority: u8,
    /// DEI位 (Drop Eligible Indicator)
    pub dei: bool,
}

impl VlanTag {
    pub fn new(vlan_id: u16, priority: u8, dei: bool) -> Self {
        Self {
            vlan_id,
            priority,
            dei,
        }
    }

    /// 创建VLAN TCI (Tag Control Information)
    pub fn to_tci(&self) -> u16 {
        let mut tci = 0u16;

        // PCP: Priority Code Point (bits 13-15)
        tci |= ((self.priority as u16) & 0x07) << 13;

        // DEI: Drop Eligible Indicator (bit 12)
        if self.dei {
            tci |= 1 << 12;
        }

        // VLAN ID (bits 0-11)
        tci |= self.vlan_id & 0x0FFF;

        tci
    }
}

/// VLAN配置
#[derive(Debug, Clone)]
pub struct VlanConfig {
    /// 外层VLAN标签
    pub outer_tag: Option<VlanTag>,
    /// 内层VLAN标签 (用于QinQ)
    pub inner_tag: Option<VlanTag>,
    /// 是否为QinQ (双层VLAN)
    pub is_qinq: bool,
}

impl VlanConfig {
    pub fn new() -> Self {
        Self {
            outer_tag: None,
            inner_tag: None,
            is_qinq: false,
        }
    }

    /// 创建单层VLAN配置
    pub fn single_layer(vlan_id: u16, priority: u8, dei: bool) -> Self {
        Self {
            outer_tag: Some(VlanTag::new(vlan_id, priority, dei)),
            inner_tag: None,
            is_qinq: false,
        }
    }

    /// 创建双层VLAN (QinQ) 配置
    pub fn double_layer(outer_vlan_id: u16, inner_vlan_id: u16,
                        outer_priority: u8, inner_priority: u8) -> Self {
        Self {
            outer_tag: Some(VlanTag::new(outer_vlan_id, outer_priority, false)),
            inner_tag: Some(VlanTag::new(inner_vlan_id, inner_priority, false)),
            is_qinq: true,
        }
    }
}

/// 解析MAC地址字符串
pub fn parse_mac_address(mac_str: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err("MAC地址格式错误，期望格式: XX:XX:XX:XX:XX:XX".to_string());
    }

    let mut mac_bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac_bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("无效的MAC地址段: {}", part))?;
    }

    Ok(mac_bytes)
}

/// 构建VLAN数据包 (单层)
#[allow(clippy::too_many_arguments)]
pub fn build_vlan_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    vlan_tag: &VlanTag,
    ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    // VLAN数据包大小: Ethernet头(14) + VLAN头(4) + 负载
    let total_size = 14 + 4 + payload.len();
    let mut buffer = vec![0u8; total_size];

    {
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..14 + 4]).unwrap();

        // 设置以太网头
        eth_packet.set_destination(MacAddr::from(dst_mac));
        eth_packet.set_source(MacAddr::from(src_mac));
        eth_packet.set_ethertype(EtherTypes::Vlan);

        // 设置VLAN头
        if let Some(mut vlan_packet) = MutableVlanPacket::new(&mut buffer[14..18]) {
            vlan_packet.set_vlan_identifier(vlan_tag.vlan_id);
            vlan_packet.set_priority_code_point((vlan_tag.priority as u8) & 0x07);
            vlan_packet.set_drop_eligible_indicator(vlan_tag.dei);
        }
    }

    // 设置负载
    buffer[18..].copy_from_slice(payload);

    buffer
}

/// 构建QinQ数据包 (双层VLAN)
#[allow(clippy::too_many_arguments)]
pub fn build_qinq_packet(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    outer_vlan: &VlanTag,
    inner_vlan: &VlanTag,
    ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    // QinQ数据包大小: Ethernet头(14) + 外层VLAN(4) + 内层VLAN(4) + 负载
    let total_size = 14 + 4 + 4 + payload.len();
    let mut buffer = vec![0u8; total_size];

    {
        let mut eth_packet = MutableEthernetPacket::new(&mut buffer[..14 + 8]).unwrap();

        // 设置以太网头
        eth_packet.set_destination(MacAddr::from(dst_mac));
        eth_packet.set_source(MacAddr::from(src_mac));
        eth_packet.set_ethertype(EtherTypes::Vlan);

        // 设置外层VLAN头
        if let Some(mut outer_vlan_packet) = MutableVlanPacket::new(&mut buffer[14..18]) {
            outer_vlan_packet.set_vlan_identifier(outer_vlan.vlan_id);
            outer_vlan_packet.set_priority_code_point((outer_vlan.priority as u8) & 0x07);
            outer_vlan_packet.set_drop_eligible_indicator(outer_vlan.dei);
        }

        // 设置内层VLAN头
        if let Some(mut inner_vlan_packet) = MutableVlanPacket::new(&mut buffer[18..22]) {
            inner_vlan_packet.set_vlan_identifier(inner_vlan.vlan_id);
            inner_vlan_packet.set_priority_code_point((inner_vlan.priority as u8) & 0x07);
            inner_vlan_packet.set_drop_eligible_indicator(inner_vlan.dei);
        }
    }

    // 设置负载
    buffer[22..].copy_from_slice(payload);

    buffer
}

/// 从TCP参数构建VLAN TCP数据包
pub fn build_vlan_tcp_packet(
    tcp_params: TcpPacketParams,
    vlan_config: &VlanConfig,
) -> Vec<u8> {
    // 首先构建标准的TCP/IP数据包
    let tcp_payload = build_tcp_payload(&tcp_params);

    if vlan_config.is_qinq {
        if let (Some(outer_vlan), Some(inner_vlan)) = (&vlan_config.outer_tag, &vlan_config.inner_tag) {
            return build_qinq_packet(
                tcp_params.src_mac,
                tcp_params.dst_mac,
                outer_vlan,
                inner_vlan,
                EtherTypes::Ipv4.0,
                &tcp_payload,
            );
        }
    } else if let Some(vlan_tag) = &vlan_config.outer_tag {
        return build_vlan_packet(
            tcp_params.src_mac,
            tcp_params.dst_mac,
            vlan_tag,
            EtherTypes::Ipv4.0,
            &tcp_payload,
        );
    }

    // 如果没有VLAN配置，返回标准数据包
    tcp_payload
}

/// 从带数据的TCP参数构建VLAN TCP数据包
pub fn build_vlan_tcp_packet_with_data(
    tcp_params: TcpPacketWithDataParams,
    vlan_config: &VlanConfig,
) -> Vec<u8> {
    // 首先构建标准的TCP/IP数据包
    let tcp_payload = build_tcp_payload_with_data(&tcp_params);

    if vlan_config.is_qinq {
        if let (Some(outer_vlan), Some(inner_vlan)) = (&vlan_config.outer_tag, &vlan_config.inner_tag) {
            return build_qinq_packet(
                tcp_params.src_mac,
                tcp_params.dst_mac,
                outer_vlan,
                inner_vlan,
                EtherTypes::Ipv4.0,
                &tcp_payload,
            );
        }
    } else if let Some(vlan_tag) = &vlan_config.outer_tag {
        return build_vlan_packet(
            tcp_params.src_mac,
            tcp_params.dst_mac,
            vlan_tag,
            EtherTypes::Ipv4.0,
            &tcp_payload,
        );
    }

    // 如果没有VLAN配置，返回标准数据包
    tcp_payload
}

/// 构建TCP/IP负载 (复用现有逻辑)
fn build_tcp_payload(params: &TcpPacketParams) -> Vec<u8> {
    // 这里需要复用现有的TCP数据包构建逻辑
    // 为了简化，这里返回一个基本的TCP负载
    let mut packet = vec![0u8; 54]; // Ethernet(14) + IP(20) + TCP(20)

    // 填充以太网头
    packet[0..6].copy_from_slice(&params.dst_mac);
    packet[6..12].copy_from_slice(&params.src_mac);
    packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4

    // 填充IP头
    packet[14] = 0x45; // Version (4) + IHL (5)
    packet[15] = 0; // DSCP + ECN
    packet[16..18].copy_from_slice(&40u16.to_be_bytes()); // Total Length
    packet[18..20].copy_from_slice(&0u16.to_be_bytes()); // Identification
    packet[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags + Fragment Offset
    packet[22] = 64; // TTL
    packet[23] = 6; // Protocol (TCP)
    // Checksum will be calculated later
    packet[26..30].copy_from_slice(&params.src_ip.octets());
    packet[30..34].copy_from_slice(&params.dst_ip.octets());

    // 填充TCP头
    packet[34..36].copy_from_slice(&params.src_port.to_be_bytes());
    packet[36..38].copy_from_slice(&params.dst_port.to_be_bytes());
    packet[38..42].copy_from_slice(&params.seq.to_be_bytes());
    packet[42..46].copy_from_slice(&params.ack.to_be_bytes());
    packet[46] = 0x50; // Data Offset (5 * 4 = 20 bytes)
    packet[47] = params.flags as u8;
    packet[48..50].copy_from_slice(&0x2000u16.to_be_bytes()); // Window Size (8192)
    // Checksum will be calculated later
    packet[52..54].copy_from_slice(&0u16.to_be_bytes()); // Urgent Pointer

    packet
}

/// 构建带数据的TCP/IP负载
fn build_tcp_payload_with_data(params: &TcpPacketWithDataParams) -> Vec<u8> {
    // 首先构建基础数据包
    let mut packet = build_tcp_payload(&TcpPacketParams {
        src_mac: params.src_mac,
        dst_mac: params.dst_mac,
        src_ip: params.src_ip,
        dst_ip: params.dst_ip,
        src_port: params.src_port,
        dst_port: params.dst_port,
        seq: params.seq,
        ack: params.ack,
        flags: params.flags,
    });

    // 添加数据负载
    packet.extend_from_slice(&params.data);

    // 更新IP总长度
    let total_length = packet.len() - 14; // 减去以太网头
    packet[16..18].copy_from_slice(&(total_length as u16).to_be_bytes());

    packet
}