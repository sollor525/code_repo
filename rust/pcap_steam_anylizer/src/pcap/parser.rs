//! 数据包解析器
//!
//! 提供网络数据包各层协议的解析功能

#![allow(clippy::single_match)]

use crate::types::packet::{Packet, Protocol, PacketLayer, TcpFlags};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use etherparse::{SlicedPacket, LinkSlice, InternetSlice, TransportSlice};

/// 解析错误类型
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("数据包头部解析失败: {0}")]
    HeaderParseError(String),
    #[error("无效的以太网帧")]
    InvalidEthernetFrame,
    #[error("不支持的协议类型: {0}")]
    UnsupportedProtocol(u8),
    #[error("数据包截断")]
    TruncatedPacket,
    #[error("IP校验和错误")]
    InvalidIpChecksum,
    #[error("TCP校验和错误")]
    InvalidTcpChecksum,
    #[error("UDP校验和错误")]
    InvalidUdpChecksum,
}

/// 数据包解析器
pub struct PacketParser {
    /// 是否验证校验和
    verify_checksums: bool,
    /// 是否解析负载
    parse_payload: bool,
    /// 链路层类型
    linktype: u32,
}

impl Default for PacketParser {
    fn default() -> Self {
        Self::new(false, false, 1)  // 默认以太网
    }
}

impl PacketParser {
    /// 创建新的数据包解析器
    ///
    /// # 参数
    /// * `verify_checksums` - 是否验证校验和
    /// * `parse_payload` - 是否解析负载
    /// * `linktype` - 链路层类型
    pub fn new(verify_checksums: bool, parse_payload: bool, linktype: u32) -> Self {
        Self {
            verify_checksums,
            parse_payload,
            linktype,
        }
    }

    /// 解析数据包
    ///
    /// 解析时把原始字节移出再借用，避免逐包克隆整个缓冲区。
    pub fn parse(&self, mut packet: Packet) -> Result<Packet, ParseError> {
        let data = std::mem::take(&mut packet.data);
        self.parse_inner(&data, packet).map(|mut parsed| {
            parsed.data = data;
            parsed
        })
    }

    /// 在借用的原始字节上解析各层协议
    fn parse_inner(&self, data: &[u8], packet: Packet) -> Result<Packet, ParseError> {
        // 根据链路层类型选择解析策略
        match self.linktype {
            // 标准以太网
            1 => {
                match SlicedPacket::from_ethernet(data) {
                    Ok(sliced) => {
                        let mut parsed_packet = packet;

                        // 解析链路层
                        if let Some(link) = sliced.link {
                            self.parse_link_layer(&link, &mut parsed_packet)?;
                        }

                        // 解析网络层
                        if let Some(ip) = sliced.ip {
                            self.parse_network_layer(&ip, &mut parsed_packet)?;
                        }

                        // 解析传输层
                        if let Some(transport) = sliced.transport {
                            self.parse_transport_layer(&transport, &mut parsed_packet)?;
                        }

                        // 解析负载
                        if self.parse_payload && !sliced.payload.is_empty() {
                            self.parse_payload(&sliced.payload, &mut parsed_packet)?;
                        }

                        return Ok(parsed_packet);
                    }
                    Err(_) => {}
                }
            }
            // Linux cooked "any" (65535) 或 Raw IP (101)
            101 | 65535 => {
                // 对于链路层类型65535，某些情况下实际数据仍然是标准以太网帧
                // 先尝试作为以太网帧解析
                #[allow(clippy::single_match)]
                if self.linktype == 65535 && data.len() >= 14 {
                    // 检查是否是以太网帧（0x0800表示IPv4）
                    if data[12] == 0x08 && data[13] == 0x00 {
                        match SlicedPacket::from_ethernet(data) {
                            Ok(sliced) => {
                                let mut parsed_packet = packet;

                                // 解析链路层
                                if let Some(link) = sliced.link {
                                    self.parse_link_layer(&link, &mut parsed_packet)?;
                                }

                                // 解析网络层
                                if let Some(ip) = sliced.ip {
                                    self.parse_network_layer(&ip, &mut parsed_packet)?;
                                }

                                // 解析传输层
                                if let Some(transport) = sliced.transport {
                                    self.parse_transport_layer(&transport, &mut parsed_packet)?;
                                }

                                // 解析负载
                                if self.parse_payload && !sliced.payload.is_empty() {
                                    self.parse_payload(&sliced.payload, &mut parsed_packet)?;
                                }

                                return Ok(parsed_packet);
                            }
                            Err(_) => {}
                        }
                    }
                }

                // 如果不是以太网帧，尝试作为Raw IP解析
                let ip_data = if self.linktype == 65535 && data.len() > 16 {
                    // Linux cooked capture (SLL) 头部格式：
                    // 跳过SLL头部（通常是16字节）
                    &data[16..]
                } else {
                    // Raw IP，直接使用数据
                    data
                };

                match SlicedPacket::from_ip(ip_data) {
                    Ok(sliced) => {
                        let mut parsed_packet = packet;

                        // Raw IP 模式，添加IP层标记
                        parsed_packet.layers.push(PacketLayer::Ip);

                        // 解析网络层
                        if let Some(ip) = sliced.ip {
                            self.parse_network_layer(&ip, &mut parsed_packet)?;
                        }

                        // 解析传输层
                        if let Some(transport) = sliced.transport {
                            self.parse_transport_layer(&transport, &mut parsed_packet)?;
                        }

                        // 解析负载
                        if self.parse_payload && !sliced.payload.is_empty() {
                            self.parse_payload(&sliced.payload, &mut parsed_packet)?;
                        }

                        return Ok(parsed_packet);
                    }
                    Err(e) => return Err(ParseError::HeaderParseError(e.to_string())),
                }
            }
            _ => {}
        }

        // 最后尝试：如果所有特定方法都失败，尝试通用的Raw IP解析
        // 尝试找到 IP 数据包的开始
        let ip_data = if data.len() >= 4 && data[0] != 0x45 {
            // 不是以 0x45 开头，尝试搜索IPv4头
            match data.iter().position(|&b| b == 0x45) {
                Some(ip_start) => &data[ip_start..],
                None => data,
            }
        } else {
            data
        };

        match SlicedPacket::from_ip(ip_data) {
            Ok(sliced) => {
                let mut parsed_packet = packet;

                // 解析网络层
                if let Some(ip) = sliced.ip {
                    self.parse_network_layer(&ip, &mut parsed_packet)?;
                }

                // 解析传输层
                if let Some(transport) = sliced.transport {
                    self.parse_transport_layer(&transport, &mut parsed_packet)?;
                }

                // 解析负载
                if self.parse_payload && !sliced.payload.is_empty() {
                    self.parse_payload(&sliced.payload, &mut parsed_packet)?;
                }

                Ok(parsed_packet)
            }
            Err(e) => Err(ParseError::HeaderParseError(e.to_string())),
        }
    }

    /// 解析链路层（以太网）
    #[allow(unreachable_patterns)]  // 在某些版本中可能还有其他链路层类型
    fn parse_link_layer(&self, link: &LinkSlice, packet: &mut Packet) -> Result<(), ParseError> {
        match link {
            LinkSlice::Ethernet2(header) => {
                // 提取MAC地址
                packet.src_mac = Some(header.source());
                packet.dst_mac = Some(header.destination());

                // 添加协议信息
                packet.protocols.push(Protocol::Ethernet);
                packet.layers.push(PacketLayer::Ethernet);

                // 根据EtherType判断上层协议
                match header.ether_type() {
                    0x0800 => packet.protocols.push(Protocol::Ipv4),  // IPv4
                    0x86DD => packet.protocols.push(Protocol::Ipv6),  // IPv6
                    0x0806 => packet.protocols.push(Protocol::Arp),   // ARP
                    0x8100 => {
                        // VLAN标签
                        packet.protocols.push(Protocol::Other(0x81));
                    }
                    0x8847 => {
                        // MPLS标签
                        packet.protocols.push(Protocol::Other(0x88));
                    }
                    _ => packet.protocols.push(Protocol::Other((header.ether_type() >> 8) as u8)),
                }

                Ok(())
            }
            _ => Err(ParseError::InvalidEthernetFrame),
        }
    }

    #[allow(dead_code)]  // 这些函数作为扩展功能保留
    /// 解析VLAN标签
    fn parse_vlan_tag(&self, data: &[u8], packet: &mut Packet) -> Result<(), ParseError> {
        if data.len() < 4 {
            return Err(ParseError::TruncatedPacket);
        }

        // VLAN标签格式：TPID(2B) + TCI(2B)
        let tpid = u16::from_be_bytes([data[0], data[1]]);
        let tci = u16::from_be_bytes([data[2], data[3]]);

        // VLAN优先级（3位）
        let _priority = (tci >> 13) & 0x07;
        // VLAN ID（12位）
        let _vlan_id = tci & 0x0FFF;

        // 根据TPID判断上层协议
        match tpid {
            0x0800 => packet.protocols.push(Protocol::Ipv4),
            0x86DD => packet.protocols.push(Protocol::Ipv6),
            0x0806 => packet.protocols.push(Protocol::Arp),
            _ => packet.protocols.push(Protocol::Other(0)),
        }

        Ok(())
    }

    /// 解析VLAN内部数据
    #[allow(dead_code)]
    fn parse_vlan_inner(&self, _tag: u16, _inner: u16, packet: &mut Packet) -> Result<(), ParseError> {
        // 简化的VLAN处理
        packet.layers.push(PacketLayer::Ethernet);
        Ok(())
    }

    /// 解析MPLS标签
    #[allow(dead_code)]
    fn parse_mpls_tag(&self, data: &[u8], _packet: &mut Packet) -> Result<(), ParseError> {
        if data.len() < 4 {
            return Err(ParseError::TruncatedPacket);
        }

        // MPLS标签格式：Label(20B) + TC(3B) + S(1B) + TTL(8B)
        let _label = u32::from_be_bytes([0, data[0], data[1], data[2]]) >> 12;
        let _tc = (data[2] >> 1) & 0x07;
        let _s = (data[2] & 0x01) != 0;

        Ok(())
    }

    /// 解析MPLS标签栈
    #[allow(dead_code)]
    fn parse_mpls_tags(&self, tags: &[u32], _packet: &mut Packet) -> Result<(), ParseError> {
        for (_i, &_label) in tags.iter().enumerate() {
            // 处理每个MPLS标签
        }
        Ok(())
    }

    /// 解析网络层
    fn parse_network_layer(&self, net: &InternetSlice, packet: &mut Packet) -> Result<(), ParseError> {
        packet.layers.push(PacketLayer::Ip);

        match net {
            InternetSlice::Ipv4(header, _extensions) => {
                packet.src_ip = Some(IpAddr::V4(Ipv4Addr::from(header.source())));
                packet.dst_ip = Some(IpAddr::V4(Ipv4Addr::from(header.destination())));
                // 提取TTL与identification（用于识别NPatch注入报文签名）
                packet.ip_ttl = Some(header.ttl());
                packet.ip_id = Some(header.identification());
                packet.protocols.push(Protocol::Ipv4);

                // 验证校验和（如果需要）
                if self.verify_checksums {
                    // TODO: 实现IPv4校验和验证
                }

                Ok(())
            }
            InternetSlice::Ipv6(header, _extensions) => {
                packet.src_ip = Some(IpAddr::V6(Ipv6Addr::from(header.source())));
                packet.dst_ip = Some(IpAddr::V6(Ipv6Addr::from(header.destination())));
                packet.protocols.push(Protocol::Ipv6);

                // IPv6没有校验和头部
                Ok(())
            }
        }
    }

    /// 解析传输层
    fn parse_transport_layer(&self, transport: &TransportSlice, packet: &mut Packet) -> Result<(), ParseError> {
        packet.layers.push(PacketLayer::Transport);

        match transport {
            TransportSlice::Tcp(header) => {
                packet.src_port = Some(header.source_port());
                packet.dst_port = Some(header.destination_port());
                packet.tcp_seq = Some(header.sequence_number());
                packet.tcp_ack = Some(header.acknowledgment_number());

                // 解析TCP标志位
                let flags = TcpFlags {
                    fin: header.fin(),
                    syn: header.syn(),
                    rst: header.rst(),
                    psh: header.psh(),
                    ack: header.ack(),
                    urg: header.urg(),
                    ece: header.ece(),
                    cwr: header.cwr(),
                };
                packet.tcp_flags = Some(flags);

                // 解析TCP窗口大小
                packet.tcp_window = Some(header.window_size());

                packet.protocols.push(Protocol::Tcp);

                // 验证校验和（如果需要）
                if self.verify_checksums {
                    // TODO: 实现TCP校验和验证
                }

                // 根据端口判断应用层协议
                self.identify_application_protocol(header.source_port(),
                                                  header.destination_port(),
                                                  packet);

                Ok(())
            }
            TransportSlice::Udp(header) => {
                packet.src_port = Some(header.source_port());
                packet.dst_port = Some(header.destination_port());
                packet.protocols.push(Protocol::Udp);

                // 验证校验和（如果需要）
                if self.verify_checksums {
                    // TODO: 实现UDP校验和验证
                }

                // 根据端口判断应用层协议
                self.identify_application_protocol(header.source_port(),
                                                  header.destination_port(),
                                                  packet);

                Ok(())
            }
            TransportSlice::Icmpv4(header) => {
                packet.protocols.push(Protocol::Icmp);
                // 可以解析ICMP类型和代码
                let _icmp_type = header.icmp_type();
                // ICMPv4没有直接的code方法，信息都在icmp_type中
                Ok(())
            }
            TransportSlice::Icmpv6(header) => {
                packet.protocols.push(Protocol::IcmpV6);
                // 可以解析ICMPv6类型和代码
                let _icmp_type = header.icmp_type();
                // ICMPv6没有直接的code方法，信息都在icmp_type中
                Ok(())
            }
            TransportSlice::Unknown(protocol) => {
                packet.protocols.push(Protocol::Other(*protocol));
                Ok(())
            }
        }
    }

    /// 识别应用层协议
    fn identify_application_protocol(&self, src_port: u16, dst_port: u16, packet: &mut Packet) {
        match (src_port, dst_port) {
            (80, _) | (_, 80) => packet.protocols.push(Protocol::Http),
            (443, _) | (_, 443) => packet.protocols.push(Protocol::Https),
            (53, _) | (_, 53) => packet.protocols.push(Protocol::Dns),
            (67, _) | (68, _) => packet.protocols.push(Protocol::Dhcp),
            _ => {},
        }

        // 检查是否有应用层数据
        if packet.payload().is_some() {
            packet.layers.push(PacketLayer::Application);
        }
    }

    /// 解析负载
    fn parse_payload(&self, payload: &[u8], packet: &mut Packet) -> Result<(), ParseError> {
        // 可以对负载进行进一步解析
        // 例如HTTP解析、DNS解析等

        // 简单的HTTP检测
        if payload.len() >= 4 {
            let start = &payload[..4];
            if start == b"HTTP" || start == b"GET " || start == b"POST" ||
               start == b"PUT " || start == b"HEAD" || start == b"DELE" {
                packet.protocols.push(Protocol::Http);
            }
        }

        // 简单的DNS检测（通过端口已经判断）
        if packet.protocols.contains(&Protocol::Dns) {
            // TODO: 可以进一步解析DNS消息
        }

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_packet_parser_default() {
        let parser = PacketParser::default();
        assert!(!parser.verify_checksums);
        assert!(!parser.parse_payload);
    }

    #[test]
    fn test_packet_parser_new() {
        let parser = PacketParser::new(true, true, 1);
        assert!(parser.verify_checksums);
        assert!(parser.parse_payload);
    }
}