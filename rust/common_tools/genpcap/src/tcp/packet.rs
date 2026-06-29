// TCP包构造

use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::tcp::MutableTcpPacket;
use pnet_packet::MutablePacket;
use pnet_base::MacAddr;
use pnet_packet::tcp;
use pnet_packet::ipv4;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// TCP包构建参数
#[derive(Debug, Clone)]
pub struct TcpPacketParams {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
}

impl TcpPacketParams {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u16,
    ) -> Self {
        Self {
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
        }
    }
}

/// 构建 TCP 数据包 - 根据 IP 版本自动分发
pub fn build_tcp_packet(params: TcpPacketParams) -> Vec<u8> {
    match (&params.src_ip, &params.dst_ip) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            build_tcp_ipv4_packet(&params, *src_v4, *dst_v4)
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            build_tcp_ipv6_packet(&params, *src_v6, *dst_v6)
        }
        _ => panic!("源IP和目标IP必须为同一版本（同为IPv4或同为IPv6）"),
    }
}

/// IPv4 TCP 数据包构建
fn build_tcp_ipv4_packet(params: &TcpPacketParams, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut tcp_buf = vec![0u8; 20];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp_header.set_source(params.src_port);
    tcp_header.set_destination(params.dst_port);
    tcp_header.set_sequence(params.seq);
    tcp_header.set_acknowledgement(params.ack);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(params.flags);
    tcp_header.set_window(64240);
    tcp_header.set_checksum(0);
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);

    let mut ip_buf = vec![0u8; 20];
    let mut ip4_header = MutableIpv4Packet::new(&mut ip_buf).unwrap();
    ip4_header.set_version(4);
    ip4_header.set_header_length(5);
    ip4_header.set_total_length((20 + tcp_buf.len()) as u16);
    ip4_header.set_identification(0xabcd);
    ip4_header.set_flags(0x02);
    ip4_header.set_ttl(64);
    ip4_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip4_header.set_source(src_ip);
    ip4_header.set_destination(dst_ip);
    let checksum = ipv4::checksum(&ip4_header.to_immutable());
    ip4_header.set_checksum(checksum);

    let mut eth_buf = vec![0u8; 14 + 20 + tcp_buf.len()];
    let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_pkt.set_destination(MacAddr::from(params.dst_mac));
    eth_pkt.set_source(MacAddr::from(params.src_mac));
    eth_pkt.set_ethertype(EtherTypes::Ipv4);
    eth_pkt.payload_mut()[..20].copy_from_slice(&ip_buf);
    eth_pkt.payload_mut()[20..].copy_from_slice(&tcp_buf);
    eth_buf
}

/// IPv6 TCP 数据包构建
fn build_tcp_ipv6_packet(params: &TcpPacketParams, src_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> Vec<u8> {
    let mut tcp_buf = vec![0u8; 20];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp_header.set_source(params.src_port);
    tcp_header.set_destination(params.dst_port);
    tcp_header.set_sequence(params.seq);
    tcp_header.set_acknowledgement(params.ack);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(params.flags);
    tcp_header.set_window(64240);
    tcp_header.set_checksum(0);

    // IPv6 TCP 校验和计算
    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);

    // IPv6 头部（40 字节）
    let mut ip_buf = vec![0u8; 40];
    let mut ip6_header = MutableIpv6Packet::new(&mut ip_buf).unwrap();
    ip6_header.set_version(6);
    ip6_header.set_traffic_class(0);
    ip6_header.set_flow_label(0);
    ip6_header.set_payload_length(tcp_buf.len() as u16);
    ip6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    ip6_header.set_hop_limit(64);
    ip6_header.set_source(src_ip);
    ip6_header.set_destination(dst_ip);

    // 以太网头 + IPv6 头 + TCP 头
    let mut eth_buf = vec![0u8; 14 + 40 + tcp_buf.len()];
    let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_pkt.set_destination(MacAddr::from(params.dst_mac));
    eth_pkt.set_source(MacAddr::from(params.src_mac));
    eth_pkt.set_ethertype(EtherTypes::Ipv6); // 0x86DD
    eth_pkt.payload_mut()[..40].copy_from_slice(&ip_buf);
    eth_pkt.payload_mut()[40..].copy_from_slice(&tcp_buf);
    eth_buf
}

/// 带数据的TCP包构建参数
#[derive(Debug, Clone)]
pub struct TcpPacketWithDataParams {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub data: Vec<u8>,
}

impl TcpPacketWithDataParams {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u16,
        data: Vec<u8>,
    ) -> Self {
        Self {
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            data,
        }
    }
}

/// 构建带数据的 TCP 数据包 - 根据 IP 版本自动分发
pub fn build_tcp_packet_with_data(params: TcpPacketWithDataParams) -> Vec<u8> {
    match (&params.src_ip, &params.dst_ip) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => {
            build_tcp_ipv4_packet_with_data(&params, *src_v4, *dst_v4)
        }
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => {
            build_tcp_ipv6_packet_with_data(&params, *src_v6, *dst_v6)
        }
        _ => panic!("源IP和目标IP必须为同一版本（同为IPv4或同为IPv6）"),
    }
}

/// IPv4 带数据的 TCP 数据包构建
fn build_tcp_ipv4_packet_with_data(params: &TcpPacketWithDataParams, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut tcp_buf = vec![0u8; 20 + params.data.len()];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp_header.set_source(params.src_port);
    tcp_header.set_destination(params.dst_port);
    tcp_header.set_sequence(params.seq);
    tcp_header.set_acknowledgement(params.ack);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(params.flags);
    tcp_header.set_window(64240);
    tcp_header.set_checksum(0);

    // 复制数据到TCP载荷
    tcp_header.payload_mut().copy_from_slice(&params.data);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);

    let mut ip_buf = vec![0u8; 20];
    let mut ip4_header = MutableIpv4Packet::new(&mut ip_buf).unwrap();
    ip4_header.set_version(4);
    ip4_header.set_header_length(5);
    ip4_header.set_total_length((20 + tcp_buf.len()) as u16);
    ip4_header.set_identification(0xabcd);
    ip4_header.set_flags(0x02);
    ip4_header.set_ttl(64);
    ip4_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip4_header.set_source(src_ip);
    ip4_header.set_destination(dst_ip);
    let checksum = ipv4::checksum(&ip4_header.to_immutable());
    ip4_header.set_checksum(checksum);

    let mut eth_buf = vec![0u8; 14 + 20 + tcp_buf.len()];
    let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_pkt.set_destination(MacAddr::from(params.dst_mac));
    eth_pkt.set_source(MacAddr::from(params.src_mac));
    eth_pkt.set_ethertype(EtherTypes::Ipv4);
    eth_pkt.payload_mut()[..20].copy_from_slice(&ip_buf);
    eth_pkt.payload_mut()[20..].copy_from_slice(&tcp_buf);
    eth_buf
}

/// IPv6 带数据的 TCP 数据包构建
fn build_tcp_ipv6_packet_with_data(params: &TcpPacketWithDataParams, src_ip: Ipv6Addr, dst_ip: Ipv6Addr) -> Vec<u8> {
    let mut tcp_buf = vec![0u8; 20 + params.data.len()];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp_header.set_source(params.src_port);
    tcp_header.set_destination(params.dst_port);
    tcp_header.set_sequence(params.seq);
    tcp_header.set_acknowledgement(params.ack);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(params.flags);
    tcp_header.set_window(64240);
    tcp_header.set_checksum(0);

    // 复制数据到TCP载荷
    tcp_header.payload_mut().copy_from_slice(&params.data);

    // IPv6 TCP 校验和计算
    let checksum = tcp::ipv6_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);

    // IPv6 头部（40 字节）
    let mut ip_buf = vec![0u8; 40];
    let mut ip6_header = MutableIpv6Packet::new(&mut ip_buf).unwrap();
    ip6_header.set_version(6);
    ip6_header.set_traffic_class(0);
    ip6_header.set_flow_label(0);
    ip6_header.set_payload_length(tcp_buf.len() as u16);
    ip6_header.set_next_header(IpNextHeaderProtocols::Tcp);
    ip6_header.set_hop_limit(64);
    ip6_header.set_source(src_ip);
    ip6_header.set_destination(dst_ip);

    // 以太网头 + IPv6 头 + TCP 头
    let mut eth_buf = vec![0u8; 14 + 40 + tcp_buf.len()];
    let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_pkt.set_destination(MacAddr::from(params.dst_mac));
    eth_pkt.set_source(MacAddr::from(params.src_mac));
    eth_pkt.set_ethertype(EtherTypes::Ipv6); // 0x86DD
    eth_pkt.payload_mut()[..40].copy_from_slice(&ip_buf);
    eth_pkt.payload_mut()[40..].copy_from_slice(&tcp_buf);
    eth_buf
}
