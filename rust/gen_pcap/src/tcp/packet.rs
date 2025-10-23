// TCP包构造

use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::MutablePacket;
use pnet::util::MacAddr;
use pnet::packet::tcp;
use pnet::packet::ipv4;
use std::net::Ipv4Addr;

/// TCP包构建参数
#[derive(Debug, Clone)]
pub struct TcpPacketParams {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
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
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
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

pub fn build_tcp_packet(params: TcpPacketParams) -> Vec<u8> {
    let TcpPacketParams {
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        seq,
        ack,
        flags,
    } = params;
    let mut tcp_buf = vec![0u8; 20];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(seq);
    tcp_header.set_acknowledgement(ack);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(flags);
    tcp_header.set_window(64240);
    tcp_header.set_checksum(0); // 内核会计算，这里留空即可
    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);

    let mut ip_buf = vec![0u8; 20];
    let mut ip4_header = MutableIpv4Packet::new(&mut ip_buf).unwrap();
    ip4_header.set_version(4);
    ip4_header.set_header_length(5);
    ip4_header.set_total_length((20 + tcp_buf.len()) as u16);
    ip4_header.set_identification(0xabcd);
    ip4_header.set_flags(0x02); // DF
    ip4_header.set_ttl(64);
    ip4_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip4_header.set_source(src_ip);
    ip4_header.set_destination(dst_ip);
    let checksum = ipv4::checksum(&ip4_header.to_immutable());
    ip4_header.set_checksum(checksum);

    let mut eth_buf = vec![0u8; 14 + 20 + tcp_buf.len()];
    let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_pkt.set_destination(MacAddr::from(dst_mac));
    eth_pkt.set_source(MacAddr::from(src_mac));
    eth_pkt.set_ethertype(EtherTypes::Ipv4);
    eth_pkt.payload_mut()[..20].copy_from_slice(&ip_buf);
    eth_pkt.payload_mut()[20..].copy_from_slice(&tcp_buf);
    eth_buf
}

/// 带数据的TCP包构建参数
#[derive(Debug, Clone)]
pub struct TcpPacketWithDataParams {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
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
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
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

pub fn build_tcp_packet_with_data(params: TcpPacketWithDataParams) -> Vec<u8> {
    let TcpPacketWithDataParams {
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
    } = params;
    let mut tcp_buf = vec![0u8; 20 + data.len()];
    let mut tcp_header = MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp_header.set_source(src_port);
    tcp_header.set_destination(dst_port);
    tcp_header.set_sequence(seq);
    tcp_header.set_acknowledgement(ack);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(flags);
    tcp_header.set_window(64240);
    tcp_header.set_checksum(0); // 内核会计算，这里留空即可

    // 复制数据到TCP载荷
    tcp_header.payload_mut().copy_from_slice(&data);

    let checksum = tcp::ipv4_checksum(&tcp_header.to_immutable(), &src_ip, &dst_ip);
    tcp_header.set_checksum(checksum);

    let mut ip_buf = vec![0u8; 20];
    let mut ip4_header = MutableIpv4Packet::new(&mut ip_buf).unwrap();
    ip4_header.set_version(4);
    ip4_header.set_header_length(5);
    ip4_header.set_total_length((20 + tcp_buf.len()) as u16);
    ip4_header.set_identification(0xabcd);
    ip4_header.set_flags(0x02); // DF
    ip4_header.set_ttl(64);
    ip4_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip4_header.set_source(src_ip);
    ip4_header.set_destination(dst_ip);
    let checksum = ipv4::checksum(&ip4_header.to_immutable());
    ip4_header.set_checksum(checksum);

    let mut eth_buf = vec![0u8; 14 + 20 + tcp_buf.len()];
    let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_pkt.set_destination(MacAddr::from(dst_mac));
    eth_pkt.set_source(MacAddr::from(src_mac));
    eth_pkt.set_ethertype(EtherTypes::Ipv4);
    eth_pkt.payload_mut()[..20].copy_from_slice(&ip_buf);
    eth_pkt.payload_mut()[20..].copy_from_slice(&tcp_buf);
    eth_buf
}