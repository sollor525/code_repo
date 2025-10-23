// TCP三次握手逻辑

use super::connection::TcpConnection;
use super::packet::{build_tcp_packet, TcpPacketParams};
use std::net::Ipv4Addr;

// 封装TCP三次握手
pub fn build_tcp_handshake_packets(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    isn: u32,
) -> (Vec<Vec<u8>>, TcpConnection) {
    let mut packets = Vec::new();
    let mut conn = TcpConnection::new(isn);

    // 1) SYN
    let syn = build_tcp_packet(TcpPacketParams::new(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
        conn.client_seq, 0, pnet::packet::tcp::TcpFlags::SYN,
    ));
    packets.push(syn);
    conn.update_seq(true, 1); // SYN占用1个序列号

    // 2) SYN/ACK
    let syn_ack = build_tcp_packet(TcpPacketParams::new(
        dst_mac, src_mac, dst_ip, src_ip, dst_port, src_port,
        conn.server_seq, conn.client_seq,
        pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK,
    ));
    packets.push(syn_ack);
    conn.update_seq(false, 1); // SYN占用1个序列号
    conn.update_ack(false, 1); // 确认客户端的SYN

    // 3) ACK
    let ack = build_tcp_packet(TcpPacketParams::new(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
        conn.client_seq, conn.server_seq,
        pnet::packet::tcp::TcpFlags::ACK,
    ));
    packets.push(ack);
    conn.update_ack(true, 1); // 确认服务器的SYN

    (packets, conn)
}