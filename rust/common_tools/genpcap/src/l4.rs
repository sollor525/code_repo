//! 非 TCP 的 L4 报文构造：ICMP（echo 请求/应答）与 UDP，均为 IPv4 + 以太网。
//!
//! 手工拼装并计算校验和，避免引入额外依赖。当前仅支持 IPv4（调用方需保证地址为
//! IPv4；ICMP/UDP 的 IPv6 形态暂未实现）。

use std::net::Ipv4Addr;

/// 标准 Internet 校验和（16 位反码求和）
fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// 组装 以太网 + IPv4 + L4 负载（计算 IPv4 头校验和），返回整帧。
fn build_eth_ipv4(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    l4: &[u8],
) -> Vec<u8> {
    let total_len = 20 + l4.len();
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45; // version 4, IHL 5
    ip[1] = 0x00; // DSCP/ECN
    ip[2] = (total_len >> 8) as u8;
    ip[3] = (total_len & 0xff) as u8;
    ip[4] = 0xab; // identification
    ip[5] = 0xcd;
    ip[6] = 0x40; // flags = DF, fragment offset 0
    ip[7] = 0x00;
    ip[8] = 64; // TTL
    ip[9] = protocol;
    // ip[10..12] checksum = 0 (待计算)
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());
    let ip_csum = checksum16(&ip);
    ip[10] = (ip_csum >> 8) as u8;
    ip[11] = (ip_csum & 0xff) as u8;

    let mut frame = Vec::with_capacity(14 + total_len);
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(l4);
    frame
}

/// 构建 ICMP echo（IPv4）。`request=true` 为请求(type 8)，否则为应答(type 0)。
#[allow(clippy::too_many_arguments)]
pub fn build_icmp_echo(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
    request: bool,
) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(if request { 8 } else { 0 }); // type
    icmp.push(0); // code
    icmp.extend_from_slice(&[0, 0]); // checksum 占位
    icmp.extend_from_slice(&identifier.to_be_bytes());
    icmp.extend_from_slice(&sequence.to_be_bytes());
    icmp.extend_from_slice(payload);
    let csum = checksum16(&icmp);
    icmp[2] = (csum >> 8) as u8;
    icmp[3] = (csum & 0xff) as u8;

    build_eth_ipv4(src_mac, dst_mac, src_ip, dst_ip, 1, &icmp)
}

/// 构建 UDP 报文（IPv4，含伪首部校验和）。
#[allow(clippy::too_many_arguments)]
pub fn build_udp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum 占位
    udp.extend_from_slice(payload);

    // 伪首部 + UDP 计算校验和
    let mut pseudo = Vec::with_capacity(12 + udp_len);
    pseudo.extend_from_slice(&src_ip.octets());
    pseudo.extend_from_slice(&dst_ip.octets());
    pseudo.push(0);
    pseudo.push(17); // protocol = UDP
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let mut csum = checksum16(&pseudo);
    if csum == 0 {
        csum = 0xffff; // UDP 校验和为 0 表示未计算，故 0 写成 0xFFFF
    }
    udp[6] = (csum >> 8) as u8;
    udp[7] = (csum & 0xff) as u8;

    build_eth_ipv4(src_mac, dst_mac, src_ip, dst_ip, 17, &udp)
}
