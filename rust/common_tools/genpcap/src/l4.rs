//! 非 TCP 的 L4 报文构造：ICMP / ICMPv6 echo 与 UDP，IPv4 与 IPv6 均支持。
//!
//! 每个构造函数返回**一个或多个**以太网帧：当 IP 数据报超过 MTU 时按 IP 层分片
//! （IPv4 用分片标志/偏移；IPv6 用分片扩展头）。L4 校验和在分片前对完整数据报计算。
//! `mtu == 0` 表示不限制（不分片）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

/// IPv6 伪首部校验和（用于 UDP / ICMPv6）
fn ipv6_pseudo_checksum(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, upper: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + upper.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.extend_from_slice(&(upper.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, next_header]);
    buf.extend_from_slice(upper);
    checksum16(&buf)
}

// --------------------------- IPv4 组帧 / 分片 ---------------------------

fn one_ipv4_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    ip_id: u16,
    more: bool,
    frag_off_8: usize,
    data: &[u8],
) -> Vec<u8> {
    let total = 20 + data.len();
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[2] = (total >> 8) as u8;
    ip[3] = (total & 0xff) as u8;
    ip[4] = (ip_id >> 8) as u8;
    ip[5] = (ip_id & 0xff) as u8;
    let flags_off = (if more { 0x2000u16 } else { 0 }) | (frag_off_8 as u16 & 0x1fff);
    ip[6] = (flags_off >> 8) as u8;
    ip[7] = (flags_off & 0xff) as u8;
    ip[8] = 64;
    ip[9] = proto;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let c = checksum16(&ip);
    ip[10] = (c >> 8) as u8;
    ip[11] = (c & 0xff) as u8;

    let mut f = Vec::with_capacity(14 + total);
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend_from_slice(&ip);
    f.extend_from_slice(data);
    f
}

fn eth_ipv4_fragments(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    l4: &[u8],
    mtu: usize,
    ip_id: u16,
) -> Vec<Vec<u8>> {
    if mtu == 0 || 20 + l4.len() <= mtu {
        return vec![one_ipv4_frame(src_mac, dst_mac, src, dst, proto, ip_id, false, 0, l4)];
    }
    let max_data = (((mtu - 20) / 8) * 8).max(8);
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < l4.len() {
        let end = (offset + max_data).min(l4.len());
        let more = end < l4.len();
        out.push(one_ipv4_frame(
            src_mac, dst_mac, src, dst, proto, ip_id, more, offset / 8, &l4[offset..end],
        ));
        offset = end;
    }
    out
}

// --------------------------- IPv6 组帧 / 分片 ---------------------------

/// `frag = Some((l4_next_header, offset_in_8octets, more_flag, id))` 时插入分片扩展头。
fn one_ipv6_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    ip_next: u8,
    frag: Option<(u8, u16, bool, u32)>,
    payload: &[u8],
) -> Vec<u8> {
    let ext: Vec<u8> = if let Some((l4_next, off8, more, id)) = frag {
        let foff = (off8 << 3) | (if more { 1 } else { 0 });
        let mut fh = vec![0u8; 8];
        fh[0] = l4_next;
        fh[2] = (foff >> 8) as u8;
        fh[3] = (foff & 0xff) as u8;
        fh[4..8].copy_from_slice(&id.to_be_bytes());
        fh
    } else {
        Vec::new()
    };
    let payload_len = ext.len() + payload.len();

    let mut ip = vec![0u8; 40];
    ip[0] = 0x60; // version 6
    ip[4] = (payload_len >> 8) as u8;
    ip[5] = (payload_len & 0xff) as u8;
    ip[6] = ip_next; // next header（分片时为 44，否则为 L4 协议号）
    ip[7] = 64; // hop limit
    ip[8..24].copy_from_slice(&src.octets());
    ip[24..40].copy_from_slice(&dst.octets());

    let mut f = Vec::with_capacity(14 + 40 + payload_len);
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x86, 0xdd]);
    f.extend_from_slice(&ip);
    f.extend_from_slice(&ext);
    f.extend_from_slice(payload);
    f
}

fn eth_ipv6_fragments(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    l4: &[u8],
    mtu: usize,
    id: u32,
) -> Vec<Vec<u8>> {
    if mtu == 0 || 40 + l4.len() <= mtu {
        return vec![one_ipv6_frame(src_mac, dst_mac, src, dst, next_header, None, l4)];
    }
    let max_data = (((mtu - 40 - 8) / 8) * 8).max(8);
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < l4.len() {
        let end = (offset + max_data).min(l4.len());
        let more = end < l4.len();
        out.push(one_ipv6_frame(
            src_mac, dst_mac, src, dst, 44, // Fragment 扩展头
            Some((next_header, (offset / 8) as u16, more, id)),
            &l4[offset..end],
        ));
        offset = end;
    }
    out
}

// ------------------------------- ICMP echo -------------------------------

/// 构建 ICMP / ICMPv6 echo。`request=true` 为请求，否则为应答。返回若干帧（按 MTU 分片）。
#[allow(clippy::too_many_arguments)]
pub fn build_icmp_echo(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
    request: bool,
    mtu: usize,
) -> Vec<Vec<u8>> {
    match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut icmp = vec![if request { 8 } else { 0 }, 0, 0, 0];
            icmp.extend_from_slice(&identifier.to_be_bytes());
            icmp.extend_from_slice(&sequence.to_be_bytes());
            icmp.extend_from_slice(payload);
            let c = checksum16(&icmp);
            icmp[2] = (c >> 8) as u8;
            icmp[3] = (c & 0xff) as u8;
            eth_ipv4_fragments(src_mac, dst_mac, s, d, 1, &icmp, mtu, 0x1000u16.wrapping_add(sequence))
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut icmp = vec![if request { 128 } else { 129 }, 0, 0, 0];
            icmp.extend_from_slice(&identifier.to_be_bytes());
            icmp.extend_from_slice(&sequence.to_be_bytes());
            icmp.extend_from_slice(payload);
            let c = ipv6_pseudo_checksum(s, d, 58, &icmp);
            icmp[2] = (c >> 8) as u8;
            icmp[3] = (c & 0xff) as u8;
            eth_ipv6_fragments(src_mac, dst_mac, s, d, 58, &icmp, mtu, 0x1000u32.wrapping_add(sequence as u32))
        }
        _ => Vec::new(), // 版本不一致（上游已校验）
    }
}

// --------------------------------- UDP ---------------------------------

/// 构建 UDP 报文（IPv4 / IPv6），返回若干帧（按 MTU 分片）。
#[allow(clippy::too_many_arguments)]
pub fn build_udp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    mtu: usize,
) -> Vec<Vec<u8>> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum 占位
    udp.extend_from_slice(payload);

    match (src_ip, dst_ip) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut pseudo = Vec::with_capacity(12 + udp_len);
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.push(0);
            pseudo.push(17);
            pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
            pseudo.extend_from_slice(&udp);
            let mut c = checksum16(&pseudo);
            if c == 0 {
                c = 0xffff;
            }
            udp[6] = (c >> 8) as u8;
            udp[7] = (c & 0xff) as u8;
            eth_ipv4_fragments(src_mac, dst_mac, s, d, 17, &udp, mtu, 0x2000)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut c = ipv6_pseudo_checksum(s, d, 17, &udp);
            if c == 0 {
                c = 0xffff;
            }
            udp[6] = (c >> 8) as u8;
            udp[7] = (c & 0xff) as u8;
            eth_ipv6_fragments(src_mac, dst_mac, s, d, 17, &udp, mtu, 0x2000)
        }
        _ => Vec::new(),
    }
}
