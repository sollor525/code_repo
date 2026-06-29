//! 各协议的报文序列生成。
//!
//! TCP 类（TCP 模式 / HTTP / FTP / SSH / MySQL）经 [`TcpConversation`] 构造，seq/ack
//! 自洽，并按 MSS（由 MTU 推导）做 TCP 分段；ICMP / UDP 经 [`crate::l4`] 构造（IPv4/IPv6，
//! 按 MTU 做 IP 分片）。`GenOptions` 提供 MTU 与自动填充载荷大小（用户未指定内容时生效）。
//! 应用层协议（FTP/SSH/MySQL）使用代表性载荷，并非完整协议状态机。

use std::net::IpAddr;

use crate::conversation::TcpConversation;
use crate::core::session::{
    FtpMode, GenOptions, HttpConfig, IcmpConfig, TcpMode, TcpSession, UdpConfig,
};
use crate::l4;

const SERVER_ISN_OFFSET: u32 = 0x9E3779B9;

/// 由 MTU 推导 TCP 最大段大小（MSS = MTU − IP头 − TCP头）；mtu==0 时不分段。
fn mss_for(session: &TcpSession, mtu: usize) -> usize {
    if mtu == 0 {
        return 0;
    }
    let ip_hdr = match session.connection.src_ip {
        IpAddr::V4(_) => 20,
        IpAddr::V6(_) => 40,
    };
    mtu.saturating_sub(ip_hdr + 20).max(1)
}

fn conv(session: &TcpSession, src_port: u16, dst_port: u16, salt: u32, opts: &GenOptions) -> TcpConversation {
    let c = &session.connection;
    let mut tc = TcpConversation::new(
        c.src_mac,
        c.dst_mac,
        c.src_ip,
        c.dst_ip,
        src_port,
        dst_port,
        session.isn.wrapping_add(salt),
        session.isn.wrapping_add(SERVER_ISN_OFFSET).wrapping_add(salt),
    );
    tc.set_mss(mss_for(session, opts.mtu));
    tc
}

/// 自动填充载荷：可打印的重复模式，便于在 Wireshark 中辨识。
fn filler(n: usize) -> Vec<u8> {
    const PAT: &[u8] = b"ByteBench PCAP payload 0123456789ABCDEF abcdefghijklmnopqrstuvwxyz\n";
    (0..n).map(|i| PAT[i % PAT.len()]).collect()
}

/// CRLF 规范化：把单独的 \n 也补成 \r\n（便于用户直接粘贴文本）。
fn normalize_crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}

// ============================== TCP 模式 ==============================

pub fn tcp_mode(session: &TcpSession, mode: TcpMode, opts: &GenOptions) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let mut tc = conv(session, c.src_port, c.dst_port, 0, opts);
    let data = if opts.payload_size > 0 { Some(filler(opts.payload_size)) } else { None };
    match mode {
        TcpMode::SynOnly => tc.syn_only(),
        TcpMode::Handshake => {
            tc.handshake();
            if let Some(d) = &data { tc.client_data(d); }
        }
        TcpMode::HandshakeClose => {
            tc.handshake();
            if let Some(d) = &data { tc.client_data(d); }
            tc.close_graceful();
        }
        TcpMode::HandshakeReset => {
            tc.handshake();
            if let Some(d) = &data { tc.client_data(d); }
            tc.reset();
        }
    }
    tc.into_packets()
}

// ================================ HTTP ================================

/// 默认 HTTP 响应；payload_size>0 时响应体填充到该大小（octet-stream）。
fn default_http_response(json_body: &str, payload_size: usize) -> Vec<u8> {
    let (ctype, body): (&str, Vec<u8>) = if payload_size > 0 {
        ("application/octet-stream", filler(payload_size))
    } else {
        ("application/json", json_body.as_bytes().to_vec())
    };
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nServer: ByteBench\r\nContent-Type: {}\r\n\
         Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        ctype,
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(&body);
    out
}

pub fn http(session: &TcpSession, cfg: &HttpConfig, opts: &GenOptions) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let mut tc = conv(session, c.src_port, c.dst_port, 0, opts);
    tc.handshake();

    let custom_resp = cfg.response_content.as_ref().map(|r| normalize_crlf(r).into_bytes());

    if let Some(req) = cfg.request_content.as_ref() {
        tc.client_data(normalize_crlf(req).as_bytes());
        let resp = custom_resp.unwrap_or_else(|| default_http_response("{\"ok\":true}", opts.payload_size));
        tc.server_data(&resp);
    } else {
        let uris = if cfg.uris.is_empty() {
            vec!["/".to_string()]
        } else {
            cfg.uris.clone()
        };
        for uri in &uris {
            let req = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ByteBench/0.1\r\n\
                 Accept: */*\r\nConnection: keep-alive\r\n\r\n",
                uri, cfg.host
            );
            tc.client_data(req.as_bytes());
            let resp = custom_resp
                .clone()
                .unwrap_or_else(|| default_http_response(&format!("{{\"uri\":\"{}\",\"ok\":true}}", uri), opts.payload_size));
            tc.server_data(&resp);
        }
    }

    tc.close_graceful();
    tc.into_packets()
}

// ============================== ICMP / UDP ==============================

const DEFAULT_ICMP_PAYLOAD: &[u8] = b"abcdefghijklmnopqrstuvwabcdefghi"; // 32 字节

pub fn icmp(session: &TcpSession, cfg: &IcmpConfig, opts: &GenOptions) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let payload = if opts.payload_size > 0 {
        filler(opts.payload_size)
    } else {
        DEFAULT_ICMP_PAYLOAD.to_vec()
    };
    let n = cfg.count.max(1);
    let mut out = Vec::new();
    for seq in 0..n as u16 {
        out.extend(l4::build_icmp_echo(c.src_mac, c.dst_mac, c.src_ip, c.dst_ip, 0x1234, seq, &payload, true, opts.mtu));
        out.extend(l4::build_icmp_echo(c.dst_mac, c.src_mac, c.dst_ip, c.src_ip, 0x1234, seq, &payload, false, opts.mtu));
    }
    out
}

pub fn udp(session: &TcpSession, cfg: &UdpConfig, opts: &GenOptions) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let payload = if !cfg.payload.is_empty() {
        cfg.payload.clone()
    } else if opts.payload_size > 0 {
        filler(opts.payload_size)
    } else {
        b"ByteBench UDP payload".to_vec()
    };
    let mut out = Vec::new();
    out.extend(l4::build_udp(c.src_mac, c.dst_mac, c.src_ip, c.dst_ip, c.src_port, c.dst_port, &payload, opts.mtu));
    if cfg.with_response {
        out.extend(l4::build_udp(
            c.dst_mac, c.src_mac, c.dst_ip, c.src_ip, c.dst_port, c.src_port,
            b"ByteBench UDP response", opts.mtu,
        ));
    }
    out
}

// ================================ FTP ================================

/// FTP PORT / PASV 的 h1,h2,h3,h4,p1,p2 形式（仅 IPv4 有意义；IPv6 退回回环占位）
fn host_port_tuple(ip: IpAddr, port: u16) -> String {
    let o = match ip {
        IpAddr::V4(a) => a.octets(),
        IpAddr::V6(_) => [127, 0, 0, 1],
    };
    format!("{},{},{},{},{},{}", o[0], o[1], o[2], o[3], port >> 8, port & 0xff)
}

pub fn ftp(session: &TcpSession, mode: FtpMode, opts: &GenOptions) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let mut out: Vec<Vec<u8>> = Vec::new();

    let mut ctrl = conv(session, c.src_port, c.dst_port, 0, opts);
    ctrl.handshake();
    ctrl.server_data(b"220 (ByteBench FTP)\r\n");
    ctrl.client_data(b"USER anonymous\r\n");
    ctrl.server_data(b"331 Please specify the password.\r\n");
    ctrl.client_data(b"PASS guest@example.com\r\n");
    ctrl.server_data(b"230 Login successful.\r\n");
    ctrl.client_data(b"TYPE I\r\n");
    ctrl.server_data(b"200 Switching to Binary mode.\r\n");

    let data_port: u16 = 50_000;
    let file_payload = if opts.payload_size > 0 {
        filler(opts.payload_size)
    } else {
        b"ByteBench FTP demo file contents.\nLine 2.\n".to_vec()
    };
    let mss = mss_for(session, opts.mtu);

    match mode {
        FtpMode::Passive => {
            ctrl.client_data(b"PASV\r\n");
            let line = format!("227 Entering Passive Mode ({}).\r\n", host_port_tuple(c.dst_ip, data_port));
            ctrl.server_data(line.as_bytes());
            ctrl.client_data(b"RETR demo.txt\r\n");
            ctrl.server_data(b"150 Opening BINARY mode data connection for demo.txt.\r\n");
            out.extend(ctrl.take());

            // 数据连接：客户端 -> 服务器被动端口
            let mut dc = TcpConversation::new(
                c.src_mac, c.dst_mac, c.src_ip, c.dst_ip,
                c.src_port.wrapping_add(1), data_port,
                session.isn.wrapping_add(0x100),
                session.isn.wrapping_add(SERVER_ISN_OFFSET).wrapping_add(0x100),
            );
            dc.set_mss(mss);
            dc.handshake();
            dc.server_data(&file_payload);
            dc.close_graceful();
            out.extend(dc.into_packets());

            ctrl.server_data(b"226 Transfer complete.\r\n");
        }
        FtpMode::Active => {
            let port_line = format!("PORT {}\r\n", host_port_tuple(c.src_ip, data_port));
            ctrl.client_data(port_line.as_bytes());
            ctrl.server_data(b"200 PORT command successful. Consider using PASV.\r\n");
            ctrl.client_data(b"RETR demo.txt\r\n");
            ctrl.server_data(b"150 Opening BINARY mode data connection for demo.txt.\r\n");
            out.extend(ctrl.take());

            // 数据连接：服务器(20) 主动连客户端(data_port)，故服务器为发起方
            let mut dc = TcpConversation::new(
                c.dst_mac, c.src_mac, c.dst_ip, c.src_ip,
                20, data_port,
                session.isn.wrapping_add(SERVER_ISN_OFFSET).wrapping_add(0x200),
                session.isn.wrapping_add(0x200),
            );
            dc.set_mss(mss);
            dc.handshake();
            dc.client_data(&file_payload); // 此处 "client" 即服务器(20)，向客户端发数据
            dc.close_graceful();
            out.extend(dc.into_packets());

            ctrl.server_data(b"226 Transfer complete.\r\n");
        }
    }

    ctrl.client_data(b"QUIT\r\n");
    ctrl.server_data(b"221 Goodbye.\r\n");
    ctrl.close_graceful();
    out.extend(ctrl.into_packets());
    out
}

// ================================ SSH ================================

/// 构造一个代表性的 SSH KEXINIT 二进制包（含真实算法名列表）。
fn ssh_kexinit() -> Vec<u8> {
    let cookie: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    ];
    let name_lists = [
        "curve25519-sha256",
        "ssh-ed25519",
        "aes128-ctr",
        "aes128-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ];
    let mut payload = Vec::new();
    payload.push(20u8); // SSH_MSG_KEXINIT
    payload.extend_from_slice(&cookie);
    for nl in name_lists {
        payload.extend_from_slice(&(nl.len() as u32).to_be_bytes());
        payload.extend_from_slice(nl.as_bytes());
    }
    payload.push(0); // first_kex_packet_follows
    payload.extend_from_slice(&[0, 0, 0, 0]); // reserved

    let mut padding_len = 8 - ((1 + payload.len() + 4) % 8);
    if padding_len < 4 {
        padding_len += 8;
    }
    let packet_len = 1 + payload.len() + padding_len;
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&(packet_len as u32).to_be_bytes());
    pkt.push(padding_len as u8);
    pkt.extend_from_slice(&payload);
    pkt.extend(std::iter::repeat(0u8).take(padding_len));
    pkt
}

pub fn ssh(session: &TcpSession, opts: &GenOptions) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let mut tc = conv(session, c.src_port, c.dst_port, 0, opts);
    tc.handshake();
    tc.client_data(b"SSH-2.0-OpenSSH_8.9p1 ByteBench\r\n");
    tc.server_data(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n");
    let kex = ssh_kexinit();
    tc.client_data(&kex);
    tc.server_data(&kex);
    tc.close_graceful();
    tc.into_packets()
}

// ================================ MySQL ===============================

fn mysql_packet(seq: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut p = Vec::with_capacity(4 + len);
    p.push((len & 0xff) as u8);
    p.push(((len >> 8) & 0xff) as u8);
    p.push(((len >> 16) & 0xff) as u8);
    p.push(seq);
    p.extend_from_slice(payload);
    p
}

fn mysql_server_greeting() -> Vec<u8> {
    let mut b = Vec::new();
    b.push(10);
    b.extend_from_slice(b"8.0.34-ByteBench\0");
    b.extend_from_slice(&0x0000_002au32.to_le_bytes());
    b.extend_from_slice(b"\x01\x02\x03\x04\x05\x06\x07\x08");
    b.push(0);
    b.extend_from_slice(&0xffffu16.to_le_bytes());
    b.push(0x21);
    b.extend_from_slice(&0x0002u16.to_le_bytes());
    b.extend_from_slice(&0xc0ffu16.to_le_bytes());
    b.push(21);
    b.extend_from_slice(&[0u8; 10]);
    b.extend_from_slice(b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\0");
    b.extend_from_slice(b"mysql_native_password\0");
    mysql_packet(0, &b)
}

fn mysql_login_request() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x000a_a685u32.to_le_bytes());
    b.extend_from_slice(&0x0100_0000u32.to_le_bytes());
    b.push(0x21);
    b.extend_from_slice(&[0u8; 23]);
    b.extend_from_slice(b"root\0");
    b.push(20);
    b.extend_from_slice(&[0xab; 20]);
    b.extend_from_slice(b"mysql_native_password\0");
    mysql_packet(1, &b)
}

fn mysql_ok(seq: u8) -> Vec<u8> {
    mysql_packet(seq, &[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00])
}

fn mysql_com_query(sql: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(1 + sql.len());
    b.push(0x03);
    b.extend_from_slice(sql.as_bytes());
    mysql_packet(0, &b)
}

fn mysql_select1_result() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&mysql_packet(1, &[0x01]));
    let mut col = Vec::new();
    for s in ["def", "", "", "", "1", ""] {
        col.push(s.len() as u8);
        col.extend_from_slice(s.as_bytes());
    }
    col.extend_from_slice(&[0x0c]);
    col.extend_from_slice(&0x3fu16.to_le_bytes());
    col.extend_from_slice(&0x0000_0001u32.to_le_bytes());
    col.push(0x03);
    col.extend_from_slice(&0x0000u16.to_le_bytes());
    col.push(0x00);
    col.extend_from_slice(&[0x00, 0x00]);
    out.extend_from_slice(&mysql_packet(2, &col));
    out.extend_from_slice(&mysql_packet(3, &[0xfe, 0x00, 0x00, 0x02, 0x00]));
    out.extend_from_slice(&mysql_packet(4, &[0x01, b'1']));
    out.extend_from_slice(&mysql_packet(5, &[0xfe, 0x00, 0x00, 0x02, 0x00]));
    out
}

pub fn mysql(session: &TcpSession, opts: &GenOptions) -> Vec<Vec<u8>> {
    let c = &session.connection;
    let mut tc = conv(session, c.src_port, c.dst_port, 0, opts);
    tc.handshake();
    tc.server_data(&mysql_server_greeting());
    tc.client_data(&mysql_login_request());
    tc.server_data(&mysql_ok(2));
    tc.client_data(&mysql_com_query("SELECT 1"));
    tc.server_data(&mysql_select1_result());
    tc.client_data(&mysql_packet(0, &[0x01])); // COM_QUIT
    tc.close_graceful();
    tc.into_packets()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::network::NetworkConnection;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn sess() -> TcpSession {
        let conn = NetworkConnection::new(
            [0, 1, 2, 3, 4, 5],
            [6, 7, 8, 9, 10, 11],
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
            80,
        );
        TcpSession::new(conn, 1000)
    }

    fn sess_v6() -> TcpSession {
        let conn = NetworkConnection::new(
            [0, 1, 2, 3, 4, 5],
            [6, 7, 8, 9, 10, 11],
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
            1234,
            80,
        );
        TcpSession::new(conn, 1000)
    }

    fn flags(frame: &[u8]) -> u8 {
        frame[47]
    }
    fn ethertype(frame: &[u8]) -> u16 {
        u16::from_be_bytes([frame[12], frame[13]])
    }
    const DEF: GenOptions = GenOptions { mtu: 1500, payload_size: 0 };

    #[test]
    fn tcp_mode_packet_counts_and_flags() {
        const SYN: u8 = 0x02;
        const RST: u8 = 0x04;
        const FIN: u8 = 0x01;

        let syn = tcp_mode(&sess(), TcpMode::SynOnly, &DEF);
        assert_eq!(syn.len(), 1);
        assert_eq!(flags(&syn[0]) & SYN, SYN);

        assert_eq!(tcp_mode(&sess(), TcpMode::Handshake, &DEF).len(), 3);

        let close = tcp_mode(&sess(), TcpMode::HandshakeClose, &DEF);
        assert_eq!(close.len(), 7);
        assert!(close.iter().any(|p| flags(p) & FIN == FIN));

        let reset = tcp_mode(&sess(), TcpMode::HandshakeReset, &DEF);
        assert_eq!(reset.len(), 4);
        assert_eq!(flags(&reset[3]) & RST, RST);
    }

    #[test]
    fn icmp_and_udp_counts_v4_and_v6() {
        assert_eq!(icmp(&sess(), &IcmpConfig { count: 2 }, &DEF).len(), 4);
        let ic = icmp(&sess(), &IcmpConfig { count: 1 }, &DEF);
        assert_eq!(ethertype(&ic[0]), 0x0800);
        assert_eq!(ic[0][34], 8); // ICMP echo request

        let u = udp(&sess(), &UdpConfig { payload: vec![], with_response: true }, &DEF);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0][23], 17); // IPv4 proto = UDP

        // IPv6 变体
        let ic6 = icmp(&sess_v6(), &IcmpConfig { count: 1 }, &DEF);
        assert_eq!(ethertype(&ic6[0]), 0x86dd);
        assert_eq!(ic6[0][54], 128); // ICMPv6 echo request（eth14 + ipv6 40 = 54）
        let u6 = udp(&sess_v6(), &UdpConfig { payload: vec![1, 2, 3], with_response: false }, &DEF);
        assert_eq!(ethertype(&u6[0]), 0x86dd);
        assert_eq!(u6[0][20], 17); // IPv6 next header = UDP（eth14 + 6）
    }

    #[test]
    fn tcp_segmentation_and_ip_fragmentation() {
        // MTU 触发 TCP 分段：1000B 数据，MSS=600-40=... 取小 MTU 让其分段
        let opts = GenOptions { mtu: 200, payload_size: 1000 };
        let pk = tcp_mode(&sess(), TcpMode::Handshake, &opts);
        // 握手 3 + 多个数据段 + 1 个 ACK
        assert!(pk.len() > 3 + 2, "应产生多个 TCP 段, got {}", pk.len());

        // IP 分片：UDP 1000B 载荷，MTU 200 → 多个 IPv4 分片
        let frags = udp(&sess(), &UdpConfig { payload: filler(1000), with_response: false }, &opts);
        assert!(frags.len() > 1, "应产生多个 IP 分片, got {}", frags.len());
    }

    #[test]
    fn app_protocols_nonempty() {
        assert!(!ssh(&sess(), &DEF).is_empty());
        assert!(!mysql(&sess(), &DEF).is_empty());
        assert!(!ftp(&sess(), FtpMode::Passive, &DEF).is_empty());
        assert!(!ftp(&sess(), FtpMode::Active, &DEF).is_empty());
        let h = http(&sess(), &HttpConfig {
            uris: vec!["/".into()],
            host: "x".into(),
            request_content: None,
            response_content: None,
        }, &DEF);
        assert_eq!(h.len(), 11);
    }
}
